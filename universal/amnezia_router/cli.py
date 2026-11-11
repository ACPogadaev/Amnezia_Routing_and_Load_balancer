from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from . import __version__, render
from .config import DEFAULT_INTERVAL, ConfigError, load_routes, make_config, read_profile, require, ipv4
from .runtime import BACKUP, CONFIG, STATE, Runtime, atomic_json, load_config
from .system import Runner, discovery, identity, platform_checks, resource_checks

SOURCE = Path(__file__).resolve().parent.parent
UNITS = Path("/etc/systemd/system")
DROPIN = UNITS / "docker.service.d/30-amnezia-router.conf"
LAUNCHER = Path("/usr/local/bin/amnezia-router")


def arguments():
    parser = argparse.ArgumentParser(description="Выборочная IPv4-маршрутизация AmneziaWG через 1–3 выхода")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "plan"):
        command = commands.add_parser(name, help="Установка с проверками" if name == "install" else "Проверка файлов и план без изменения системы")
        command.add_argument("--egress", type=Path, action="append", required=True, help="AWG-профиль выхода; повторить 1–3 раза, порядок задаёт номера")
        command.add_argument("--balanced-routes", type=Path, required=True, help="Первый файл: IPv4/CIDR для балансировки")
        command.add_argument("--pinned-routes", type=Path, help="Второй файл: IPv4/CIDR для одного выхода")
        command.add_argument("--pin-egress", type=int, help="Номер выхода для второго списка: 1, 2 или 3")
        command.add_argument("--expected-exit", action="append", default=[], metavar="N=IP", help="Публичный выходной IP при отличии от Endpoint")
        command.add_argument("--ingress-container", default="amnezia-awg2")
        command.add_argument("--ingress-interface")
        command.add_argument("--egress-image", help="Локальный образ с AWG и утилитами healthcheck; по умолчанию образ ingress")
        command.add_argument("--client-subnet", help="Подсеть клиентов, если адрес ingress-интерфейса задан с /32")
        command.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                             help="Интервал проверок в секундах (по умолчанию: %(default)s)")
        if name == "install":
            command.add_argument("--check-only", action="store_true", help="Только проверки, без записи файлов, firewall и запуска служб")
            command.add_argument("--no-wait", action="store_true", help="Не ждать здоровья всех выходов после запуска")
        else:
            command.add_argument("--ingress-info", type=Path, required=True, help="Описание окружения JSON для автономного планирования")
            command.add_argument("--output", type=Path, help="Новый каталог для плана и генерируемых правил без ключей")
    commands.add_parser("status", help="Состояние, выходы и закреплённый маршрут")
    commands.add_parser("doctor", help="Текущие проверки окружения и правил без исправлений")
    uninstall = commands.add_parser("uninstall", help="Удаление собственных ресурсов и восстановление прямой маршрутизации")
    uninstall.add_argument("--restore-direct", action="store_true", required=True, help="Подтверждает возврат целевых адресов к исходному прямому пути")
    return parser


def expected_exits(values):
    result = {}
    for value in values:
        try:
            number, address = value.split("=", 1)
            number = int(number)
        except ValueError as error:
            raise ConfigError("--expected-exit must have format N=IPv4") from error
        require(number not in result, "Duplicate --expected-exit number")
        result[number] = ipv4(address)
    return result


def inputs(args):
    require(1 <= len(args.egress) <= 3, "Supply one to three --egress arguments")
    profiles = [read_profile(path) for path in args.egress]
    return profiles, load_routes(args.balanced_routes), load_routes(args.pinned_routes)


def summary(config):
    return {"version": __version__, "egresses": [{"id": e["id"], "endpoint": f"{e['endpoint_ip']}:{e['endpoint_port']}",
             "expected_exit_ip": e["expected_exit_ip"]} for e in config["egresses"]],
            "balanced_networks": len(config["balanced_routes"]), "pinned_networks": len(config["pinned_routes"]),
            "pinned_egress": config["pin_egress"], "overlap_policy": "pinned-first", "pinned_failure_policy": "block-until-recovered",
            "ingress": config["ingress"]["container"], "networks": [n["subnet"] for n in [config["direct"], config["transit"], *(e["network"] for e in config["egresses"])]]}


def write_text(path, contents, mode=0o644):
    path = Path(path)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    require(not path.is_symlink(), "Refusing to replace a symlink: " + str(path))
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def operation_lock():
    import fcntl
    directory = Path("/var/lib/amnezia-router")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (directory / "operation.lock").open("a+") as stream:
        os.chmod(stream.name, 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def plan(args):
    profiles, balanced, pinned = inputs(args)
    info = json.loads(args.ingress_info.read_text(encoding="utf-8"))
    config = make_config(profiles, balanced, pinned, args.pin_egress, info["ingress"], info.get("used_subnets", []), expected_exits(args.expected_exit), args.interval)
    if args.output:
        require(not args.output.exists(), "Plan output already exists; use a new directory")
        args.output.mkdir(parents=True)
        for name, text in (("config.json", json.dumps(config, indent=2)), ("compose.json", json.dumps(render.compose(config), indent=2)),
                           ("host.create.nft", render.host_nft(config)), ("ingress.create.nft", render.ingress_nft(config))):
            (args.output / name).write_text(text + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(summary(config), indent=2, ensure_ascii=False))


def install(args, runner):
    profiles, balanced, pinned = inputs(args)
    environment = platform_checks(runner)
    require(not CONFIG.parent.exists(), "Installation already exists or is incomplete. Run status/doctor; use uninstall --restore-direct before a new installation")
    require(not Path(render.LIB).exists() and not LAUNCHER.exists() and not LAUNCHER.is_symlink(), "Installation path is already occupied")
    require(not any((UNITS / name).exists() for name in ("amnezia-router.service", "amnezia-router-guard.service")) and not DROPIN.exists(), "Service names are already occupied")
    ingress, used = discovery(runner, args.ingress_container, args.ingress_interface, args.client_subnet, args.egress_image)
    config = make_config(profiles, balanced, pinned, args.pin_egress, ingress, used, expected_exits(args.expected_exit), args.interval)
    resource_checks(runner, config)
    # Validate complete inactive batches and Compose before installing files.
    runner.run(["nft", "-c", "-f", "-"], input=render.host_nft(config))
    pid = identity(runner.inspect(ingress["container"]))[2]
    runner.ns(pid, "nft", "-c", "-f", "-", input=render.ingress_nft(config))
    runner.docker("compose", "--project-name", render.PROJECT, "-f", "-", "config", "--quiet", input=json.dumps(render.compose(config)))
    print(json.dumps({"environment": environment, "plan": summary(config)}, indent=2, ensure_ascii=False), flush=True)
    if args.check_only:
        print("Проверки пройдены. Установка не выполнялась.")
        return 0
    with operation_lock():
        # Recheck after acquiring the process-wide installation lock.
        require(not CONFIG.parent.exists() and not Path(render.LIB).exists(), "Another installation appeared during checks")
        CONFIG.parent.mkdir(mode=0o700)
        secrets = CONFIG.parent / "secrets"
        secrets.mkdir(mode=0o700)
        for egress, profile in zip(config["egresses"], profiles):
            write_text(secrets / f"{egress['name']}.conf", profile.contents, 0o600)
        atomic_json(CONFIG, config)
        write_text(CONFIG.parent / "compose.json", json.dumps(render.compose(config), indent=2) + "\n", 0o600)
        library = Path(render.LIB)
        library.mkdir(mode=0o755, parents=True)
        shutil.copytree(SOURCE / "amnezia_router", library / "amnezia_router", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(SOURCE / "data", library / "data")
        for name in ("routerctl.py", "egress-start.sh", "egress-healthcheck.sh"):
            write_text(library / name, (SOURCE / name).read_text(encoding="utf-8"), 0o755)
        write_text(LAUNCHER, f"#!/bin/sh\nexec /usr/bin/python3 {render.LIB}/routerctl.py \"$@\"\n", 0o755)
        for name, text in render.units().items():
            if name != "docker-dropin.conf":
                write_text(UNITS / name, text)
        runner.run(["systemd-analyze", "verify", str(UNITS / "amnezia-router.service"), str(UNITS / "amnezia-router-guard.service")])
        runtime = Runtime(config, runner)
        installed_at = time.time()
        try:
            # Protect routed destinations before installing Docker's boot dependency.
            runtime.boot_guard()
            write_text(DROPIN, render.units()["docker-dropin.conf"])
            runner.run(["systemctl", "daemon-reload"])
            runner.run(["systemctl", "enable", "--now", "amnezia-router-guard.service", "amnezia-router.service"])
            if not args.no_wait:
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    if STATE.exists():
                        state = json.loads(STATE.read_text())
                        if installed_at <= state.get("time", 0) + 1 and 0 <= time.time() - state.get("time", 0) < max(45, config["interval"] * 3) and state.get("generation") == render.generation(config) and state.get("mode") == "balanced" and state.get("admission_open"):
                            print("Установка завершена. Все выходы здоровы; маршрутизация включена.")
                            return 0
                    time.sleep(1)
                raise RuntimeError("Выходы не стали здоровыми за 180 секунд. Проверьте amnezia-router status и journalctl -u amnezia-router; защита остаётся включённой")
            print("Служба запущена. Состояние: sudo amnezia-router status")
            return 0
        except BaseException:
            runtime.block()
            runtime.boot_guard()
            raise


def status():
    require(STATE.exists(), "State is absent; inspect systemctl status amnezia-router")
    config = load_config()
    state = json.loads(STATE.read_text(encoding="utf-8"))
    age = time.time() - state.get("time", 0)
    state["age_seconds"] = round(age, 1)
    current = 0 <= age <= max(45, config["interval"] * 3) and state.get("generation") == render.generation(config)
    state["state_current"] = current
    print(json.dumps(state, indent=2, ensure_ascii=False))
    if not current or state.get("mode") == "blocked" or (config["pinned_routes"] and state.get("pinned_available") is not True):
        return 2
    return 0 if state.get("mode") == "balanced" else 1


def doctor(runner):
    platform_checks(runner)
    config = load_config()
    runtime = Runtime(config, runner)
    # This command adopts expected fingerprints from root-owned state published
    # by the daemon, then reads live rules without performing repairs.
    require(STATE.exists(), "No controller state")
    state = json.loads(STATE.read_text())
    require(state.get("generation") == render.generation(config), "Controller generation differs")
    require(state.get("host_fingerprint") and state.get("ingress_fingerprint"), "Controller has not published validated infrastructure")
    runtime.ingress_identity = identity(runner.inspect(config["ingress"]["container"]))
    runtime.interfaces = (runtime.interface_for(config["direct"]["address"]), runtime.interface_for(config["transit"]["address"]), runtime.interface_for(runtime.outer_address()))
    runtime.host_fingerprint, runtime.ingress_fingerprint = state["host_fingerprint"], state["ingress_fingerprint"]
    runtime.validate_infrastructure()
    print("Текущее окружение и правила проверены. Изменений не внесено.")
    return status()


def uninstall(runner):
    require(sys.platform == "linux" and os.geteuid() == 0, "Use sudo on the installed Linux host")
    config = load_config()
    with operation_lock():
        # Establish ownership before any stop/remove action.
        for egress in config["egresses"]:
            result = runner.docker("inspect", egress["container"], check=False)
            if not result.returncode:
                labels = json.loads(result.stdout)[0].get("Config", {}).get("Labels") or {}
                require(labels.get("com.docker.compose.project") == render.PROJECT and labels.get("org.amnezia-router.managed") == "1"
                        and labels.get("com.docker.compose.service") == egress["name"], "Refusing to remove an unmanaged container")
        runner.run(["systemctl", "disable", "--now", "amnezia-router.service"], check=False, timeout=120)
        require(runner.run(["systemctl", "is-active", "--quiet", "amnezia-router.service"], check=False).returncode != 0,
                "Controller is still active; no containers will be removed")
        runtime = Runtime(config, runner)
        runtime.block()
        runtime.compose("down")  # Deliberately complete, dedicated project; no orphan removal.
        container = config["ingress"]["container"]
        data = runner.docker("inspect", container, check=False)
        if not data.returncode and json.loads(data.stdout)[0].get("State", {}).get("Running"):
            runtime.ingress_identity = identity(json.loads(data.stdout)[0])
            # Remove only project-owned rules; never change the ingress main default.
            for binary, chains in (("iptables", [("mangle", "OUTPUT", "AMR_OUTER"), ("nat", "POSTROUTING", "AMR_INGRESS_NAT"), ("filter", "FORWARD", "AMR_INGRESS")]),
                                    ("ip6tables", [("filter", "FORWARD", "AMR_IPV6")])):
                remove_chains(runtime, runner, chains, binary, ingress=True)
            for priority in range(31099, 31104):
                remove_policy(runner, priority, runtime)
            for table in (render.TRANSIT_TABLE, render.DIRECT_TABLE):
                runtime.ns("ip", "route", "flush", "table", str(table), "proto", "99", check=False)
            remove_nft_table(runner, runtime)
            if runtime.baseline.get("ingress_identity") == list(runtime.ingress_identity):
                for key, value in runtime.baseline["ingress_sysctls"].items():
                    runtime.ns("sysctl", "-q", "-w", f"{key}={value}", check=False)
            for net in (config["direct"], config["transit"]):
                attachment = runner.inspect(container)["NetworkSettings"]["Networks"].get(net["name"])
                if attachment:
                    require(attachment.get("IPAddress") == net["address"], "Managed attachment changed")
                    runner.docker("network", "disconnect", net["name"], container)
        remove_chains(runtime, runner, [(t, p, c) for t, p, c, _ in render.host_chains(config)], "iptables")
        for priority in range(31000, 31008):
            remove_policy(runner, priority)
        for egress in config["egresses"]:
            runner.run(["ip", "route", "flush", "table", str(egress["table"]), "proto", "99"], check=False)
        for net in runtime.owned_networks():
            result = runner.docker("network", "inspect", net["name"], check=False)
            if not result.returncode:
                observed = json.loads(result.stdout)[0]
                require((observed.get("Labels") or {}).get("org.amnezia-router.managed") == "1" and not observed.get("Containers"), "Refusing to remove a network with foreign attachments")
                runner.docker("network", "rm", net["name"])
        for key, value in runtime.baseline.get("host_sysctls", {}).items():
            runner.run(["sysctl", "-q", "-w", f"{key}={value}"], check=False)
        # Drop Docker's dependency before stopping the guard, avoiding a propagated Docker stop.
        DROPIN.unlink(missing_ok=True)
        runner.run(["systemctl", "daemon-reload"])
        runner.run(["systemctl", "disable", "--now", "amnezia-router-guard.service"], check=False)
        remove_nft_table(runner)
        for name in ("amnezia-router.service", "amnezia-router-guard.service"):
            (UNITS / name).unlink(missing_ok=True)
        runner.run(["systemctl", "daemon-reload"])
        LAUNCHER.unlink(missing_ok=True)
        # Preserve profiles and original sysctls while freeing installation paths
        # for a subsequent install with another count/order of egress profiles.
        stamp = str(time.time_ns())
        archive = CONFIG.parent.with_name(CONFIG.parent.name + ".uninstalled-" + stamp)
        require(not CONFIG.parent.is_symlink(), "Refusing to archive a symlink")
        CONFIG.parent.rename(archive)
        library = Path(render.LIB)
        if library.exists():
            require(not library.is_symlink(), "Refusing to archive a symlink")
            library.rename(library.with_name(library.name + ".uninstalled-" + stamp))
        if BACKUP.exists():
            BACKUP.rename(BACKUP.with_name(BACKUP.name + ".uninstalled-" + stamp))
        print(f"Службы и сетевые ресурсы удалены. Исходный прямой путь восстановлен. Профили сохранены в {archive}; можно выполнить новую установку.")
    return 0


def remove_nft_table(runner, runtime=None):
    call = runtime.ns if runtime else lambda *a, **k: runner.run(list(a), **k)

    def present():
        snapshot = json.loads(call("nft", "-j", "list", "tables").stdout)
        require(isinstance(snapshot, dict) and isinstance(snapshot.get("nftables"), list), "Cannot verify nftables table inventory")
        require(all(isinstance(item, dict) for item in snapshot["nftables"]), "Invalid nftables table inventory")
        tables = [item["table"] for item in snapshot["nftables"] if "table" in item]
        require(all(isinstance(table, dict) and isinstance(table.get("family"), str) and isinstance(table.get("name"), str)
                    for table in tables), "Invalid nftables table inventory")
        return any(table["family"] == "inet" and table["name"] == render.TABLE for table in tables)

    if present():
        call("nft", "delete", "table", "inet", render.TABLE)
    require(not present(), "Managed nftables table remains after removal; uninstall stopped")


def remove_policy(runner, priority, runtime=None):
    call = runtime.ns if runtime else lambda *a, **k: runner.run(list(a), **k)
    rules = json.loads(call("ip", "-N", "-j", "-4", "rule", "show").stdout)
    selected = [r for r in rules if int(r["priority"]) == priority]
    require(all(str(r.get("protocol")) in {"99", "openr"} for r in selected), "Refusing to delete foreign policy rules")
    for _ in selected:
        call("ip", "rule", "del", "priority", str(priority), "protocol", "99")


def remove_chains(runtime, runner, chains, binary, ingress=False):
    for table, parent, chain in chains:
        call = (lambda *a, **k: runtime.ns(binary, "-w", "5", "-t", table, *a, **k)) if ingress else (lambda *a, **k: runner.run([binary, "-w", "5", "-t", table, *a], **k))
        for _ in range(16):
            if call("-C", parent, "-j", chain, check=False).returncode:
                break
            call("-D", parent, "-j", chain)
        call("-F", chain, check=False)
        call("-X", chain, check=False)


def main(argv=None):
    values = sys.argv[1:] if argv is None else argv
    args = argparse.Namespace(command=values[0]) if len(values) == 1 and values[0] in {"daemon", "boot-guard", "block"} else arguments().parse_args(values)
    try:
        runner = Runner()
        if args.command == "plan":
            plan(args)
            return 0
        if args.command == "install":
            return install(args, runner)
        if args.command == "status":
            return status()
        if args.command == "doctor":
            return doctor(runner)
        if args.command == "uninstall":
            return uninstall(runner)
        require(sys.platform == "linux" and os.geteuid() == 0, "System service commands require root on Linux")
        runtime = Runtime(load_config(), runner)
        if args.command == "daemon":
            runtime.daemon()
        elif args.command == "boot-guard":
            runtime.boot_guard()
        else:
            runtime.block()
        return 0
    except (ConfigError, OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("amnezia-router: " + str(error), file=sys.stderr)
        return 2
