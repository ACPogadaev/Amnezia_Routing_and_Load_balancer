# Контролируемое обновление CPU-проверок действующего сервера

Процедура рассчитана на **уже проверенную схему main + pgdl + ae**. Она сохраняет
существующие адреса, bridges, firewall batches, парные loader hashes, inventory,
AWG-профили и локальные overrides. Fresh-install скрипты здесь не используются.

Возврат третьего выхода на действующий двухвыходной сервер — отдельная
предварительная операция. Одного файла ae.conf недостаточно: до этого обновления
должны быть проверены третий контейнер, сеть, host policy и guards. Если ae ещё
отсутствует, staging tool завершится до установки. Список маршрутов не меняется;
для рассматриваемого пилота нужно подтвердить те же 4103 нормализованные сети.

Команды ниже выполняются root в Bash в согласованное окно с доступной консолью
провайдера. Их не нужно выполнять на рабочем сервере ради проверки PR.

## 1. Условия допуска и три профиля

Для каждого main/pgdl/ae до сборки подтвердить уникальные endpoint IP:UDP-port и
внутренний AWG IPv4, ожидаемый exit IP, свежий handshake именно нужного peer и
реальный HTTPS через адрес туннеля. Проверить профиль 0600 и каталог секретов 0700.
Профили остаются в /opt/amnezia-lb-*/secrets; ключи и реальные env/routes не попадают
в Git или публичные CI artifacts.

Публичный default route хоста должен оставаться на uplink. AWG default route
допустим внутри egress namespace; host policy tables 401–403 направляют через
контейнерные next hops. Не запускать клиентский awg-quick с default на host namespace.

Перед обновлением обязательны:

- стабильный balanced с тремя ожидаемыми выходами и работающим клиентским трафиком;
- RECOVERY_ENABLED=0 и RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT=0;
- валидный recovery journal без pending/outcome_unknown;
- отсутствие пересечения RETIRED_MARKS с активными 0x201/0x202/0x203. Возврат ранее
  удалённого 0x203 требует отдельного разбора старых conntrack entries;
- остановка любых других ручных rollout/repair операций;
- исходный release из проверенного commit, зелёный CI, sha256sum -c SHA256SUMS.

## 2. Приватная резервная копия и baseline 15 минут

```bash
set -Eeuo pipefail
umask 077
V2=/etc/amnezia-lb-v2
V3=/etc/amnezia-lb-multi-v3
TASK_TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/var/backups/amnezia-lb-cpu-$TASK_TS
install -d -m 0700 "$BACKUP" "$BACKUP/etc" "$BACKUP/units" "$BACKUP/metrics"
cp -a "$V2" "$BACKUP/etc/v2"
cp -a "$V3" "$BACKUP/etc/v3"
cp -a /opt/amnezia-lb-v2/secrets "$BACKUP/main-secrets"
cp -a /opt/amnezia-lb-multi-v3/secrets "$BACKUP/additional-secrets"
cp -a /var/lib/amnezia-lb "$BACKUP/state"
cp -a /run/amnezia-lb-v2 "$BACKUP/runtime-v2"
cp -a /run/amnezia-lb-multi-v3 "$BACKUP/runtime-v3"
for unit in amnezia-lb-v2-{guard,ingress-router,pilot,health}.service \
            amnezia-lb-multi-v3-{guard,egress,controller}.service; do
    cp -a "/etc/systemd/system/$unit" "$BACKUP/units/"
    systemctl show "$unit" > "$BACKUP/units/$unit.show"
done
cp -a /etc/systemd/system/docker.service.d "$BACKUP/docker.service.d"
systemctl show docker -p Requires -p After -p DropInPaths > "$BACKUP/docker-dependencies.txt"
iptables-save > "$BACKUP/iptables.save"
ip6tables-save > "$BACKUP/ip6tables.save"
nft -j list ruleset > "$BACKUP/nft.json"
ip -j -4 rule show > "$BACKUP/rules.json"
ip -j -4 route show table all > "$BACKUP/routes.json"
. "$V2/pilot.env"
. "$V3/multi.env"
docker inspect "$INGRESS_CONTAINER" "$EGRESS_CONTAINER" "$PGDL_CONTAINER" "$AE_CONTAINER" > "$BACKUP/inspect-before.json"
docker compose --env-file "$V2/pilot.env" -f "$V2/egress/compose.yaml" config --format json > "$BACKUP/compose-v2.json"
docker compose --env-file "$V3/multi.env" -f "$V3/egress/compose.yaml" config --format json > "$BACKUP/compose-v3.json"
```

Inspect сохраняет container ID, StartedAt, PID, restart count и исходное environment.
Если проект задаётся через локальный override, передать в compose config его
исходный --project-name из labels/inventory. Staging проверит совпадение project.
Дополнительно сохранить ingress namespace rules/routes/iptables/nft по его текущему
PID. Существующие installed-manifest и контрольные суммы уже входят в копии etc.

Собирать baseline **до** запуска теневых проверок нового кода. Например:

```bash
awk '$1=="processes" {print $2}' /proc/stat > "$BACKUP/metrics/processes-before"
systemd-cgtop -b -n 900 -d 1s > "$BACKUP/metrics/cgroups.txt" &
CPU_SAMPLER_PID=$!
vmstat -t 1 900 > "$BACKUP/metrics/vmstat.txt" &
VM_SAMPLER_PID=$!
for index in $(seq 1 180); do
    sample=$(date -u +%Y%m%dT%H%M%SZ)
    cp "$RUNTIME_DIR/state.json" "$BACKUP/metrics/state-$sample.json"
    cat /proc/loadavg /proc/stat /proc/sys/net/netfilter/nf_conntrack_count > "$BACKUP/metrics/kernel-$sample.txt"
    sleep 5
done
wait "$CPU_SAMPLER_PID" "$VM_SAMPLER_PID"
docker inspect "$INGRESS_CONTAINER" "$EGRESS_CONTAINER" "$PGDL_CONTAINER" "$AE_CONTAINER" > "$BACKUP/inspect-after-baseline.json"
awk '$1=="processes" {print $2}' /proc/stat > "$BACKUP/metrics/processes-after"
```

В отчёте зафиксировать CPU cgroup controller/ingress-router вместе с потомками,
load/steal, скорость создания процессов по разности /proc/stat, conntrack,
свежесть state/принятых health samples, handshake age, buckets, Docker restart
count и период обновления state. Длительность работы цикла измерять отдельно
трассировкой/профилированием: период публикации state не равен времени работы
цикла. Сохранить методику и нагрузку, чтобы повторить их после обновления.

Проверить backup, включая права 0700/0600, и посчитать отдельный BACKUP-SHA256SUMS
с исключением самого файла checksum. Не публиковать эту копию: в ней есть секреты
и реальные параметры. Recovery journal копируется для анализа; откат не должен
слепо заменять его старой версией и забывать уже записанные lifecycle-действия.

## 3. Собрать согласованный staging без записи в /etc

Сначала собрать release штатным build-release.py и проверить его SHA256SUMS.
Ни один install-files.sh не запускать. Ниже PROJECT_ROOT и RELEASE — абсолютные
пути к проверенным исходникам и готовому release на сервере:

```bash
PROJECT_ROOT=/opt/Amnezia_Routing_and_Load_balancer
RELEASE=$PROJECT_ROOT/dist/release-cpu
STAGE=$BACKUP/staged
(cd "$RELEASE" && sha256sum -c SHA256SUMS)
python3 "$PROJECT_ROOT/tools/prepare-cpu-upgrade.py" \
    --release "$RELEASE" \
    --baseline-v2 "$BACKUP/etc/v2" --baseline-v3 "$BACKUP/etc/v3" \
    --compose-v2 "$BACKUP/compose-v2.json" --compose-v3 "$BACKUP/compose-v3.json" \
    --output "$STAGE"
```

Tool проверяет checksums, наличие трёх выходов, метки, уникальность адресов и
endpoint pairs, интервалы и режим recovery. Затем копирует исходный локальный
runtime и заменяет только перечисленные в upgrade-report.json CPU-файлы:
runtime_checks/runtime-collect/ingress-router, wrappers, RPDB/default-route
validators, controller, verify/verify-state и оба healthcheck. Новая ingress
systemd unit входит в staging. Остальные units, guards/loaders и локальные
сетевые параметры сохраняются.

Оба **действующих** Compose JSON сохраняют исходные services, names, mounts и
networks; в environment трёх сервисов добавляется HEALTH_INTERVAL_SECONDS.
JSON сохраняется как compose.yaml: JSON — допустимое YAML-представление.
Так не перетираются локальные имена AWG-интерфейсов, mounts и endpoint-порты
параметрами fresh-install шаблонов. Staging приватный, в Git его не добавлять.

Проверить upgrade-report, diff staging против backup, Compose config --quiet и
systemd-analyze verify новой ingress unit. Выполнить один read-only теневой
проход новых validators для ingress, guard-v2/v3, docker-v2/v3, задав
AMNEZIA_LB_DIR="$STAGE/v2" и AMNEZIA_LB_MULTI_DIR="$STAGE/v3". Он читает
существующие /run fingerprints и реальные namespaces, не устанавливает файлы.
Любое несовпадение — остановка до maintenance, а не повод отключать проверку.

## 4. Закрыть admission, остановить старые readers и установить комплект

После baseline убедиться, что конфигурация/Compose/inventory/units не изменились
относительно backup; иначе пересобрать staging из нового снимка. Секретные
профили также не должны меняться во время операции.

```bash
flock -x "$LOCK_FILE" bash -c 'umask 077; printf "operation=cpu-upgrade\n" > "$1"' _ "$MAINTENANCE_FILE"
"$V2/host/policy-down.sh"
```

У штатного pilot есть Requires=ingress-router и ExecStop с compose down
--remove-orphans. До остановки manager временно отключить **только этот
ExecStop**, иначе systemd может удалить egress-контейнеры при каскадной остановке.
Runtime-only override не меняет сохранённую unit и удаляется после операции:

```bash
PILOT_STOP_OVERRIDE=/run/systemd/system/amnezia-lb-v2-pilot.service.d/zz-cpu-upgrade.conf
test ! -e "$PILOT_STOP_OVERRIDE"
install -d -m 0755 "$(dirname "$PILOT_STOP_OVERRIDE")"
printf '[Service]\nExecStop=\n' > "$PILOT_STOP_OVERRIDE"
systemctl daemon-reload
test -z "$(systemctl show amnezia-lb-v2-pilot.service -p ExecStop --value)"
test -z "$(systemctl show amnezia-lb-v2-pilot.service -p ExecStopPost --value)"
systemctl stop amnezia-lb-multi-v3-controller.service amnezia-lb-v2-ingress-router.service
systemctl stop amnezia-lb-v2-health.service
for unit in amnezia-lb-multi-v3-controller.service amnezia-lb-v2-ingress-router.service; do
    test "$(systemctl show "$unit" -p ActiveState --value)" = inactive
    test "$(systemctl show "$unit" -p MainPID --value)" = 0
done
```

Подтвердить отсутствие старых PID/cgroup tasks и пустую target table 301 в
текущем ingress namespace. Не продолжать, если остановка или закрытие admission
не подтверждены. Guards и Docker остаются включены. Ingress-контейнер не пересоздавать.

Подготовить соседние каталоги для переименования на том же filesystem:

```bash
NEXT_V2=/etc/amnezia-lb-v2.cpu-next-$TASK_TS
NEXT_V3=/etc/amnezia-lb-multi-v3.cpu-next-$TASK_TS
PREV_V2=/etc/amnezia-lb-v2.cpu-prev-$TASK_TS
PREV_V3=/etc/amnezia-lb-multi-v3.cpu-prev-$TASK_TS
test ! -e "$NEXT_V2" && test ! -e "$NEXT_V3" && test ! -e "$PREV_V2" && test ! -e "$PREV_V3"
cp -a "$STAGE/v2" "$NEXT_V2"
cp -a "$STAGE/v3" "$NEXT_V3"
mv "$V2" "$PREV_V2"
mv "$NEXT_V2" "$V2"
mv "$V3" "$PREV_V3"
mv "$NEXT_V3" "$V3"
install -m 0644 "$STAGE/units/amnezia-lb-v2-ingress-router.service" /etc/systemd/system/
systemctl daemon-reload
sha256sum -c "$V2/installed-manifest.sha256"
sha256sum -c "$V3/installed-manifest.sha256"
sha256sum -c "$STAGE/unit-manifest.sha256"
```

Это две пары rename, не одна глобальная транзакция. При прерывании сверить
фактически существующие V2/V3/NEXT/PREV и восстановить согласованную пару через
консоль, оставляя maintenance. Не пытаться автоматически повторять mv.

## 5. Пересоздать только egress и проверить под maintenance

```bash
docker compose --env-file "$V2/pilot.env" -f "$V2/egress/compose.yaml" up -d --force-recreate --no-deps egress-main
docker compose --env-file "$V3/multi.env" -f "$V3/egress/compose.yaml" up -d --force-recreate --no-deps egress-pgdl egress-ae
systemctl reset-failed amnezia-lb-v2-ingress-router.service
systemctl start amnezia-lb-v2-ingress-router.service
systemctl start amnezia-lb-v2-pilot.service
systemctl start amnezia-lb-multi-v3-controller.service
```

Service names в примере — штатные. При локальных названиях взять проверенные
compose_service из сохранённого inventory. Не использовать compose down,
--remove-orphans или рестарт всего Docker при обычном обновлении. Проверить
новые ID/StartedAt egress, environment с HEALTH_INTERVAL_SECONDS, неизменную
identity ingress и завершение старых egress-процессов.

Дождаться трёх healthy и выполнить:

```bash
"$V3/host/verify.sh" --maintenance
```

Этот режим проверяет manifest, guards, RPDB, MSS, Docker health, expected exit IP,
journal и quarantine. При этом требует maintenance=true, admission_open=false,
mode=reconciling, 256 fail buckets и quarantine всех активных marks. Это
функциональный допуск **до** открытия admission. Обычный verify в этот момент
должен отклонять закрытое admission.

Только после успешного допуска снять maintenance под state lock:

```bash
"$V3/host/verify.sh" --maintenance
flock -x "$LOCK_FILE" bash -c 'rm -f -- "$1"' _ "$MAINTENANCE_FILE"
```

Дождаться
нового state: balanced, infra_valid=true, admission_open=true, три healthy,
fail=0. Затем выполнить обычный verify.sh и клиентские проверки. Для canary
recovery остаётся выключенным. Каждый успешный verify относится к своему
моменту времени; после него продолжается штатный периодический контроль.
После приёмки удалить только PILOT_STOP_OVERRIDE и выполнить daemon-reload.
При откате после его удаления сначала снова установить и проверить этот override.

## 6. Приёмка, отказы и откат

Повторить 15-минутный baseline тем же способом при сопоставимом трафике, в новый
приватный каталог. Сравнить CPU и дочерние процессы, state/sample age, реальную
задержку failover, conntrack, restart count и steal. Синтетический benchmark
CIDR не заменяет этот замер.

Проверить неизменность SHA/семантики всех 4103 сетей, прямой путь вне списка,
распределение новых целевых потоков, запрет IPv6-обхода и отсутствие repair/restart
цикла. В отдельном окне последовательно проверить: отказ/возврат одного выхода,
отказ двух и всех трёх, ip_forward=0, удаление policy rule, SNAT/FORWARD,
повреждённый sample, смену identity, Docker restart и reboot. Во всех сценариях
целевой трафик не должен получить прямой выход. Текущие TCP-сессии не обязаны
переживать смену выхода; для приёмки использовать новые соединения.

Немедленно закрыть admission и откатывать при постоянном fail-closed после
прогрева, отсутствии readiness, повторном repair/restart, непризнании исправных
выходов, outcome_unknown/повреждении journal, росте CPU или нестабильности трафика.
Пока maintenance действует, fail=256 ожидается и сам по себе не является ошибкой.

Откат этой CPU-операции:

1. Повторно установить maintenance и выполнить policy-down; убедиться, что
   runtime-only override pilot ExecStop установлен и проверен; остановить controller
   и ingress manager, подтвердить завершение процессов.
2. Переименовать новые runtime-каталоги в отдельные .cpu-failed-$TASK_TS;
   вернуть **обе** PREV-папки на прежние V2/V3 пути. Не смешивать версии.
3. Восстановить сохранённую ingress unit из BACKUP/units, daemon-reload.
4. По сохранённым Compose пересоздать только три egress, восстановив старое
   environment и старые bind-mounted healthcheck. Ingress не пересоздавать.
5. Проверить старые manifests/guards и запустить старые manager/controller.
   Снять maintenance только после проверки согласованного baseline и здоровья.
6. Сохранить новые logs/state/identity и journal для разбора. Не восстанавливать
   глобальный iptables-save поверх Docker и не обнулять recovery journal.

Это возврат к исходному трёхвыходному runtime. rollback.sh v3→v2 выполняет другую
операцию и не заменяет откат CPU-обновления. StartLimit допускает до трёх запусков
ingress manager за 300 секунд; после его срабатывания сначала разобраться с
причиной, затем вручную reset-failed. Не запускать reset-failed в цикле.
