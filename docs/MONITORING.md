# Мониторинг балансера

Этот документ описывает только наблюдение. Команды не меняют маршруты, firewall и состояние контейнеров. Автоматический restart рассматривается отдельно и не должен подменять мониторинг.

## Что именно нужно контролировать

Работоспособность делится на три уровня:

1. **Процессы:** Docker, controller и контейнеры существуют и не находятся в restart loop.
2. **Туннели:** AWG-интерфейсы подняты, handshake свежий, forwarding и policy routing корректны.
3. **Функция:** HTTPS probe действительно выходит через каждый egress и видит ожидаемый публичный IP.

`systemctl active`, Docker `Up` или один свежий handshake по отдельности не доказывают работоспособность всей цепочки.

## Отдельный минимальный блок мониторинга

Рекомендуемый минимальный набор для любого внешнего мониторинга:

```bash
sudo python3 /path/to/repository/tools/check-runtime.py
sudo systemctl is-active docker containerd \
  amnezia-lb-multi-v3-controller.service \
  amnezia-lb-v2-ingress-router.service
sudo systemctl --failed --no-legend
sudo docker ps --format 'table {{.Names}}\t{{.Status}}'
```

`check-runtime.py` печатает одну JSON-строку и возвращает:

| Код | Статус | Значение |
|---:|---|---|
| `0` | `OK` | Все настроенные egress здоровы и eligible, режим `balanced`, fail-buckets отсутствуют. |
| `1` | `WARNING` | Режим `degraded`, но хотя бы один egress обслуживает новые соединения, либо выполняется контролируемое recovery. |
| `2` | `CRITICAL` | State устарел, infra invalid, admission закрыт, есть fail-buckets, invalid journal или `outcome_unknown`. |
| `3` | `UNKNOWN` | Файл состояния/конфигурации нельзя прочитать или его схема неожиданна. |

Пример для установленного сервера:

```bash
sudo install -m 0755 tools/check-runtime.py /usr/local/sbin/amnezia-lb-check
sudo /usr/local/sbin/amnezia-lb-check
echo $?
```

Не запускайте эту проверку чаще периода controller. При интервале controller 10 секунд достаточно проверки раз в 30–60 секунд.

## Ожидаемые systemd-состояния

Постоянно работающие службы:

```bash
sudo systemctl show \
  amnezia-lb-multi-v3-controller.service \
  amnezia-lb-v2-ingress-router.service \
  -p Id -p ActiveState -p SubState -p Result -p MainPID -p NRestarts
```

Норма: `ActiveState=active`, `SubState=running`, `Result=success`. Рост `NRestarts` означает, что процесс завершался и был поднят systemd.

Одноразовые units:

```bash
sudo systemctl show \
  amnezia-lb-multi-v3-guard.service \
  amnezia-lb-v2-guard.service \
  amnezia-lb-v2-targets-stage.service \
  amnezia-lb-v2-pilot.service \
  amnezia-lb-multi-v3-egress.service \
  -p Id -p ActiveState -p SubState -p Result -p ExecMainStatus
```

Для `Type=oneshot` нормой является `active (exited)`, `Result=success`, `ExecMainStatus=0`. Состояние `exited` здесь не означает остановку защиты: unit выполнил настройку, а правила продолжают жить в ядре.

Базовые системные службы:

- `docker.service` и `containerd.service` — обязательны;
- используемый сетевой менеджер — обязателен;
- `systemd-journald` — нужен для журналов;
- NTP-клиент (`systemd-timesyncd`, `chrony` или аналог) — нужен для достоверного возраста handshake и временных меток;
- SSH нужен для управления, но не входит в VPN data path;
- `cron` и `fail2ban` полезны, но не доказывают работу маршрутизации.

`nftables.service` может быть inactive: ruleset проекта загружают guard-units. Не включайте общий nftables unit и не выполняйте `nft flush ruleset` только ради устранения этого статуса.

## Контейнеры и процессы

```bash
sudo docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
sudo docker inspect <CONTAINER> \
  --format 'status={{.State.Status}} running={{.State.Running}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}} restarts={{.RestartCount}} oom={{.State.OOMKilled}} started={{.State.StartedAt}} log={{.HostConfig.LogConfig.Type}}'
sudo docker top <CONTAINER>
```

Для egress ожидается `Up (healthy)`, `OOMKilled=false`. Ненулевой restart count не всегда означает текущую аварию, но его рост между двумя измерениями должен вызвать alert и корреляцию с controller journal.

Внутри egress обычно работают start-script, `amneziawg-go` и служебный `sleep`. При kernel implementation отдельного процесса `amneziawg-go` может не быть. Главный критерий — интерфейс и функциональный probe:

```bash
sudo docker exec <CONTAINER> awg show interfaces
sudo docker exec <CONTAINER> ip -br link show <AWG_IF>
sudo docker exec <CONTAINER> sysctl net.ipv4.ip_forward
sudo docker exec <CONTAINER> awg show <AWG_IF> latest-handshakes
sudo docker exec <CONTAINER> awg show <AWG_IF> transfer
```

Не экспортируйте `awg showconf`, private key, preshared key и полные профили в систему мониторинга.

## Controller state

Основной источник состояния:

```bash
sudo jq . /run/amnezia-lb-multi-v3/state.json
```

Важные поля:

- `time` — должен обновляться чаще monitor max-age;
- `mode` — `balanced`, `degraded`, `fail-closed` или `reconciling`;
- `infra_valid` — инфраструктурные проверки;
- `admission_open` — можно ли назначать новые потоки;
- `healthy` — выходы, прошедшие пороги здоровья;
- `eligible` — выходы, которым разрешены новые соединения;
- `bucket_counts` — сумма должна быть 256;
- `egresses.*.reason` — последняя причина;
- `handshake_age` — возраст handshake;
- `exit_ip` — реально наблюдаемый внешний IP;
- `engine_restart_count` — наблюдаемый Docker restart count;
- `recovery_journal_valid` и `recovery_journal_error`;
- `recovery_pending` — текущая lifecycle-операция или fence.

Интерпретация режимов:

- `balanced` — все активные выходы здоровы;
- `degraded` — часть выходов исключена, но новые соединения ещё обслуживаются;
- `fail-closed` — допустимых выходов нет либо инфраструктура невалидна; целевой трафик блокируется, чтобы не утечь напрямую;
- `reconciling` — короткое переходное состояние при запуске/сверке; длительное состояние ненормально.

## Recovery journal

Durable journal находится в `/var/lib/amnezia-lb/recovery-state.json` и должен быть доступен только root.

События controller journal:

- `candidate` — выбран допустимый кандидат;
- `intent_recorded` — намерение записано на диск до Docker RPC;
- `rpc_dispatched` — lifecycle-команда отправлена;
- `completed` — эффект подтверждён;
- `cooldown` — действует защита от повторов;
- `budget_exhausted` — исчерпан лимит, нужен оператор;
- `configuration_rejected` — recovery-конфигурация отклонена;
- `outcome_unknown` — результат RPC нельзя доказать, последующие действия fenced.

`outcome_unknown` — CRITICAL. Не удаляйте journal и не повторяйте restart. Сначала сохраните journal, controller log, Docker events и identity контейнера; ручное разрешение выполняется `recovery-resolve.py` только по документированным доказательствам.

## Журналы

```bash
sudo journalctl -u amnezia-lb-multi-v3-controller.service --since '-1 hour' --no-pager
sudo journalctl -u amnezia-lb-multi-v3-controller.service -f
sudo journalctl -u amnezia-lb-v2-ingress-router.service --since '-1 hour' --no-pager
sudo journalctl -u docker.service --since '-1 hour' --no-pager
sudo journalctl -k -b --since '-1 hour' --no-pager | \
  grep -Ei 'amnezia|awg|tun|oom|killed process|segfault|netfilter|conntrack|martian|drop'
```

Egress-контейнеры:

```bash
sudo docker logs --since 1h <EGRESS_CONTAINER>
sudo docker inspect <EGRESS_CONTAINER> --format '{{json .State.Health}}'
```

У официального ingress Amnezia может использоваться logging driver `none`; пустой `docker logs` в таком случае ожидаем. Проверяйте `inspect`, AWG-интерфейс, handshakes, counters и packet capture.

## Ресурсы хоста

```bash
uptime
nproc
free -h
swapon --show
df -h /
df -ih /
sudo sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
sudo journalctl -k -b -p warning..alert --no-pager
```

Alert нужен при:

- RAM близка к исчерпанию и swap продолжает расти;
- появился kernel OOM;
- filesystem или inode заполнены более чем на 85–90%;
- conntrack приближается к лимиту;
- load average стабильно значительно выше количества vCPU;
- появились disk/filesystem errors.

## Рекомендуемые alerts

| Условие | Уровень | Рекомендуемая задержка |
|---|---|---:|
| State старше 30–45 секунд | Critical | 1–2 проверки |
| `infra_valid=false` или admission закрыт вне окна работ | Critical | сразу |
| `mode=fail-closed` | Critical | сразу |
| `mode=degraded` | Warning | после 2 циклов |
| `fail` buckets больше 0 | Critical | сразу |
| Egress `reason=wrong_exit_ip` | Critical/security | сразу |
| Handshake старше настроенного лимита | Warning/Critical | по порогу controller |
| `recovery_journal_valid=false` | Critical | сразу |
| `recovery_pending.status=outcome_unknown` | Critical/manual | сразу |
| `budget_exhausted` | Critical/manual | сразу |
| Рост restart count ingress | Critical | сразу |
| Рост restart count egress | Warning; Critical при повторе | сразу/по частоте |
| Диск или inode >85% | Warning | 5 минут |
| Диск или inode >95%, OOM | Critical | сразу |

Не отправляйте alert на каждое изменение bucket distribution: контроллер меняет веса по EWMA, поэтому небольшие перестановки нормальны.

## Внешние black-box проверки

Внутренний healthcheck доказывает каждый egress. Дополнительно полезен независимый клиент, который подключается к ingress и проверяет:

1. VPN handshake;
2. адрес из target list;
3. адрес вне target list;
4. DNS отдельно от IP-доступа;
5. наблюдаемый внешний IP целевого соединения.

Black-box endpoint лучше контролировать самостоятельно. Не создавайте высокочастотную нагрузку на публичные сервисы определения IP.

## Временное route logging

```bash
sudo /etc/amnezia-lb-v2/host/route-log-enable.sh
sudo /etc/amnezia-lb-multi-v3/host/route-log-enable.sh
sudo journalctl -k -f -g 'AMLB2|AML-V3'
```

После теста:

```bash
sudo /etc/amnezia-lb-multi-v3/host/route-log-disable.sh
sudo /etc/amnezia-lb-v2/host/route-log-disable.sh
```

Route logging содержит source/destination metadata. Даже с rate limit не оставляйте его постоянно включённым без политики хранения и доступа к журналам.

## Что сохранить до restart

```bash
date -Is
sudo cp -a /run/amnezia-lb-multi-v3/state.json /tmp/amnezia-lb-state-incident.json
sudo cp -a /var/lib/amnezia-lb/recovery-state.json /tmp/amnezia-lb-recovery-incident.json
sudo systemctl --failed --no-pager
sudo docker ps -a --no-trunc
sudo journalctl -u amnezia-lb-multi-v3-controller.service -b --no-pager
sudo journalctl -u docker.service -b --since '-2 hours' --no-pager
sudo journalctl -k -b --since '-2 hours' --no-pager
```

Только после сохранения состояния решайте, нужен ли restart конкретного egress. Не начинайте диагностику с restart всего Docker или ingress Amnezia.
