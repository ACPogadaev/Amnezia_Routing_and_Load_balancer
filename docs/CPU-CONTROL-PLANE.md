# Снижение CPU контрольных служб

Периодические проверки сохраняют прежние интервалы. Этот релиз уменьшает работу,
которую службы выполняют внутри одного цикла:

- ingress manager постоянно работает в Python и сохраняет подготовленную модель
  ожидаемых CIDR;
- controller вызывает тот же библиотечный валидатор, без повторного
  ingress-targets-check;
- IPv4/IPv6 iptables читаются через save-снимки; точный разбор применяется к
  цепочкам балансера, чужие расширения остаются непрозрачными токенами. Позиции
  и единственность jumps в родительских цепочках проверяются отдельно;
- один namespace collector получает адреса, маршруты, RPDB, sysctl и nft table;
- один nft JSON используется для fingerprint, проверки цепочки и семантики CIDR;
- host iptables snapshot используется несколькими проверками только в текущем
  цикле и сбрасывается после repair;
- forwarding setup повторяется при новой identity/instance или выявленном
  отключении ip_forward; функциональная проверка sysctl остаётся в каждом probe;
- Docker healthcheck сначала использует свежий sample controller, включая failure,
  а при устаревании выполняет полноценную пробу самостоятельно.

Два независимых периодических ingress-аудита сохранены. Readiness-файл с PID не
заменяет текущую проверку правил. Recovery allowlist, budget, quarantine, policy
unreachable и диагностические standalone helpers продолжают действовать.

## Границы кеша

Ожидаемые CIDR кешируются по SHA256 содержимого файла, а не mtime. Фактическое
состояние ядра заново читается каждый цикл. Повторное использование семантического
разбора допускается только для идентичного содержимого свежего observed set.

Ingress identity проверяется до и после сбора: container ID, StartedAt, PID и
network namespace inode. При несовпадении снимок отклоняется. Сбор нескольких
подсистем не является глобальной атомарной транзакцией; собственный repair
аннулирует ранее собранные host snapshots. Полная ingress-проверка ограничена
25 секундами, отдельная команда collector — 5 секундами.

Docker обычно использует sample возрастом не больше HEALTH_INTERVAL_SECONDS
(и не больше HEALTH_MAX_SAMPLE_AGE_SECONDS). При занятом probe lock сохраняется
прежняя граница HEALTH_MAX_SAMPLE_AGE_SECONDS. Повторное чтение не меняет sample_id
и исходный timestamp. Controller учитывает один sample один раз для success и
failure counters. Для --json controller по-прежнему запускает свежий probe.

## Проверки

```bash
python3 -m unittest discover -s tests -v
find templates -name '*.sh' -print0 | xargs -0 -n 1 bash -n
sudo env AMNEZIA_LB_INTEGRATION=1 python3 -m unittest discover \
  -s tests -p test_linux_runtime.py -v
python3 tools/benchmark-checks.py --networks 4103 --iterations 10
```

Linux integration создаёт отдельный временный network namespace с dummy
интерфейсами и тестовыми правилами. Docker inspect и AWG listen-port в нём
заменены синтетическими ответами. Сетевые снимки iptables/nft/iproute2/sysctl
читаются настоящими Linux-утилитами. Живой Amnezia-сервер не нужен.

Benchmark измеряет только CIDR-валидацию на синтетических данных. В legacy CLI
включён запуск интерпретатора; в новом пути сравнивается прогретый библиотечный
валидатор. Эти числа не являются оценкой суммарного CPU сервера.

CI выполняет unit tests, сборку release, shell syntax и отдельную Linux integration
проверку на Ubuntu 24.04.

## Обновление и измерение на сервере

Изменены runtime-модули v2, ingress manager, v3 controller и оба healthcheck.
Нужно обновлять согласованный комплект файлов. Замена одного controller.py
недостаточна. Оба compose-файла передают интервал в healthcheck; контейнеры должны
получить обновлённое environment при пересоздании.

Перед установкой сохранить действующий релиз, конфигурацию, manifest и recovery
journal. Для действующей установки использовать проверенную процедуру обновления
с maintenance: существующий v2 fresh-install preflight запрещает уже созданные
сети/контейнеры, поэтому не является процедурой in-place upgrade. Этот релиз не
выполняет автоматическое обновление работающего сервера.

Готовый порядок staging, maintenance-проверки и отката для трёх проверенных
выходов приведён в [IN-PLACE-CPU-UPGRADE.md](IN-PLACE-CPU-UPGRADE.md). Tool
`prepare-cpu-upgrade.py` готовит приватные каталоги поверх копии действующего
runtime и сохраняет его сетевые параметры. Перед staging он проверяет исходные
installed-manifest обеих baseline-копий, затем сверяет скопированные файлы;
повреждения и непроверенные локальные изменения не попадают в новые manifests.
Для отдельно рассмотренных изменений предусмотрен явный `--baseline-review`
с точными хешами и записью результата проверки в приватном upgrade-report.
`verify.sh --maintenance` проверяет
здоровье трёх выходов, пока admission остаётся закрытым.

Ingress manager проверяет уже работающий namespace перед решением о repair,
убирает readiness и закрывает admission до ремонта. Неудачный readback завершает
процесс; до стабильного обычного цикла допускается не более трёх последовательных
repairs. Systemd дополнительно ограничивает запуски: три за 300 секунд. SIGTERM
прерывает idle wait и запрещает публикацию readiness после запроса остановки.

После установки сравнить несколько окон по 5–10 минут при сопоставимом трафике:
CPU cgroup controller/ingress-router вместе с потомками, длительность циклов,
число процессов, возраст samples и фактическую задержку исключения/возврата выхода.
Отдельно учитывать steal. Проверить отказ одного/всех выходов, удаление route/jump,
отключение forwarding, смену namespace, maintenance, rollback и reboot.

Ожидается снижение накладных расходов проверок. Точный эффект и достижение
целевых показателей подтверждаются измерением на конкретном сервере.
