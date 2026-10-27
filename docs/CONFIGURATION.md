# Настройка параметров

## Правила файла

Рабочий файл создаётся из шаблона:

```bash
cp config/deployment.env.example config/deployment.env
chmod 0600 config/deployment.env
```

Формат: одна строка `KEY=value`. Не используйте `export`, command substitution, ссылки на другие переменные или inline-комментарии после значения. Сборщик читает файл как данные и не исполняет его в shell.

Все значения `CHANGE_ME...` обязательны. Сборщик прекращает работу, если остался хотя бы один плейсхолдер.

## 1. Публичный интерфейс и IP балансировщика

```bash
ip -4 route show default
ip -4 -brief address
```

Пример интерпретации:

```text
default via GATEWAY dev eth0
```

Тогда:

```text
PUBLIC_IF=eth0
BALANCER_PUBLIC_IP=<публичный IPv4 VPS>
```

Если у провайдера используется private address + 1:1 NAT, `BALANCER_PUBLIC_IP` — внешний адрес, а `PUBLIC_IF` всё равно интерфейс default route.

## 2. Ingress-контейнер

Найдите работающий AmneziaWG server container:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'
```

Проверьте кандидата:

```bash
INGRESS=<имя-контейнера>
docker inspect "$INGRESS" --format '{{.Name}} {{.Config.Image}} {{.State.Status}}'
docker exec "$INGRESS" ip -4 -brief address
docker exec "$INGRESS" awg show
```

Заполните:

```text
INGRESS_CONTAINER=<имя>
INGRESS_AWG_IF=<AWG-интерфейс, обычно awg0>
INGRESS_CLIENT_SUBNET=<Address server-side AWG, но как сеть, например /24>
VERIFY_CLIENT_IP=<внутренний IP реально выданного тестового клиента>
```

`VERIFY_CLIENT_IP` должен принадлежать `INGRESS_CLIENT_SUBNET`. Это не публичный адрес ноутбука и не адрес сервера; это адрес peer внутри AmneziaWG.

Посмотреть peer addresses без вывода private key можно через:

```bash
docker exec "$INGRESS" awg show "$INGRESS_AWG_IF" allowed-ips
```

## 3. Входной UDP-порт

```bash
docker port "$INGRESS"
docker inspect "$INGRESS" --format '{{json .HostConfig.PortBindings}}' | jq .
ss -lunp
```

`INGRESS_AWG_PORT` — source/listen UDP port входного AmneziaWG transport. Он должен совпадать с опубликованным портом профиля, которым телефон/ноутбук подключается к балансировщику.

## 4. Docker networks ingress

Сначала перечислите подключения:

```bash
docker inspect "$INGRESS" --format '{{json .NetworkSettings.Networks}}' | jq .
docker network ls
```

Для каждой сети:

```bash
docker network inspect <network-name> | jq '.[0] | {
  name: .Name,
  driver: .Driver,
  options: .Options,
  ipam: .IPAM.Config,
  containers: .Containers
}'
```

Параметры:

- `INGRESS_OUTER_NETWORK` — Docker network, куда Docker DNAT направляет входной UDP;
- `INGRESS_OUTER_BRIDGE` — host bridge из `.Options["com.docker.network.bridge.name"]`; если опция отсутствует, определите bridge по `docker network inspect` и `ip link`;
- `INGRESS_OUTER_IP` — IPv4 ingress container в этой сети;
- `INGRESS_OUTER_GATEWAY` — gateway сети;
- `INGRESS_DNS_*` — сеть/bridge/IP/gateway, через которые Amnezia DNS связана с ingress; в распространённой установке совпадает с outer;
- `INGRESS_AUX_*` — дополнительная сеть, обычно Docker default `bridge`/`docker0`, которую проект блокирует как альтернативный Internet path.

Сопоставить host bridge и container interface:

```bash
ip -4 -brief address
docker exec "$INGRESS" ip -4 route
docker exec "$INGRESS" ip -4 -brief address
```

Не угадывайте эти значения. Preflight специально отклоняет несоответствие фактической Docker-топологии.

## 5. Health target

Нужен публичный узел, который вы контролируете или имеете право регулярно проверять:

```text
HEALTH_TARGET_IP=<IPv4>
HEALTH_TARGET_TCP_PORT=443
```

Требования:

- стабильный публичный IPv4;
- TCP-порт отвечает с трёх внешних VPN-серверов;
- адрес не входит в пользовательский route list;
- это не IP балансировщика и не один из egress endpoint;
- probe не создаёт нежелательную нагрузку.

Проверка с каждого внешнего сервера:

```bash
timeout 8 bash -c '</dev/tcp/HEALTH_TARGET_IP/HEALTH_TARGET_TCP_PORT'
```

Если bash `/dev/tcp` недоступен:

```bash
nc -vz -w 8 HEALTH_TARGET_IP HEALTH_TARGET_TCP_PORT
```

`ACTIVE_TEST_IP` наоборот должен входить в нормализованный route list. Он нужен только для локальной проверки выбора таблицы и не добавляется в набор отдельно.

## 6. Параметры внешних AmneziaWG сервисов

Для каждого из трёх egress profiles нужны четыре значения:

```text
*_AWG_IP
*_ENDPOINT_IP
*_ENDPOINT_PORT
*_EXPECTED_EXIT_IP
```

Безопасно извлечь их локально, не печатая ключи:

```bash
awk -F= '
  tolower($1) ~ /^[[:space:]]*address[[:space:]]*$/ {
    gsub(/[[:space:]]/, "", $2); print "Address=" $2
  }
  tolower($1) ~ /^[[:space:]]*endpoint[[:space:]]*$/ {
    gsub(/[[:space:]]/, "", $2); print "Endpoint=" $2
  }
' /root/amnezia-lb-input/main.conf
```

Заполнение:

- `MAIN_AWG_IP` — `Address` первого профиля без `/32`;
- `MAIN_ENDPOINT_IP` и `MAIN_ENDPOINT_PORT` — IPv4 и порт из `Endpoint`;
- `MAIN_EXPECTED_EXIT_IP` — внешний IP, наблюдаемый при выходе через этот туннель;
- те же поля `EGRESS2_*` и `EGRESS3_*` — для второго и третьего профиля.

Если egress-сервер не находится за отдельным NAT, expected exit обычно совпадает с endpoint IP. Не делайте это предположение автоматически: проверьте.

Проект требует числовой IPv4 endpoint. Если экспорт содержит hostname, заранее разрешите его, выберите стабильный адрес и учитывайте, что смена DNS-адреса потребует пересборки.

Профиль должен разрешать `0.0.0.0/0`. Скрипт подготовки удаляет `DNS`, старые `MTU`, `Table`, `PreUp/PostUp/PreDown/PostDown`, затем добавляет:

```text
MTU = 1280
Table = off
SaveConfig = false
```

`Table=off` обязателен: маршруты создаёт проект, а не `awg-quick`.

## 7. Expected exit URL

По умолчанию:

```text
HEALTH_URL=https://1.1.1.1/cdn-cgi/trace
HEALTH_URL_SECONDARY=https://api.ipify.org
```

Primary должен возвращать строку `ip=<IPv4>`. Secondary должен возвращать JSON
вида `{"ip":"IPv4"}`. Если заменяете сервисы, сохраните ожидаемый формат или
адаптируйте `egress-healthcheck.sh`.

Для production лучше использовать собственный HTTPS endpoint и контролировать его доступность/лимиты.

## 8. Пороги здоровья

- `HEALTH_INTERVAL_SECONDS=10` — период цикла;
- `HEALTH_TIMEOUT_SECONDS=6` — timeout отдельной проверки;
- `HEALTH_FAILURE_THRESHOLD=3` — последовательные ошибки до исключения;
- `HEALTH_SUCCESS_THRESHOLD=3` — последовательные успехи до возврата;
- `HEALTH_MAX_HANDSHAKE_AGE_SECONDS=300` — максимально допустимый возраст AWG handshake.
- `HEALTH_PROBE_TIMEOUT_SECONDS=15` — внешний предел всего functional probe;
- `HEALTH_CONNECT_TIMEOUT_SECONDS=3` — предел установления HTTPS-соединения;
- `HEALTH_HTTP_TIMEOUT_SECONDS=6` — предел одного HTTPS-запроса;
- `HEALTH_MAX_SAMPLE_AGE_SECONDS=45` — допустимый возраст cache при совпадении instance/generation;
- `ALLOW_LEGACY_PROBE=0` — запрещает ослабленный fallback без v4 probe.

Три ошибки при интервале 10 секунд означают обнаружение примерно через 20–30 секунд плюс фактические timeout. Слишком малые значения вызовут flapping, слишком большие — долгий blackhole новых соединений.

## 9. Параметры нагрузки

- `LOAD_EWMA_ALPHA` — насколько быстро EWMA реагирует на свежий byte rate; диапазон `(0, 1]`;
- `LOAD_REFERENCE_BPS` — скорость, относительно которой снижается вес;
- `LOAD_WEIGHT_FLOOR` — минимальный относительный вес здорового выхода.

Начните с значений примера. Изменяйте только после наблюдения `state.json` и фактических byte counters.

## 10. Controlled recovery

Начальная безопасная конфигурация:

```text
RECOVERY_ENABLED=0
RECOVERY_ALLOWED_EGRESSES=
RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT=0
```

После стабильного периода разрешите один canary из `main`, `pgdl`, `ae`:

```text
RECOVERY_ENABLED=1
RECOVERY_ALLOWED_EGRESSES=pgdl
```

Остальные параметры задают число последовательных recoverable failures,
cooldown, окно бюджета, максимум restart и startup grace. В текущей версии
`RECOVERY_MAX_PARALLEL` обязан быть равен `1`.

Не включайте recovery при неработающем мониторинге, invalid journal или
неразобранном `outcome_unknown`. `wrong_exit_ip`, ошибки configuration/security,
collector failures и общий внешний outage не должны вызывать restart.

## 11. Внутренняя адресация

Текущая версия фиксирует внутренние bridge/subnet/table/mark значения в шаблонах. Перед запуском убедитесь, что они свободны:

```bash
ip -4 route show table all | grep -E '172\.30\.(249|250|251|252)\.' || true
ip -4 rule show | grep -E '(^|: )(2050[0-7]|2100[01]):' || true
docker network ls --format '{{.Name}}' | grep -E '^amnezia-lb-' || true
```

Конфликт — причина остановиться и изменить все связанные шаблоны и validators согласованно. Не меняйте один IP или номер таблицы точечно.
