# Диагностика

## VPN подключается, но весь Internet не работает

Проверьте сначала входной transport и direct path:

```bash
sudo systemctl --failed
sudo docker ps --format 'table {{.Names}}\t{{.Status}}'
sudo /etc/amnezia-lb-v2/host/ingress-check.sh
sudo /etc/amnezia-lb-v2/host/docker-dnat-check.sh
sudo /etc/amnezia-lb-v2/host/default-route-check.py
sudo journalctl -u amnezia-lb-v2-ingress-router.service --since '-15 min' --no-pager
```

Частые причины:

- неверный `INGRESS_OUTER_IP`/bridge;
- перепутан published UDP port;
- ingress container был пересоздан с другим IP;
- host firewall добавил более ранний drop;
- route list случайно содержит слишком широкий префикс, например default route;
- клиентский split tunneling маскирует результат теста.

## Вне списка работает, по списку — нет

```bash
sudo jq . /run/amnezia-lb-multi-v3/state.json
sudo /etc/amnezia-lb-multi-v3/host/verify.sh
sudo nft list table inet amnezia_lb_v2
sudo nft list table inet amnezia_lb_balance_v3
sudo ip -4 rule show
sudo ip -4 route show table 401
sudo ip -4 route show table 402
sudo ip -4 route show table 403
```

Интерпретация:

- `fail` buckets > 0 — нет достаточного числа здоровых выходов или admission закрыт;
- `infra_valid=false` — controller нашёл структурное расхождение;
- target counters растут, но egress SNAT counters нет — проблема между host policy и egress container;
- SNAT counters растут, но ответа нет — AWG tunnel/MTU/upstream;
- target counters не растут — адрес не попал в нормализованный set либо запрос использует другой IP/CDN.

Для домена сначала определите фактические IPv4:

```bash
getent ahostsv4 example.com
```

Маршрутизация идёт по destination IP, не по доменному имени. CDN может менять IP между запросами.

## Один egress всегда unhealthy

```bash
sudo docker logs --tail 200 amnezia-egress-2-v3
sudo docker exec amnezia-egress-2-v3 awg show
sudo docker exec amnezia-egress-2-v3 ip -4 rule show
sudo docker exec amnezia-egress-2-v3 ip -4 route show table 202
sudo docker exec amnezia-egress-2-v3 curl -4 --interface <AWG_IP> \
  --max-time 10 https://1.1.1.1/cdn-cgi/trace
```

Сверьте Address/Endpoint с profile и `deployment.env`. Ошибка expected exit тоже делает probe неуспешным, даже если HTTP работает.

## `prepare-egress-config.sh` завершился без сообщения

Скрипт использует `set -e` и строгие сравнения. Обычно не совпал `Address` или `Endpoint`.

```bash
awk -F= '
  tolower($1) ~ /^[[:space:]]*(address|endpoint)[[:space:]]*$/ {
    print $1 "=" $2
  }
' /root/amnezia-lb-input/egress2.conf
grep -E '^(PGDL_AWG_IP|PGDL_ENDPOINT_IP|PGDL_ENDPOINT_PORT)=' \
  /etc/amnezia-lb-multi-v3/multi.env
```

Не ослабляйте проверку и не копируйте профиль вручную в secrets directory до выяснения расхождения.

## Ошибка SHA256 ruleset

Установленный `.nft` изменён после сборки либо loader не соответствует release:

```bash
sudo sha256sum /etc/amnezia-lb-v2/guard.create.nft
sudo grep SHA256 /etc/amnezia-lb-v2/host/guard-load.sh
```

Переустановите файлы из одного и того же сгенерированного release. Не исправляйте hash вручную на сервере: сначала проверьте, почему изменился ruleset.

## `nft -c -f` не проходит

```bash
sudo nft -c -f /etc/amnezia-lb-v2/guard.create.nft
sudo nft -c -f /etc/amnezia-lb-multi-v3/host/guard.create.nft
```

Возможные причины:

- слишком старый nftables;
- подставлено невалидное имя интерфейса;
- повреждён/неполный generated file;
- ручное редактирование внесло синтаксическую ошибку.

Старый активный table не удаляйте. Исправьте build input и создайте новый release.

## DNS timeout при успешном HTTPS

`Resolve-DnsName -Server 8.8.8.8` проверяет UDP/TCP 53 конкретного public resolver. Он может фильтровать datacenter/VPN sources. Сравните:

```powershell
curl.exe -4 -k -I --connect-timeout 10 https://8.8.8.8/dns-query
Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly
```

HTTP-ответ доказывает IP reachability к `8.8.8.8:443`, но не доступность DNS/53. Разделяйте эти проверки.

## После reboot всё сломалось

```bash
sudo systemd-analyze critical-chain docker.service
sudo systemctl cat docker.service
sudo systemctl --no-pager --full status \
  amnezia-lb-v2-guard.service amnezia-lb-multi-v3-guard.service docker.service
sudo journalctl -b -u amnezia-lb-v2-guard.service \
  -u amnezia-lb-multi-v3-guard.service -u docker.service --no-pager
```

Guard должен завершиться до разрешения Docker startup. Не удаляйте dependency/drop-in только ради запуска Docker: это откроет окно утечки. Если нужен аварийный возврат, используйте VNC и документированный rollback.

## rp_filter

Асимметричная policy routing требует отключения strict reverse-path filter на управляемых transit bridges:

```bash
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.amlt0.rp_filter
sysctl net.ipv4.conf.amlp0.rp_filter
sysctl net.ipv4.conf.amla0.rp_filter
```

Скрипт сохраняет baseline и меняет только необходимые keys. Если внешний hardening tool периодически возвращает `rp_filter=1`, устраните конфликт конфигураций, а не запускайте бесконечный override loop.

## Что приложить к issue

Допустимо:

- версия Ubuntu/kernel/Docker/nftables;
- commit проекта;
- redacted `state.json`;
- `systemctl status` и journald errors;
- имена интерфейсов и внутренние RFC1918 сети, если вы согласны их раскрыть;
- `build-report.json` после удаления абсолютного пути source.

Нельзя:

- AWG `.conf` целиком;
- `PrivateKey`, `PresharedKey`, SSH password/key;
- необработанный `docker inspect`, если он содержит env/secrets;
- пользовательский route list, если вы не хотите его публиковать.
