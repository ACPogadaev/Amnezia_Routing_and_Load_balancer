# Эксплуатация

## Состояние контроллера

```bash
sudo jq . /run/amnezia-lb-multi-v3/state.json
sudo journalctl -u amnezia-lb-multi-v3-controller.service \
  --since '-30 min' --no-pager
```

Ключевые поля:

- `time` — timestamp последнего цикла;
- `release` — идентификатор runtime;
- `infra_valid` — целостность требуемой инфраструктуры;
- `maintenance` — закрыт ли admission для изменения/отката;
- `admission_open` — разрешено ли назначать новые соединения;
- `mode` — `balanced`, `degraded` или fail mode;
- `healthy` — доступные egress names;
- `bucket_counts` — распределение 256 buckets, включая `fail`;
- диагностические причины конкретного egress.

## Полная недеструктивная проверка

```bash
sudo /etc/amnezia-lb-multi-v3/host/verify.sh
sudo systemctl --failed
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Networks}}'
sudo ip -4 rule show
sudo ip -4 route show table 401
sudo ip -4 route show table 402
sudo ip -4 route show table 403
```

`verify.sh` проверяет контрольные суммы установленных файлов, fingerprint nftables, policy rules, Docker guard, контейнеры, MSS, публичный IP каждого egress и состояние controller.

## Клиентская проверка

Подключите Amnezia к балансировщику и выберите:

- `TARGET_IP` — адрес из нормализованного списка;
- `DIRECT_IP` — публичный адрес вне списка;
- `EXPECTED_DIRECT_IP` — публичный IP балансировщика.

Windows PowerShell:

```powershell
curl.exe -4 --connect-timeout 10 https://TARGET_IP/
curl.exe -4 --connect-timeout 10 https://DIRECT_IP/
curl.exe -4 --connect-timeout 10 https://1.1.1.1/cdn-cgi/trace
```

Сам факт HTTP-ответа не доказывает выбранный egress. Используйте сервис, который показывает source IP, либо временное route logging.

DNS-запрос к `8.8.8.8:53` проверяет ещё и UDP/53, но публичные DNS-серверы могут ограничивать запросы от VPN/datacenter адресов. Timeout такого запроса не является достаточным доказательством поломки маршрута.

## Временное логирование маршрутов

Логи выключены по умолчанию.

Включить:

```bash
sudo /etc/amnezia-lb-v2/host/route-log-enable.sh
sudo /etc/amnezia-lb-multi-v3/host/route-log-enable.sh
```

Смотреть события:

```bash
sudo journalctl -k -f -g 'AMLB2|AML-V3'
```

Статус и counters:

```bash
sudo /etc/amnezia-lb-v2/host/route-log-status.sh
sudo /etc/amnezia-lb-multi-v3/host/route-log-status.sh
```

Выключить сразу после теста:

```bash
sudo /etc/amnezia-lb-multi-v3/host/route-log-disable.sh
sudo /etc/amnezia-lb-v2/host/route-log-disable.sh
```

Логирование rate-limited, но destination/source metadata всё равно попадает в kernel journal. Не держите его включённым постоянно без политики хранения логов.

## Проверка failover

Это деструктивный тест для новых соединений. Выполняйте через VNC и сначала запишите имя контейнера:

```bash
sudo jq . /run/amnezia-lb-multi-v3/state.json
sudo docker stop amnezia-egress-2-v3
watch -n 2 'sudo jq "{mode,healthy,bucket_counts,time}" /run/amnezia-lb-multi-v3/state.json'
```

После порога ошибок egress 2 должен исчезнуть из `healthy`, его buckets перейдут к оставшимся здоровым выходам, `fail` останется 0.

Вернуть:

```bash
sudo docker start amnezia-egress-2-v3
```

После порога успехов выход снова появится. Проверяйте только новые соединения; существующие могут оставаться pinned или завершиться.

## Проверка fail-closed

Не проводите на production без окна работ. При остановке всех egress целевые новые соединения должны перестать работать, а адреса вне target set и сам входной VPN transport — оставаться доступными.

Удаление conntrack не выполняется автоматически: оно не отправляет TCP RST и не гарантирует мгновенное переподключение приложения.

## Перезагрузка Docker

```bash
sudo systemctl restart docker
sudo systemctl --no-pager --full status amnezia-lb-v2-guard.service
sudo systemctl --no-pager --full status amnezia-lb-multi-v3-guard.service
sudo /etc/amnezia-lb-multi-v3/host/verify.sh
```

Если guard не загружается, не обходите dependency ручным запуском контейнеров. Исправьте ruleset/checksum, сохраняя fail-closed состояние.

## Обновление route list

1. сохраните новый исходник вне Git;
2. скачайте актуальный IANA CSV;
3. соберите новый output directory;
4. проверьте `build-report.json` и `SHA256SUMS`;
5. stage v2 files новым `v2/install-files.sh` с тем же main profile;
6. перезагрузите target set/guard штатными loaders;
7. выполните verify и клиентские проверки;
8. сохраните предыдущий release до завершения наблюдения.

Не заменяйте set последовательностью `flush`/`add` из интерактивной shell: между командами возникает окно с пустым набором. Используйте целый batch через `nft -f`.

## Откат v3 -> v2

```bash
sudo /etc/amnezia-lb-multi-v3/host/rollback.sh
sudo /etc/amnezia-lb-v2/host/verify.sh
```

Откат:

- останавливает v3 controller;
- закрывает v3 admission;
- удаляет только созданные v3 rules/routes/tables/drop-in;
- останавливает дополнительные egress-контейнеры;
- возвращает single-egress v2 health controller;
- не удаляет входной Amnezia container и его client profiles.

## Полный откат v2

```bash
sudo /etc/amnezia-lb-v2/host/rollback.sh --restore-baseline
```

После него проверьте входной Amnezia вручную и сравните состояние с backup. Не восстанавливайте целиком старый `iptables-save` поверх работающего Docker: правила Docker могли измениться, и глобальное восстановление может нарушить сеть.

## Обновления ОС/Docker

Перед обновлением:

```bash
sudo /etc/amnezia-lb-multi-v3/host/verify.sh
sudo cp -a /etc/amnezia-lb-v2 /root/amnezia-lb-backup/
sudo cp -a /etc/amnezia-lb-multi-v3 /root/amnezia-lb-backup/
```

Обновляйте в окно работ. После изменения Docker, kernel, iproute2, nftables или Amnezia image повторяйте reboot acceptance checks.
