# Установка

## 1. Требования

Рекомендуемая исходная конфигурация:

- отдельный VPS-балансировщик;
- Ubuntu Server 24.04 LTS x86_64/amd64;
- статический публичный IPv4;
- минимум 1 vCPU, 1 ГБ RAM и 10 ГБ диска; для заметной нагрузки лучше 2 vCPU и 2 ГБ RAM;
- доступ `root` или пользователь с `sudo`;
- рабочая VNC/serial/web-консоль провайдера;
- уже установленный на балансировщике входной AmneziaWG;
- три клиентских AmneziaWG `.conf`, каждый подключается к отдельному внешнему VPN-серверу;
- один публичный TCP/HTTPS узел для независимой проверки доступности;
- пользовательский IPv4 CIDR-список.

Официальная инструкция Amnezia по установке self-hosted VPN: <https://docs.amnezia.org/documentation/instructions/install-vpn-on-server/>. В ней сервер разворачивается из актуального клиента Amnezia; проект ожидает, что этот этап уже завершён.

## 2. Резервный доступ и снимок

До сетевых изменений:

1. откройте VNC/консоль провайдера;
2. держите две независимые SSH-сессии;
3. сделайте snapshot VPS, если провайдер поддерживает;
4. сохраните read-only диагностику.

```bash
sudo -i
install -d -m 0700 /root/amnezia-lb-backup
date -Is > /root/amnezia-lb-backup/time.txt
ip -details address > /root/amnezia-lb-backup/ip-address.txt
ip -4 route show table all > /root/amnezia-lb-backup/ip-route-all.txt
ip -4 rule show > /root/amnezia-lb-backup/ip-rule.txt
nft list ruleset > /root/amnezia-lb-backup/nft-ruleset.txt
iptables-save > /root/amnezia-lb-backup/iptables-save.txt
docker ps -a --no-trunc > /root/amnezia-lb-backup/docker-ps.txt
docker network ls > /root/amnezia-lb-backup/docker-network-ls.txt
systemctl list-unit-files --state=enabled > /root/amnezia-lb-backup/enabled-units.txt
```

Не публикуйте этот каталог: он может раскрывать внутреннюю адресацию и метаданные контейнеров.

## 3. Проверка Ubuntu

```bash
cat /etc/os-release
uname -m
systemd --version
ip -V
nft --version || true
docker version || true
docker compose version || true
```

Текущая реализация проверялась для Ubuntu 24.04 LTS. Другие дистрибутивы могут отличаться systemd unit paths, nftables/iptables backend и поведением Docker.

## 4. Установка базовых пакетов

```bash
sudo apt-get update
sudo apt-get install -y \
  ca-certificates curl git jq python3 \
  nftables iproute2 iptables conntrack \
  util-linux gawk coreutils procps
```

Проверьте backend:

```bash
iptables --version
update-alternatives --display iptables || true
```

На Ubuntu 24.04 обычно используется `iptables-nft`. Не переключайте backend на работающем сервере без отдельного плана миграции.

## 5. Docker Engine

Если Amnezia уже установила Docker и `docker version`/`docker compose version` работают, **не удаляйте и не переустанавливайте Docker**. Переходите к следующему разделу.

Для чистого сервера используйте официальный apt-репозиторий Docker: <https://docs.docker.com/engine/install/ubuntu/>.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker run --rm hello-world
```

Docker предупреждает, что опубликованные container ports могут обходить правила ufw/firewalld. В этом проекте критичные разрешения дополнительно ограничиваются `DOCKER-USER` и nftables guard; не добавляйте широкие `ACCEPT` перед ними.

Не обязательно добавлять администратора в группу `docker`: она даёт root-equivalent доступ к daemon. Для установки безопаснее выполнять команды через `sudo`/root.

## 6. Установка входного AmneziaWG

На чистом балансировщике:

1. установите актуальное приложение AmneziaVPN с официального репозитория <https://github.com/amnezia-vpn/amnezia-client/releases>;
2. выберите добавление self-hosted сервера;
3. укажите IP балансировщика и SSH-доступ;
4. в Expert mode установите AmneziaWG;
5. создайте отдельный клиентский профиль;
6. подключитесь телефоном и компьютером;
7. убедитесь, что до установки балансера обычный интернет работает.

Проверки на сервере:

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
docker images --format 'table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}'
docker image inspect amnezia-awg2 >/dev/null
```

Если ingress или образ называются иначе, сначала заполните фактический `INGRESS_CONTAINER`. Compose-файлы egress используют локальный образ `amnezia-awg2`; для другой установки потребуется проверить совместимость образа и при необходимости изменить строку `image:` в двух шаблонах до сборки.

## 7. Получение исходников

```bash
cd /opt
sudo git clone https://github.com/ACPogadaev/Amnezia_Routing_and_Load_balancer.git
sudo chown -R root:root /opt/Amnezia_Routing_and_Load_balancer
cd /opt/Amnezia_Routing_and_Load_balancer
git status --short
```

Проверьте release/tag или commit, который собираетесь ставить:

```bash
git log -1 --show-signature --oneline
```

## 8. Подготовка трёх egress-профилей

Экспортируйте из Amnezia три клиентских AmneziaWG-конфигурации: по одной для каждого внешнего сервера. Они должны содержать как минимум:

- `[Interface]`;
- `PrivateKey`;
- `Address = IPv4/32`;
- `[Peer]`;
- `PublicKey` и, если используется, `PresharedKey`;
- `Endpoint = public-ip:udp-port`;
- `AllowedIPs`, включающий `0.0.0.0/0`;
- параметры обфускации AmneziaWG, соответствующие серверу.

Передайте файлы на балансировщик не через Git:

```bash
sudo install -d -m 0700 /root/amnezia-lb-input
sudo install -m 0600 /secure/source/main.conf /root/amnezia-lb-input/main.conf
sudo install -m 0600 /secure/source/egress2.conf /root/amnezia-lb-input/egress2.conf
sudo install -m 0600 /secure/source/egress3.conf /root/amnezia-lb-input/egress3.conf
```

Не выводите конфиги через `cat` в записываемую терминальную сессию и не прикладывайте их к issue.

## 9. Конфигурация проекта

```bash
cd /opt/Amnezia_Routing_and_Load_balancer
cp config/deployment.env.example config/deployment.env
chmod 0600 config/deployment.env
nano config/deployment.env
```

Откуда взять каждое значение, описано в [CONFIGURATION.md](CONFIGURATION.md).

## 10. Список маршрутизации и IANA

```bash
sudo install -m 0600 /secure/source/routes.txt /root/amnezia-lb-input/routes.txt
cd /opt/Amnezia_Routing_and_Load_balancer
python3 tools/fetch-iana-registry.py
```

Формат — в [ROUTING-LIST.md](ROUTING-LIST.md).

## 11. Локальные тесты и сборка

```bash
python3 -m unittest discover -s tests -v

rm -rf dist/release-new
python3 tools/build-release.py \
  --config config/deployment.env \
  --routes /root/amnezia-lb-input/routes.txt \
  --iana-csv data/iana-ipv4-special-registry.csv \
  --output dist/release-new

cd dist/release-new
sha256sum -c SHA256SUMS
cat build-report.json
```

Сборщик не включает три AWG-конфига. Он включает нормализованный целевой набор в сгенерированный release; поэтому каталог `dist/` тоже считается чувствительным операционным артефактом и игнорируется Git.

## 12. Read-only preflight

```bash
cd /opt/Amnezia_Routing_and_Load_balancer/dist/release-new
sudo ./v2/install-files.sh /root/amnezia-lb-input/main.conf
```

Команда копирует файлы в `/etc/amnezia-lb-v2`, приватный egress profile — в `/opt/amnezia-lb-v2/secrets`, проверяет preflight и systemd units, но ещё не активирует маршрутизацию.

Если preflight завершился ошибкой, не переходите дальше. Исправьте обнаруженное расхождение и пересоберите release.

## 13. Активация первого выхода

Оставьте VNC и вторую SSH-сессию открытыми:

```bash
sudo /etc/amnezia-lb-v2/host/activate.sh
sudo /etc/amnezia-lb-v2/host/wait-ready.sh
sudo /etc/amnezia-lb-v2/host/verify.sh
```

Переподключите один VPN-клиент и проверьте один адрес из списка и один адрес вне списка. Только после успешного single-egress режима продолжайте.

## 14. Установка и активация трёх выходов

```bash
cd /opt/Amnezia_Routing_and_Load_balancer/dist/release-new
sudo ./v3/install-files.sh \
  /root/amnezia-lb-input/egress2.conf \
  /root/amnezia-lb-input/egress3.conf

sudo /etc/amnezia-lb-multi-v3/host/activate.sh
```

Проверка:

```bash
sudo /etc/amnezia-lb-multi-v3/host/verify.sh
sudo systemctl --no-pager --full status \
  amnezia-lb-v2-guard.service \
  amnezia-lb-v2-ingress-router.service \
  amnezia-lb-v2-pilot.service \
  amnezia-lb-multi-v3-guard.service \
  amnezia-lb-multi-v3-egress.service \
  amnezia-lb-multi-v3-controller.service
sudo jq . /run/amnezia-lb-multi-v3/state.json
```

Ожидается `mode` `balanced` или временно `degraded`, `infra_valid: true`, `admission_open: true`, свежий `time`, три healthy выхода в нормальном состоянии и ноль fail buckets.

Новая сборка оставляет controlled recovery выключенным. Это намеренно: сначала
должны быть подтверждены functional healthchecks, reboot acceptance и
мониторинг. Порядок canary-включения описан в [RELEASE-V4.md](RELEASE-V4.md).

Установите read-only monitor check:

```bash
sudo install -m 0755 \
  /opt/Amnezia_Routing_and_Load_balancer/tools/check-runtime.py \
  /usr/local/sbin/amnezia-lb-check
sudo /usr/local/sbin/amnezia-lb-check
```

Коды возврата и рекомендуемые alerts приведены в
[MONITORING.md](MONITORING.md).

## 15. Проверка после перезагрузки

Сначала убедитесь, что VNC доступен:

```bash
sudo reboot
```

После возврата:

```bash
systemctl is-active docker
systemctl is-active amnezia-lb-v2-guard.service
systemctl is-active amnezia-lb-multi-v3-controller.service
sudo /etc/amnezia-lb-multi-v3/host/verify.sh
sudo jq . /run/amnezia-lb-multi-v3/state.json
```

Только затем считайте установку завершённой.
