# Список маршрутизации

## Где хранить

Храните исходный файл вне Git-репозитория, например:

```bash
sudo install -d -m 0700 /root/amnezia-lb-input
sudo install -m 0600 /path/to/source/routes.txt /root/amnezia-lb-input/routes.txt
```

Репозиторий игнорирует `routes.txt`, `routes-*.txt`, `dist/` и AWG-конфиги. Не используйте `git add -f` для этих файлов.

## Формат

- UTF-8;
- один IPv4 CIDR на строку;
- пустые строки разрешены;
- часть после `#` считается комментарием;
- адрес без маски трактуется библиотекой Python как `/32`;
- host bits разрешены и будут канонизированы: `203.0.113.7/24` превращается в `203.0.113.0/24`;
- IPv6 запрещён;
- диапазоны вида `a-b`, домены, URL, ASN и wildcard не поддерживаются.

Синтаксический пример (не готовый список маршрутизации):

```text
# один узел
PUBLIC_IPV4/32

# сеть
PUBLIC_NETWORK/CIDR_PREFIX
```

Для реального файла используйте числовые значения, например `A.B.C.D/32` или `A.B.C.0/24`.

## Нормализация

`tools/normalize-targets.py`:

1. парсит все строки и прекращает работу при первой ошибке;
2. приводит сети к каноническому виду;
3. удаляет точные дубли;
4. объединяет вложенные и соседние сети через `collapse_addresses`;
5. классифицирует специальные диапазоны по текущему реестру IANA;
6. при перекрывающихся назначениях использует наиболее специфичный префикс;
7. отдельно исключает IPv4 multicast `224.0.0.0/4`;
8. отказывается создавать пустой набор.

Наиболее специфичная классификация важна: широкая служебная сеть может содержать более узкое назначение, которое IANA считает глобально достижимым. Простое вычитание всех строк с `Globally Reachable=False` дало бы неверный результат.

## Получение реестра IANA

```bash
python3 tools/fetch-iana-registry.py
sha256sum data/iana-ipv4-special-registry.csv
```

Скрипт скачивает официальный CSV и проверяет ожидаемые заголовки. SHA реестра записывается в `build-report.json`, чтобы сборку можно было воспроизвести.

## Предварительный просмотр

Можно запустить только нормализатор:

```bash
rm -rf work/normalized
python3 tools/normalize-targets.py \
  --input /root/amnezia-lb-input/routes.txt \
  --iana-csv data/iana-ipv4-special-registry.csv \
  --output-dir work/normalized
```

Проверьте:

```bash
cat work/normalized/report.json
wc -l work/normalized/target-v4.txt
sha256sum -c work/normalized/SHA256SUMS
```

`excluded_by_most_specific_assignment` объясняет, сколько адресов и по какой причине исключено.

## Атомарное обновление

Для изменения списка соберите новый release в новый каталог. Не редактируйте активный `.nft` вручную.

```bash
python3 tools/build-release.py \
  --config config/deployment.env \
  --routes /root/amnezia-lb-input/routes-new.txt \
  --iana-csv data/iana-ipv4-special-registry.csv \
  --output dist/release-new
```

Сначала выполните `nft -c -f` для сгенерированных файлов на сервере или используйте штатные `guard-load.sh`/`ingress-targets-load.sh`: они проверяют SHA, синтаксис и применяют весь batch одной транзакцией. При ошибке не удаляйте старый набор — исправьте новую сборку и повторите.
