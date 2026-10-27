# Исправленная версия: functional health и controlled recovery

Этот релиз обновляет controller предыдущей публичной версии. Каталоги установки сохраняют имена `v2` и `v3` для совместимости, но runtime controller идентифицируется как v4.

## Основные исправления

### Functional healthcheck

Состояние больше не считается здоровым только потому, что контейнер запущен и AWG-интерфейс существует. Probe проверяет:

- наличие и состояние AWG-интерфейса;
- правильный адрес интерфейса;
- включённый forwarding;
- policy lookup и парный `unreachable`;
- точные FORWARD/SNAT/OUTPUT guard rules;
- HTTPS-доступ, привязанный к адресу AWG;
- совпадение наблюдаемого и ожидаемого exit IP;
- handshake именно ожидаемого peer и его возраст;
- RX/TX counters.

Controller и Docker healthcheck используют общий probe lock и атомарный JSON cache. Совпадение расписаний больше не должно превращаться в ложное падение: Docker может использовать только свежий sample той же generation и instance.

### Исправлен цикл ожидания controller

Ожидание следующего цикла использует monotonic deadline, не передаёт отрицательное значение в `sleep` и корректно завершается при signal. Долгий probe не создаёт отрицательный timeout и crash loop controller.

### Quarantine обоих направлений

Отказавший egress исключается из новых buckets. Его conntrack-mark одновременно добавляется в nftables quarantine set, который блокирует оба направления существующих отмеченных потоков. Марки удалённых выходов могут оставаться в `RETIRED_MARKS` до естественного исчезновения старых conntrack entries.

### Controlled recovery

Добавлено ограниченное восстановление только egress-контейнеров:

- recovery по умолчанию выключен;
- allowlist определяет контейнеры, которым разрешены lifecycle-действия;
- ingress Amnezia не входит в область действий;
- отдельный recoverable streak не смешивается с общим health failure counter;
- security/infrastructure/collector failures не вызывают restart;
- cooldown, sliding-window budget и concurrency=1;
- durable intent записывается до Docker RPC;
- неопределённый исход создаёт `outcome_unknown` fence;
- restart controller не сбрасывает budget, pending и cooldown;
- ручное разрешение fence требует точный action ID и evidence file.

### Безопасный порядок старта

Controller требует guard и запускается после Docker, v2 pilot и egress oneshot. Egress start сначала публикует уникальный instance-ready token; PID-проверенный host helper включает forwarding; только после этого functional probe может стать healthy. Это устраняет циклическое ожидание `healthy -> enable forwarding -> healthy`.

## Модель включения recovery

Новая сборка содержит:

```text
RECOVERY_ENABLED=0
RECOVERY_ALLOWED_EGRESSES=
RECOVERY_ALLOW_CRASHLOOP_CONTAINMENT=0
```

Рекомендуемая последовательность:

1. установить релиз с recovery disabled;
2. подтвердить стабильный `balanced` и monitoring;
3. выбрать ровно один canary egress;
4. установить `RECOVERY_ENABLED=1` и его имя в allowlist;
5. оставить crashloop containment выключенным;
6. проверить config/build/tests и выполнить контролируемое окно наблюдения;
7. только затем расширять allowlist.

Не включайте все egress сразу на непроверенной установке.

## Совместимость и обновление

Это изменение затрагивает compose healthchecks, egress start scripts, controller, balance nftables table и recovery journal. Простая замена одного `controller.py` недостаточна.

Обновление выполняйте как полный новый release в окно работ:

1. сохранить `/etc/amnezia-lb-v2`, `/etc/amnezia-lb-multi-v3`, state и journal;
2. собрать release из новой версии Git;
3. проверить `SHA256SUMS` и тесты;
4. установить все v2/v3 файлы;
5. пересоздать egress-контейнеры, чтобы подключить functional healthcheck;
6. активировать с recovery disabled;
7. проверить `verify.sh`, `tools/check-runtime.py` и клиентский трафик;
8. не удалять старый release до завершения наблюдения.

Перед обновлением существующей нестандартной установки сравните локальные overrides. Скрипты не должны слепо перетирать правила, добавленные вне проекта.
