# ASMU

**Advanced Security Manager Utils** — набор утилит для администраторов Linux: мониторинг, анализ и усиление безопасности без лишней магии.

[![GitHub](https://img.shields.io/badge/github-repo-blue?logo=github)](https://github.com/Tosa5656/asmu)
[![Stars](https://img.shields.io/github/stars/Tosa5656/asmu?style=flat&logo=GitHub&color=blue)](https://github.com/Tosa5656/asmu/stargazers)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/Tosa5656/asmu/blob/master/LICENSE.md)
[![Coverage](https://img.shields.io/badge/coverage-80%25-green)]()
![GitHub commit activity](https://img.shields.io/github/commit-activity/t/Tosa5656/asmu)
![GitHub last commit](https://img.shields.io/github/last-commit/Tosa5656/asmu)
![GitHub contributors](https://img.shields.io/github/contributors/Tosa5656/asmu)

---

## Что внутри

Пять консольных утилит, которые закрывают типичные задачи по безопасности: SSH, логи, пароли, сеть и справочник по атакам.

| Утилита | Назначение |
|--------|------------|
| **smssh** | Безопасность SSH: конфиг, ключи, мониторинг атак |
| **smlog** | Логи: чтение, поиск, отчёты, мониторинг в реальном времени |
| **smpass** | Пароли: хранение с AES256, хэши SHA256 |
| **smnet** | Сеть: порты, соединения, трафик, статистика |
| **smdb** | База MITRE ATT&CK: описание атак и рекомендации по защите |

У каждой команды есть `help` — просто запустите `smssh help`, `smlog help` и т.д.

---

## smssh — безопасность SSH

Проверка и усиление настроек SSH-сервера, разбор логов и поиск признаков атак.

- Анализ конфигурации и понятные рекомендации  
- Генерация захардкоженной конфигурации  
- Мониторинг логов в реальном времени  
- Парсинг логов и детекция brute force, dictionary-атак и аномалий  
- Генерация ключей хоста  

```bash
smssh help              # справка
smssh analyze           # анализ текущего конфига
smssh generate out.conf # сгенерировать безопасный конфиг
smssh check             # показать текущие настройки
smssh apply             # применить рекомендации (с бэкапом)
smssh monitor           # мониторинг атак по логам
smssh parse-log /var/log/auth.log
smssh gen-key ssh_host_rsa_key
```

---

## smlog — системные логи

Чтение, поиск и мониторинг логов, в том числе journald.

- Файловые логи и systemd journal  
- Поиск по ключевым словам  
- Топ IP и пользователей по логам  
- Готовые отчёты (безопасность, система, журнал)  
- Мониторинг в реальном времени с правилами  

```bash
smlog help
smlog list               # доступные логи
smlog read /var/log/syslog 100
smlog search "Failed" /var/log/auth.log
smlog journal sshd 50    # journald
smlog top-ips /var/log/auth.log 10
smlog report security    # отчёт по безопасности
smlog monitor            # мониторинг (Ctrl+C — выход)
```

---

## smpass — пароли

Локальное хранение паролей с шифрованием и хэшированием.

- Хранение с AES256  
- SHA256 для хэшей  
- Данные в `~/.asmu/storage/`  

```bash
smpass help
smpass add-password      # интерактивно добавить запись
smpass delete-password
smpass hash-sha256 "строка"
smpass hash-aes256 "строка"
```

---

## smnet — сеть

Сканирование портов, активные соединения и статистика по интерфейсам.

- Список соединений (TCP/UDP) и процессов  
- Мониторинг трафика на интерфейсе (pcap)  
- Статистика по интерфейсам и протоколам  

```bash
smnet help
smnet scan               # открытые порты и соединения
smnet connections        # eth0 по умолчанию
smnet connections wlan0
smnet stats              # статистика интерфейсов
```

---

## smdb — база атак MITRE ATT&CK

Справочник техник с описаниями и подсказками, какими утилитами ASMU можно прикрыться.

- Список и поиск по техникам  
- Описание и рекомендации по защите  
- Указание инструментов ASMU (smssh, smlog и др.)  

```bash
smdb help
smdb list
smdb search brute
smdb show T1110
smdb tools T1078
```

Документация по атакам лежит в `doc/attacks/` (HTML). При установке — в `/usr/share/doc/asmu/attacks/`.

---

## API

Если хочется вызывать те же возможности из кода на C++ — есть единый API и статическая библиотека `libasmu.a`.

- [Описание API](api/README.md)  
- [Сгенерированная документация](doc/api/html/index.html) (после `make doc`)  

Сборка библиотеки: `make libasmu.a`.

---

## Установка

**Требования:** Linux, компилятор с C++20, OpenSSL, libpcap. Опционально: MaxMind GeoLite2 для GeoIP в smssh.

```bash
git clone https://github.com/Tosa5656/asmu
cd asmu
make
make check    # прогнать тесты
make doc      # сгенерировать документацию
sudo make install
```

Утилиты попадут в `/usr/local/bin/`, документация — в `/usr/share/doc/asmu/`. Для мониторинга SSH через systemd:

```bash
sudo make install-systemd
systemctl enable smssh
systemctl start smssh
```

Только документация (без установки бинарников):

```bash
make doc
sudo make install-doc-only
# Просмотр: xdg-open doc/api/html/index.html
```

---

## Удаление

```bash
sudo make uninstall
```

Удаляются бинарники из `/usr/local/bin/`, юнит systemd и каталог `/usr/share/doc/asmu/`. База GeoLite2 в `/usr/share/GeoIP/` не трогается.

---

## Кратко о возможностях

- **SSH:** анализ конфига, рекомендации, мониторинг атак, разбор логов, генерация ключей  
- **Логи:** файлы и journald, поиск, отчёты, мониторинг в реальном времени  
- **Пароли:** хранение с AES256, хэши SHA256  
- **Сеть:** порты, соединения, трафик, статистика  
- **Справочник:** MITRE ATT&CK с рекомендациями и привязкой к утилитам ASMU  

Лицензия: GPL v3. Подробности — в [LICENSE.md](LICENSE.md).