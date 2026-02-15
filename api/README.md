# API ASMU

API ASMU даёт программный доступ ко всем утилитам проекта через C++.

## Архитектура

API разбит на модули по утилитам:

```
api/
├── include/                 # Заголовки
│   ├── asmu.h    # Главный заголовок
│   ├── smpass_api.h         # Хранение паролей
│   ├── smnet_api.h          # Сеть
│   ├── smlog_api.h          # Логи
│   ├── smssh_api.h          # Безопасность SSH
│   └── smdb_api.h           # База атак
└── src/                     # Реализация
    ├── smpass_api.cpp
    ├── smnet_api.cpp
    ├── smlog_api.cpp
    ├── smssh_api.cpp
    └── smdb_api.cpp
```

## Возможности

- **Модульность**: отдельный API для каждой утилиты с понятным интерфейсом.
- **Ошибки**: единый формат результата (Result) с кодами и сообщениями.
- **Типы**: строгая типизация, современный C++.
- **Платформа**: Linux, несколько дистрибутивов.
- **MITRE ATT&CK**: доступ к базе атак из кода.

## Начало работы

```cpp
#include <asmu.h>

int main()
{
    Asmu::initialize();

    Asmu::PasswordManager pwd_mgr;
    auto hash = pwd_mgr.hashString("password", Asmu::HashAlgorithm::SHA256);

    Asmu::NetworkMonitor net_mgr;
    auto ports = net_mgr.scanPorts();

    Asmu::AttackDatabase attack_db;
    auto attacks = attack_db.searchAttacks("brute force");

    Asmu::cleanup();
    return 0;
}
```

## Сборка

```bash
make libasmu.a   # Собрать статическую библиотеку
make all         # Собрать утилиты и библиотеку
```

## Компоненты

### PasswordManager (`smpass_api.h`)
Хранение и хэширование паролей.

```cpp
Asmu::PasswordManager pwd_mgr;
auto hash = pwd_mgr.hashString("password", Asmu::HashAlgorithm::SHA256);
auto result = pwd_mgr.addPassword("service.com", "username", "password");
```

### NetworkMonitor (`smnet_api.h`)
Сканирование портов и мониторинг соединений.

```cpp
Asmu::NetworkMonitor net_mgr;
auto ports = net_mgr.scanPorts(1, 1024);
auto connections = net_mgr.getActiveConnections();
```

### LogAnalyzer (`smlog_api.h`)
Чтение и поиск по системным логам.

```cpp
Asmu::LogAnalyzer log_analyzer;
auto entries = log_analyzer.readLogFile("/var/log/syslog");
auto search_results = log_analyzer.searchLogFile("/var/log/auth.log", "sshd");
```

### SSHSecurity (`smssh_api.h`)
Анализ конфигурации SSH и обнаружение атак.

```cpp
Asmu::SSHSecurity ssh_sec;
auto report = ssh_sec.analyzeConfiguration("/etc/ssh/sshd_config");
auto attacks = ssh_sec.detectAttacks("/var/log/auth.log");
```

### AttackDatabase (`smdb_api.h`)
Поиск по базе MITRE ATT&CK.

```cpp
Asmu::AttackDatabase attack_db;
auto attacks = attack_db.searchAttacks("brute force");
auto info = attack_db.getAttackInfo("T1110");
```

## Ошибки

Методы возвращают `Result<T>` с флагом успеха и сообщением:

```cpp
auto result = pwd_mgr.hashString("test", Asmu::HashAlgorithm::SHA256);
if (result.success()) {
    std::cout << "Хэш: " << result.data << std::endl;
} else {
    std::cerr << "Ошибка: " << result.message << std::endl;
}
```

## Зависимости

- OpenSSL (libssl, libcrypto)
- libpcap
- libmaxminddb
- Стандартная библиотека C++20

## Примеры

Полный пример: `api/example.cpp` (или `api/api_example.cpp`).

## Тесты

```bash
make check     # Все тесты, включая API
make api_test  # Только тесты API (если есть)
```

## Коды ошибок

- `SUCCESS` — успех
- `FILE_NOT_FOUND` — файл не найден
- `PERMISSION_DENIED` — нет прав
- `INVALID_ARGUMENT` — неверный аргумент
- `NETWORK_ERROR` — сетевая ошибка
- `ENCRYPTION_ERROR` — ошибка шифрования
- `DATABASE_ERROR` — ошибка БД
- `UNKNOWN_ERROR` — неизвестная ошибка

## Память

Используется RAII: ресурсы освобождаются при выходе объекта из области видимости.

## Версия

```cpp
std::string version = Asmu::getVersion();
// Например: "1.0.0"
```

## Доработка API

1. Обновить заголовок в `api/include/`.
2. Реализовать в `api/src/`.
3. Добавить тесты в `api_test.cpp` (если есть).
4. Обновить документацию и примеры.
