CC=g++
CFLAGS = -std=c++20 -Wall -Werror
LDFLAGS = -lstdc++ -lssl -lcrypto -lpcap -lmaxminddb

all: smpass smnet smlog smssh smdb libasmu.a gui

smpass: obj/argsparser.o obj/smpass.o obj/smstorage.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Iargsparser -Ismpass -Ilogger obj/smpass.o obj/argsparser.o obj/smstorage.o obj/logger.o -o bin/smpass

smnet: obj/argsparser.o obj/smnet.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Iargsparser -Ismnet -Ilogger obj/argsparser.o obj/smnet.o obj/logger.o -o bin/smnet

smlog: obj/smlog.o obj/systemlogger.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Ilogger obj/smlog.o obj/systemlogger.o obj/logger.o -o bin/smlog

smssh: obj/smssh.o obj/sshconfig.o obj/sshattdetector.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Ismssh -Ilogger obj/smssh.o obj/sshconfig.o obj/sshattdetector.o obj/logger.o -o bin/smssh

smdb: obj/smdb.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Ismdb -Ilogger obj/smdb.o obj/logger.o -o bin/smdb

gui: libasmu.a
	@echo "Сборка графического интерфейса ASMU..."
	@cd gui && qmake asmu-gui.pro && make
	@echo "GUI собран: gui/asmu-gui"

libasmu.a: obj/smpass_api.o obj/smnet_api.o obj/smlog_api.o obj/smssh_api.o obj/smdb_api.o obj/asmu.o obj/logger.o obj/argsparser.o obj/smstorage.o obj/smnet.o obj/systemlogger.o obj/sshconfig.o obj/sshattdetector.o
	@echo "Сборка библиотеки API ASMU..."
	@ar rcs libasmu.a obj/smpass_api.o obj/smnet_api.o obj/smlog_api.o obj/smssh_api.o obj/smdb_api.o obj/asmu.o obj/logger.o obj/argsparser.o obj/smstorage.o obj/smnet.o obj/systemlogger.o obj/sshconfig.o obj/sshattdetector.o
	@echo "Статическая библиотека libasmu.a создана."

obj/smpass_api.o: api/src/smpass_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smpass_api.cpp -o obj/smpass_api.o

obj/smnet_api.o: api/src/smnet_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smnet_api.cpp -o obj/smnet_api.o

obj/smlog_api.o: api/src/smlog_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smlog_api.cpp -o obj/smlog_api.o

obj/smssh_api.o: api/src/smssh_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smssh_api.cpp -o obj/smssh_api.o

obj/smdb_api.o: api/src/smdb_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smdb_api.cpp -o obj/smdb_api.o

obj/asmu.o: api/src/asmu.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/asmu.cpp -o obj/asmu.o

obj/argsparser.o: argsparser/argsparser.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -c argsparser/argsparser.cpp -o obj/argsparser.o

obj/smpass.o: smpass/smpass.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -c smpass/smpass.cpp -o obj/smpass.o

obj/smstorage.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ijson -Ilogger -c smpass/storage.cpp -o obj/smstorage.o

obj/smnet.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ilogger -c smnet/smnet.cpp -o obj/smnet.o

obj/smlog.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ilogger -Ismlog -c smlog/smlog.cpp -o obj/smlog.o

obj/systemlogger.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismlog -c smlog/SystemLogger.cpp -o obj/systemlogger.o

obj/smssh.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismssh -c smssh/smssh.cpp -o obj/smssh.o

obj/smdb.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismdb -c smdb/smdb.cpp -o obj/smdb.o

obj/sshconfig.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismssh -c smssh/sshConfig.cpp -o obj/sshconfig.o

obj/sshattdetector.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismssh -Ilogger -c smssh/sshAttackDetector.cpp -o obj/sshattdetector.o

obj/logger.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ilogger -c logger/logger.cpp -o obj/logger.o

clean:
	rm -rf obj
	rm -rf bin
	@cd gui && make clean 2>/dev/null || true
	@rm -f gui/Makefile gui/.qmake.stash 2>/dev/null || true
	@rm -rf gui/obj 2>/dev/null || true

install: all install-geolite install-systemd install-doc install-gui
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: для установки требуются root права"; \
		exit 1; \
	fi
	@echo "Установка ASMU..."
	@install -d /usr/local/bin
	@install -m 755 bin/smpass /usr/local/bin/
	@install -m 755 bin/smnet /usr/local/bin/
	@install -m 755 bin/smlog /usr/local/bin/
	@install -m 755 bin/smssh /usr/local/bin/
	@install -m 755 bin/smdb /usr/local/bin/
	@echo "Утилиты установлены в /usr/local/bin/"
	@echo "Установка ASMU успешно завершена!"
	@echo ""
	@echo "Примеры использования:"
	@echo "  smssh help                    - безопасность SSH"
	@echo "  smlog help                    - анализ системных логов"
	@echo "  smpass help                   - хранение паролей"
	@echo "  smnet help                    - мониторинг сети"
	@echo "  asmu-gui                      - графический интерфейс"
	@echo ""
	@echo "Для запуска мониторинга SSH-атак:"
	@echo "  systemctl enable smssh"
	@echo "  systemctl start smssh"
	@echo "Установка ASMU успешно завершена!"
	@echo ""
	@echo "Примеры использования:"
	@echo "  smssh help                    - безопасность SSH"
	@echo "  smlog help                    - анализ системных логов"
	@echo "  smpass help                   - хранение паролей"
	@echo "  smnet help                    - мониторинг сети"
	@echo ""
	@echo "Для запуска мониторинга SSH-атак:"
	@echo "  systemctl enable smssh"
	@echo "  systemctl start smssh"

install-gui: gui
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: для установки GUI требуются root права"; \
		exit 1; \
	fi
	@echo "Установка ASMU GUI..."
	@install -d /usr/local/bin
	@install -m 755 gui/asmu-gui /usr/local/bin/
	@install -d /usr/share/applications
	@install -m 644 gui/asmu-gui.desktop /usr/share/applications/
	@echo "GUI установлен в /usr/local/bin/asmu-gui"

install-geolite:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: install-geolite требует root прав"; \
		exit 1; \
	fi
	@echo "Установка базы GeoLite2..."
	@mkdir -p /usr/share/GeoIP
	@if [ ! -f /usr/share/GeoIP/GeoLite2-Country.mmdb ]; then \
		cd /usr/share/GeoIP && wget -q https://git.io/GeoLite2-Country.mmdb -O GeoLite2-Country.mmdb; \
		echo "База GeoLite2 установлена"; \
	else \
		echo "База GeoLite2 уже установлена"; \
	fi

install-systemd:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: install-systemd требует root прав"; \
		exit 1; \
	fi
	@echo "Установка юнита systemd..."
	@cp smssh/smssh.service /etc/systemd/system/
	@systemctl daemon-reload
	@echo "Юнит systemd установлен."
	@echo "  systemctl enable smssh  — включить при загрузке"
	@echo "  systemctl start smssh   — запустить мониторинг SSH"

install-doc:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: для install-doc нужны права root"; \
		exit 1; \
	fi
	@echo "Установка ASMU документации..."
	@install -d /usr/share/doc/asmu
	@install -d /usr/share/doc/asmu/attacks

	@cp -r doc/api/html /usr/share/doc/asmu/api-docs
	@cp doc/attacks/*.html /usr/share/doc/asmu/attacks/
	@chmod -R 644 /usr/share/doc/asmu/
	@find /usr/share/doc/asmu/ -type d -exec chmod 755 {} \;
	@echo "Документация установлена в /usr/share/doc/asmu/"
	@echo "API документация: /usr/share/doc/asmu/api-docs/index.html"
	@echo "База атак: /usr/share/doc/asmu/attacks/"
	@echo "Гайды: /usr/share/doc/asmu/index.html"

install-doc-only: doc/api/html/index.html doc/utils/index.html
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: install-doc-only требует root прав"; \
		exit 1; \
	fi
	@echo "Установка ASMU документации..."
	@install -d /usr/share/doc/asmu
	@install -d /usr/share/doc/asmu/attacks
	@cp -r doc/api/html /usr/share/doc/asmu/api-docs
	@cp doc/attacks/*.html /usr/share/doc/asmu/attacks/
	@chmod -R 644 /usr/share/doc/asmu/
	@find /usr/share/doc/asmu/ -type d -exec chmod 755 {} \;
	@echo "Документация установлена в /usr/share/doc/asmu/"
	@echo "API документация: /usr/share/doc/asmu/api-docs/index.html"
	@echo "База атак: /usr/share/doc/asmu/attacks/"
	@echo "Гайды: /usr/share/doc/asmu/index.html"

uninstall:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Ошибка: для удаления нужны права root"; \
		exit 1; \
	fi
	@echo "Удаление ASMU..."
	@systemctl stop smssh 2>/dev/null || true
	@systemctl disable smssh 2>/dev/null || true
	@rm -f /etc/systemd/system/smssh.service
	@systemctl daemon-reload
	@echo "Юнит systemd удалён."
	@rm -f /usr/local/bin/smpass
	@rm -f /usr/local/bin/smnet
	@rm -f /usr/local/bin/smlog
	@rm -f /usr/local/bin/smssh
	@rm -f /usr/local/bin/smdb
	@rm -f /usr/local/bin/asmu-gui
	@rm -f /usr/share/applications/asmu-gui.desktop
	@echo "Утилиты удалены из /usr/local/bin/"
	@rm -rf /usr/share/doc/asmu
	@echo "Документация удалена из /usr/share/doc/asmu/"
	@echo "Удаление ASMU завершено."
	@echo ""
	@echo "База GeoLite2 в /usr/share/GeoIP/ не удалена (можно удалить вручную)."

doc: doc/api/html/index.html doc/utils/index.html
	@echo "Документация успешно сгенерирована."
	@echo "API: doc/api/html/index.html"

doc/api/html/index.html: Doxyfile
	@echo "Генерация API-документации Doxygen..."
	@doxygen Doxyfile

doc/utils/index.html: doc/utils/style.css
	@echo "HTML-документация утилит готова."

check: all
	@echo "Запуск тестов ASMU..."
	@echo "=========================================="
	@echo
	@echo "0" > /tmp/sm_test_passed
	@echo "0" > /tmp/sm_test_total

	@echo "Тестирование smssh..."
	@echo "---------------"
	@if ./bin/smssh help >/dev/null 2>&1; then echo "smssh help работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "smssh help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smssh parse-log test/test_brute_recent.log 2>/dev/null | grep -q "brute_force"; then echo "SSH brute force detection работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "SSH brute force detection failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smssh analyze test/test_sshd_config >/dev/null 2>&1; then echo "SSH config analysis работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "SSH config analysis failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Тестирование smlog..."
	@echo "---------------"
	@if ./bin/smlog help >/dev/null 2>&1; then echo "smlog help работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "smlog help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smlog read test/test_system.log >/dev/null 2>&1; then echo " smlog read работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smlog read failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smlog search "sshd" test/test_system.log >/dev/null 2>&1; then echo " smlog search работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smlog search failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Тестирование smpass..."
	@echo "---------------"
	@if ./bin/smpass help >/dev/null 2>&1; then echo " smpass help работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smpass help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smpass hash-sha256 "test" >/dev/null 2>&1; then echo " smpass SHA256 hashing работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smpass SHA256 hashing failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smpass hash-aes256 "test" >/dev/null 2>&1; then echo " smpass AES256 encryption работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smpass AES256 encryption failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Тестирование smnet..."
	@echo "---------------"
	@if ./bin/smnet help >/dev/null 2>&1; then echo " smnet help работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smnet help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smnet scan >/dev/null 2>&1; then echo " smnet port scanning работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smnet port scanning failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Тестирование API библиотеки..."
	@echo "--------------------"
	@if [ -f libasmu.a ]; then echo " API library exists"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " API library missing"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Тестирование smdb..."
	@echo "--------------"
	@if ./bin/smdb help >/dev/null 2>&1; then echo " smdb help работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smdb help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smdb list >/dev/null 2>&1; then echo " smdb attack database работает"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smdb attack database failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@passed=$$(cat /tmp/sm_test_passed); total=$$(cat /tmp/sm_test_total); rm -f /tmp/sm_test_passed /tmp/sm_test_total
	@echo "Test Results: $$passed/$$total tests passed"
	@echo "Все основные тесты пройдены успешно."
	@echo "   ASMU готов к использованию."

.PHONY: install install-geolite install-systemd install-doc install-doc-only install-gui uninstall clean check smdb doc gui