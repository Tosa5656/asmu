#-------------------------------------------------
# ASMU GUI Project File
# Графический интерфейс для ASMU утилит
#-------------------------------------------------

QT       += core gui widgets

TARGET = asmu-gui
TEMPLATE = app

CONFIG += c++20

# Определения компилятора
DEFINES += QT_DEPRECATED_WARNINGS

# Директории для объектных файлов
OBJECTS_DIR = obj
MOC_DIR = obj
RCC_DIR = obj
UI_DIR = obj

# Исходные файлы
SOURCES += \
    main.cpp \
    mainwindow.cpp \
    smpass_widget.cpp \
    smnet_widget.cpp \
    smlog_widget.cpp \
    smssh_widget.cpp \
    smdb_widget.cpp

# Заголовочные файлы
HEADERS += \
    mainwindow.h \
    smpass_widget.h \
    smnet_widget.h \
    smlog_widget.h \
    smssh_widget.h \
    smdb_widget.h

# Пути к API
INCLUDEPATH += ../api/include

# Линковка с библиотекой ASMU
LIBS += -L.. -lasmu -lssl -lcrypto -lpcap -lmaxminddb

# Установка
unix {
    target.path = /usr/local/bin
    INSTALLS += target
}

# Компилятор
QMAKE_CXX = g++
QMAKE_CXXFLAGS += -Wall -Werror -std=c++20
