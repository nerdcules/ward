QT += core gui qml quick quickcontrols2 network sql

CONFIG += c++17 release
TARGET = ward
TEMPLATE = app
LIBS += -larchive

HEADERS += \
    src/translator.h \
    src/theme.h \
    src/schedule.h \
    src/report.h \
    src/notifier.h \
    src/backend.h \
    src/cli.h \
    src/cve5.h \
    src/cvelist.h \
    src/exposure.h \
    src/feeds.h \
    src/inventory.h \
    src/matcher.h \
    src/net.h \
    src/paths.h \
    src/review.h \
    src/store.h \
    src/triage.h \
    src/vercmp.h \
    src/zip.h

SOURCES += \
    src/translator.cpp \
    src/theme.cpp \
    src/schedule.cpp \
    src/report.cpp \
    src/notifier.cpp \
    src/backend.cpp \
    src/main.cpp \
    src/cli.cpp \
    src/cve5.cpp \
    src/cvelist.cpp \
    src/exposure.cpp \
    src/feeds.cpp \
    src/inventory.cpp \
    src/matcher.cpp \
    src/net.cpp \
    src/paths.cpp \
    src/review.cpp \
    src/store.cpp \
    src/triage.cpp \
    src/vercmp.cpp \
    src/zip.cpp

RESOURCES += src/resources.qrc
