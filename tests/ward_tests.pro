QT += core gui qml network sql testlib

CONFIG += c++17 console testcase
TARGET = ward_tests
TEMPLATE = app
LIBS += -larchive
DEFINES += FIXTURES=\\\"$$PWD/fixtures\\\"

HEADERS += $$files(../src/*.h)
SOURCES += ward_tests.cpp $$files(../src/*.cpp)
SOURCES -= ../src/main.cpp ../src/cli.cpp
RESOURCES += ../src/resources.qrc
