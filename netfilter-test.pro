TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue


SOURCES += \
        main.c

HEADERS += \
    headers.h
