MODULE = source
SRCS = netflow.c pcap.c linux-native.c

include ../../../buildsys.mk
include ../../../buildsys.module.mk
include ../../../extra.mk

CPPFLAGS += -I../.. ${MOWGLI_CFLAGS}
LIBS += ${MOWGLI_LIBS}
