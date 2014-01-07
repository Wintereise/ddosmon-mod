MODULE = source
SRCS = netflow.c pcap.c linux-native.c nfq.c

include ../../../buildsys.mk
include ../../../buildsys.module.mk
include ../../../extra.mk

CPPFLAGS += -I../.. ${MOWGLI_CFLAGS}
LIBS += ${MOWGLI_LIBS} -lnetfilter_queue -lnfnetlink

