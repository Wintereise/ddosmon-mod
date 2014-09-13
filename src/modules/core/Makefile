MODULE = core
SRCS = dynamic.c exempts.c triggers.c nullable.c threshold.c

include ../../../buildsys.mk
include ../../../buildsys.module.mk
include ../../../extra.mk

CPPFLAGS += -I../.. ${MOWGLI_CFLAGS}
LIBS += -lm ${MOWGLI_LIBS}
