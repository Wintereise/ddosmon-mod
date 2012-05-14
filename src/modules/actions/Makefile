MODULE = actions

include ../../../buildsys.mk
include ../../../extra.mk
include ../../../buildsys.module.mk

CPPFLAGS += -I../.. ${MOWGLI_CFLAGS}
LIBS += -lm -lssh2 ${MOWGLI_LIBS}
SRCS = customscript.c nullroute.c email.c
