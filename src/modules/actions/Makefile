MODULE = actions
SRCS = customscript.c nullroute.c email.c

include ../../../buildsys.mk
include ../../../buildsys.module.mk
include ../../../extra.mk

CPPFLAGS += -I../.. ${MOWGLI_CFLAGS}
LIBS += -lm -lssh2 ${MOWGLI_LIBS}
