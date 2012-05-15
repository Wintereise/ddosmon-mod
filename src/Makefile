PROG = ddosmon
SRCS = action.c confprocess.c ipstate.c main.c modulefactory.c sourcefactory.c patricia.c
SUBDIRS = modules

include ../buildsys.mk
include ../extra.mk

CPPFLAGS += -DPREFIX='"$(prefix)"' ${MOWGLI_CFLAGS}
LIBS += -lm -lpcap -ldl ${MOWGLI_LIBS} -Wl,-export-dynamic
