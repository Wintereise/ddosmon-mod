PROG = ddosmon
SRCS = action.c confparse.c confprocess.c ipstate.c main.c modulefactory.c patricia.c strlcpy.c
SUBDIRS = modules

include ../buildsys.mk
include ../extra.mk

CPPFLAGS += -DPREFIX='"$(prefix)"' ${MOWGLI_CFLAGS}
LIBS += -lm -lpcap -ldl ${MOWGLI_LIBS} -Wl,-export-dynamic
