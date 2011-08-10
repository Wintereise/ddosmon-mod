PROG = ddosmon
SRCS = action.c confparse.c confprocess.c dissectors.c ipstate.c main.c modulefactory.c patricia.c strlcpy.c

include ../buildsys.mk

SUBDIRS = modules
CFLAGS += -DPREFIX='"$(prefix)"'
LIBS += -lm -lpcap -ldl -Wl,-export-dynamic
