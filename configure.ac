#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([ddosmon], [2.0], [nenolod@systeminplace.net])
AC_CONFIG_SRCDIR([src/stdinc.h])
AC_CONFIG_HEADERS([src/autoconf.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_open_live])
AC_CHECK_LIB([ssh2], [libssh2_channel_write])
AC_CHECK_LIB([dl], [dlopen])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 memset socket strcasecmp strchr strdup strerror strrchr getrlimit])

BUILDSYS_INIT
BUILDSYS_SHARED_LIB
BUILDSYS_TOUCH_DEPS

AC_CONFIG_FILES([buildsys.mk extra.mk])
AC_OUTPUT
