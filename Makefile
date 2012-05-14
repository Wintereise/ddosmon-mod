SUBDIRS = src

include extra.mk
include buildsys.mk

install-extra:
	for i in ddosmon.conf; do \
		${INSTALL_STATUS}; \
		if ${MKDIR_P} ${DESTDIR}${sysconfdir} && ${INSTALL} -m 644 dist/$$i ${DESTDIR}${sysconfdir}/$${i}.sample; then \
			${INSTALL_OK}; \
		else \
			${INSTALL_FAILED}; \
		fi; \
	done

