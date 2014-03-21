MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
DISTCLEANFILES = latvia-eid.conf 

SUFFIXES = .in

dist_noinst_DATA = opensc.conf.in
nodist_noinst_DATA = latvia-eid.conf	# For Windows MSVC build

# Make sure we build this every time
# as there is no dependency for this.
# Can be removed if MSVC is not requried.
force:
latvia-eid.conf: opensc.conf.in force
	sed \
		-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
		-e 's|@DEFAULT_PCSC_PROVIDER[@]|$(DEFAULT_PCSC_PROVIDER)|g' \
		< $< > $@

sysconf_DATA=#required in order to create dir
install-exec-hook:	install-sysconfDATA latvia-eid.conf
	if [ -f "$(DESTDIR)$(sysconfdir)/latvia-eid.conf" ]; then \
		$(INSTALL_DATA) latvia-eid.conf "$(DESTDIR)$(sysconfdir)/latvia-eid.conf.new"; \
	else \
		$(INSTALL_DATA) latvia-eid.conf "$(DESTDIR)$(sysconfdir)/latvia-eid.conf"; \
	fi
