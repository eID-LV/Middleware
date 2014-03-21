include $(top_srcdir)/win32/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
EXTRA_DIST = Makefile.mak

dist_noinst_SCRIPTS = opensc_pkcs11_install.js
lib_LTLIBRARIES = libotlvpkcs11.la libpkcs11spy.la libonepinotlvpkcs11.la

AM_CFLAGS = $(OPTIONAL_OPENSSL_CFLAGS) $(PTHREAD_CFLAGS)
INCLUDES = -I$(top_srcdir)/src

OPENSC_PKCS11_INC = sc-pkcs11.h pkcs11.h pkcs11-opensc.h
OPENSC_PKCS11_SRC = pkcs11-global.c pkcs11-session.c pkcs11-object.c misc.c slot.c \
	mechanism.c openssl.c framework-pkcs15.c \
	framework-pkcs15init.c debug.c opensc-pkcs11.exports \
	pkcs11-display.c pkcs11-display.h
OPENSC_PKCS11_LIBS = $(OPTIONAL_OPENSSL_LIBS) $(PTHREAD_LIBS) $(LTLIB_LIBS) \
	$(top_builddir)/src/common/libcompat.la \
	$(top_builddir)/src/libopensc/libotlvopensc.la

libotlvpkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC) hack-disabled.c
libotlvpkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
libotlvpkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/opensc-pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

libonepinotlvpkcs11_la_SOURCES = $(OPENSC_PKCS11_SRC) $(OPENSC_PKCS11_INC) hack-enabled.c
libonepinotlvpkcs11_la_LIBADD = $(OPENSC_PKCS11_LIBS)
libonepinotlvpkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/opensc-pkcs11.exports" \
	-module -shared -avoid-version -no-undefined

libpkcs11spy_la_SOURCES = pkcs11-spy.c pkcs11-display.c pkcs11-display.h pkcs11-spy.exports
libpkcs11spy_la_LIBADD = $(OPTIONAL_OPENSSL_LIBS) $(LTLIB_LIBS) $(top_builddir)/src/common/libpkcs11.la
libpkcs11spy_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/pkcs11-spy.exports" \
	-module -shared -avoid-version -no-undefined

if WIN32
libotlvpkcs11_la_SOURCES += $(top_builddir)/win32/versioninfo.rc
libonepinotlvpkcs11_la_SOURCES += $(top_builddir)/win32/versioninfo.rc
libpkcs11spy_la_SOURCES += $(top_builddir)/win32/versioninfo.rc
endif

jar-dir:
	if test ! -d jar-dir ; then mkdir jar-dir ; fi

pkcs11-jar: jar-dir
	cp .libs/*.so jar-dir
	cp opensc_pkcs11_install.js jar-dir
	signtool -Z"otlv-pkcs11.jar" -i"opensc_pkcs11_install.js" \
		 -k"testcert" jar-dir

if WIN32
install-exec-hook:	install-pkcs11DATA
	for l in libotlvpkcs11.dll libonepinotlvpkcs11.dll libpkcs11spy.dll; do \
		mv "$(DESTDIR)$(libdir)/$$l" "$(DESTDIR)$(bindir)/$$l"; \
	done
else
# see http://wiki.cacert.org/wiki/Pkcs11TaskForce
pkcs11_DATA = #This will create the directory
if CYGWIN
PKCS11_SUFFIX=.dll
else
PKCS11_SUFFIX=.so
endif
install-exec-hook:	install-pkcs11DATA
	for l in libotlvpkcs11$(PKCS11_SUFFIX) libonepinotlvpkcs11$(PKCS11_SUFFIX) libpkcs11spy$(PKCS11_SUFFIX); do \
		rm -f "$(DESTDIR)$(pkcs11dir)/$$l"; \
		$(LN_S) ../$$l "$(DESTDIR)$(pkcs11dir)/$$l"; \
	done; \
	$(LN_S) ../libotlvpkcs11$(PKCS11_SUFFIX) "$(DESTDIR)$(pkcs11dir)/otlv-pkcs11$(PKCS11_SUFFIX)"; \
	$(LN_S) ../libonepinotlvpkcs11$(PKCS11_SUFFIX) "$(DESTDIR)$(pkcs11dir)/onepin-otlv-pkcs11$(PKCS11_SUFFIX)"; \
	$(LN_S) ../libpkcs11spy$(PKCS11_SUFFIX) "$(DESTDIR)$(pkcs11dir)/pkcs11-spy$(PKCS11_SUFFIX)"; \
	$(LN_S) libotlvpkcs11$(PKCS11_SUFFIX) "$(libdir)/otlv-pkcs11$(PKCS11_SUFFIX)"; \
	$(LN_S) libonepinotlvpkcs11$(PKCS11_SUFFIX) "$(libdir)/onepin-otlv-pkcs11$(PKCS11_SUFFIX)"; \
	$(LN_S) libpkcs11spy$(PKCS11_SUFFIX) "$(libdir)/pkcs11-spy$(PKCS11_SUFFIX)"; \
	$(LN_S) libotlvopensc$(PKCS11_SUFFIX) "$(libdir)/otlv-opensc$(PKCS11_SUFFIX)";

endif
