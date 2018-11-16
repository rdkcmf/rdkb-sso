AM_CFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES=libsso.la
libsso_la_SOURCES = sso_api.c sso.c
libsso_la_CFLAGS = $(CURL_CFLAGS) $(OPENSSL_CFLAGS) $(AM_CFLAGS)
libsso_la_LDFLAGS = $(CURL_LIBS) $(OPENSSL_LIBS)

