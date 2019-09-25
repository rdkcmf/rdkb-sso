##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2019 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES=libsso.la
libsso_la_SOURCES = sso_api.c sso.c
libsso_la_CFLAGS = $(CURL_CFLAGS) $(OPENSSL_CFLAGS) $(AM_CFLAGS)
libsso_la_LDFLAGS = $(CURL_LIBS) $(OPENSSL_LIBS)

