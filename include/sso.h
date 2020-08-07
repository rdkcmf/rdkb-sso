/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef __SSO_H
#define __SSO_H

//#define USE_BZERO_SSO // not available in this version of glibc
#define ENABLE_SSO_LOGS

#define WEBUI_LOG_NAME "/rdklogs/logs/webui.log"

#ifdef USE_BZERO_SSO
#define memwipe( buf, x ) explicit_bzero( (void*)buf, (size_t)x )
#else
static void memwipe( volatile void *buf, int len );
#endif

int getToken( char *pURI, char *pClientId, char* pParams, void *pJWT );
#ifdef ENABLE_SSO_LOGS
void logOut( char *logline );
#else
#define logOut(ptr)
#endif

static size_t curl_write_data(void *ptr, size_t size, size_t nmemb, void *stream);
static int getClientSecret( char *cs, char *pClientId );
#endif
