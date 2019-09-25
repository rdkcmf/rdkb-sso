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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <curl/curl.h>
#include "sso.h"


#define MAX_CS_LEN 32
#define CS_CMD_FILE "/etc/mount-utils/getConfigFile.sh"
#define CS_CMD "getConfigFile"
#define CS_FILE_DIR "/tmp/.webui"
#define CS_FILE_NAME "/tmp/.webui/rcdefal.lll"
#define CURL_FILE_WRITE   // defined for writing to file

#ifdef ENABLE_SSO_LOGS
#define SSO_LOG_NAME "/rdklogs/logs/ssoLog.txt"
static char logbuf[256];
#endif


int getToken( char *pURI, char *pClientId, char* pParams, void *pJWT )
{
    char *pPostFields = NULL;
    CURL *cp;
    size_t len = 0;
    long lHttp_code = 0;
    const char *pClientIDName = "client_id=";
    const char *pClientSecretName = "client_secret=";
    const char *pGrantType = "grant_type=authorization_code";
    CURLcode RetCode;
    int iRet = 1;	
    char ClientSecret[MAX_CS_LEN + 1];      // includes a NULL

    curl_global_init(CURL_GLOBAL_ALL);
    cp = curl_easy_init();
    if( cp != NULL )
    {
#ifndef _ATOM_NO_EROUTER0_
        // atom processors that use meta-rdk-soc-intel-gw do not have
        // an erouter0 interface. Do not compile this option in.
        curl_easy_setopt( cp, CURLOPT_INTERFACE, "erouter0" );
#endif
        curl_easy_setopt( cp, CURLOPT_POST, 1L );

        // uses the curl default certificate path or file specified
        // during curl compile by --with-ca-path or --with-ca-bundle.
        curl_easy_setopt( cp, CURLOPT_SSL_VERIFYPEER, 1L );
        curl_easy_setopt( cp, CURLOPT_SSL_VERIFYHOST, 1L );

        curl_easy_setopt( cp, CURLOPT_URL, pURI );

        curl_easy_setopt( cp, CURLOPT_WRITEFUNCTION, curl_write_data );
        curl_easy_setopt( cp, CURLOPT_WRITEDATA, pJWT );

        len = strlen( pParams );
        ++len;                      // make room for an ampersand
        len += strlen( pGrantType );
        ++len;                      // make room for an ampersand
        len += strlen( pClientIDName );
        len += strlen( pClientId );
        ++len;                      // make room for an ampersand
        len += strlen( pClientSecretName );
        len += sizeof( ClientSecret );
        ++len;                      // make room for a NULL
        pPostFields = malloc( len );
        if( pPostFields != NULL )
        {
            if( getClientSecret( ClientSecret ) == 0 )
            {
                snprintf( pPostFields, len, "%s%c%s%c%s%s%c%s%s", pParams, '&',
                          pGrantType, '&', pClientIDName, pClientId, '&',
                          pClientSecretName, ClientSecret );
                curl_easy_setopt( cp, CURLOPT_POSTFIELDS, pPostFields );
                RetCode = curl_easy_perform( cp );
                curl_easy_getinfo( cp, CURLINFO_RESPONSE_CODE, &lHttp_code );
                snprintf( logbuf, sizeof( logbuf ), "RetCode = %ld\n", (long)RetCode );
                logOut( logbuf );
                snprintf( logbuf, sizeof( logbuf ), "curl returned HTTP code = %ld\n", lHttp_code );
                logOut( logbuf );
                memwipe( pPostFields, len );
                memwipe( ClientSecret, sizeof( ClientSecret ) );
                if( lHttp_code == 200 )
                {
                    iRet = 0;    // signal success
                }
            }
            free( pPostFields );
        }
        else
        {
            logOut( "getToken: Error, unable to allocate memory!\n" ) ;
        }
        curl_easy_cleanup( cp );
    }
    else
    {
        logOut( "getToken: Error, unable to create curl instance!\n" ) ;
    }

    return iRet;
}

static int getClientSecret( char *cs )
{
    FILE *fp;
    char *tmpptr;
    int i;
    int iRet = 1;
    char cmdbuf[256];
    char c;


    if( cs )
    {
        mkdir( CS_FILE_DIR, S_IRWXU | S_IRWXG | S_IRWXO );    // we don't care about errors
        *cs = 0;        // just NULL string
        i = sizeof( cmdbuf );
        snprintf( cmdbuf, i - 1, ". %s; %s %s", CS_CMD_FILE, CS_CMD, CS_FILE_NAME );
        system( cmdbuf );
        memwipe( cmdbuf, i );
        if( ( fp = fopen ( CS_FILE_NAME, "r" ) ) != NULL )
        {
            tmpptr = cs;
            // exit on EOF or 0x0a
            while( (c = fgetc( fp )) != EOF && c != 0x0a && --i )
            {
                *tmpptr++ = (char)c;
            }
            *tmpptr = 0;
            fclose( fp );
            iRet = 0;
        }
        else
        {
            logOut( "getClientSecret: Unable to open file for reading\n" );
        }
        remove( CS_FILE_NAME );
    }

    return iRet;
}

#ifndef USE_BZERO_SSO
static void memwipe( volatile void *buf, int len )
{
    int i;

    memset( (void*)buf, 0, len );
    for( i=0; i < len; i++ )
    {
        if( ((char*)buf)[i] != 0 )
        {
            exit( i /( ((char*)buf)[i] == 0 ) );
        }
    }
}
#endif

#ifdef CURL_FILE_WRITE
// use this function to write the curl data to a file
static size_t curl_write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}
#else    // undefined for function to write curl data to memory
// use this function to write the curl data to a file
typedef struct
{
  char *mem;
  size_t size;
} CURLMEM;

static size_t curl_write_data( void *contents, size_t size, size_t nmemb, void *userp )
{
    size_t realsize = size * nmemb;
    CURLMEM *mem = (CURLMEM *)userp;
 
    char *ptr = realloc( mem->mem, mem->size + realsize + 1 );
    snprintf( logbuf, sizeof( logbuf ), "curl_write_data: reallocing = %d bytes\n", mem->size + realsize + 1 );
    logOut( logbuf );
    if( ptr != NULL )
    {
        mem->mem = ptr;
        memcpy( &(mem->mem[mem->size]), contents, realsize );
        mem->size += realsize;
        mem->mem[mem->size] = 0;
    }
    else
    {
        /* out of memory! */ 
        logOut( "curl_write_data: out of memory!\n" );
        realsize = 0;
    }
 
    return realsize;
}
#endif

#ifdef ENABLE_SSO_LOGS
void logOut( char *logline )
{
    struct tm *tm_info;
    FILE *fp;
    time_t curtime;
    char buf[80];

    if( (fp=fopen( SSO_LOG_NAME, "a" )) != NULL )
    {
        curtime = time( NULL );

        tm_info = gmtime( &curtime );

        strftime( buf, sizeof( buf ) - 1, "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf( fp, "%s: %s", buf, logline );
        fflush( fp );
        fclose( fp );
    }
    else
    {
        fprintf( stdout, "logOut: failed to open %s\n", SSO_LOG_NAME );
        fflush( fp );
    }
}
#endif
