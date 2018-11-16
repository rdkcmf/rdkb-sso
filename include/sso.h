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

//int SSOgetJWT( char *pURI, char *pClient_Id, char* pParams, char *pFileName );
static size_t curl_write_data(void *ptr, size_t size, size_t nmemb, void *stream);
static int getClientSecret( char *cs );
#endif
