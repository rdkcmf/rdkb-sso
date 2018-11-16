
#include <stdio.h>
#include <stdlib.h>

#include "sso_api.h"
#include "sso.h"


int SSOgetJWT( char *pURI, char *pClient_Id, char* pParams, char *pFileName )
{
    FILE *pJWT;
    int iRet = 1;

logOut( "SSOgetJWT: Entrance\n" ) ;
    if( (pJWT=fopen( pFileName, "w" )) != NULL )
    { 
        if( getToken( pURI, pClient_Id, pParams, pJWT ) == 0 )
        {
            iRet = 0;
        }
        else
        {
            logOut( "SSOgetJWT: Error, Cannot get token!!\n" ) ;
        }
        fclose( pJWT );
    }
    else
    {
        logOut( "SSOgetJWT: Error, Cannot open file for token storage!!\n" ) ;
        iRet = 2;
    }

logOut( "SSOgetJWT: Exiting\n" ) ;
    return iRet;
}

