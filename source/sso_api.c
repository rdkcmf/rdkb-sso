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

