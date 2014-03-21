/** \file csp11.c
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
          
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <time.h>
#ifdef _MSC_VER
#include "missdef.h"
#else
#include "misscrypt.h"
#endif
#include "pkcs11.h"
#include "csp11.h"
#include "pkcs11-services.h"
#include "ui-pin.h"
#include "csp-debug.h"


HINSTANCE g_hModule = NULL; /**< DLL Instance. */
static CRITICAL_SECTION g_lock;
extern PIN_CACHE g_pinCache[128];
/** \brief Granted provider contexts.
 *
 *  This table contains all pointers to granted cryptographic contexts.
 *  Initialized to NULL.
 *  
 */
static HANDLE    *grantedContexts = (HANDLE*) NULL; /**< Granted contexts.*/
static int      grantedContextsNb = 0;  /**< Number of granted Hashes. */

static HANDLE   *grantedHashes = (HANDLE*) NULL; /**< Table of all granted hashes.*/
static int      grantedHashesNb = 0;  /**< Number of granted Hashes. */

static HANDLE    *grantedKeys = (HANDLE*) NULL; /**< Table of all granted keys handles.*/
static int  grantedKeysNb = 0; /**< Number of actual granted keys.*/

//static HANDLE  GetProcessHeap() = NULL;     /**< Handle to the csp11 heap object. */

ALGORITHM Algs[] = {
    {CALG_MD5,MD5_BITS,MD5_NAME,MD5_LONG_NAME,MD5_MIN_BITS, MD5_MAX_BITS,(BYTE*)MD5_OID, MD5_OID_LEN},
    {CALG_SHA1,SHA_BITS,SHA_NAME,SHA_LONG_NAME,SHA_MIN_BITS, SHA_MAX_BITS,(BYTE*)SHA1_OID,
                                                            SHA1_OID_LEN},
    {CALG_SHA_256,SHA256_BITS,SHA256_NAME,SHA256_LONG_NAME,SHA256_MIN_BITS, SHA256_MAX_BITS,(BYTE*)SHA256_OID,
                                                            SHA256_OID_LEN},
    {CALG_SSL3_SHAMD5,SSL3_SHAMD5_BITS,SSL3_SHAMD5_NAME,SSL3_SHAMD5_LONG_NAME,SSL3_SHAMD5_MIN_BITS,
     SSL3_SHAMD5_MAX_BITS,(BYTE*)SSL3_SHAMD5_OID, SSL3_SHAMD5_OID_LEN},
    {CALG_RSA_SIGN,RSA_SIGN_BITS,RSA_SIGN_NAME,RSA_SIGN_LONG_NAME,RSA_SIGN_MIN_BITS, RSA_SIGN_MAX_BITS,
     NULL,0},
    {CALG_RSA_KEYX,RSA_KEYX_BITS,RSA_KEYX_NAME,RSA_KEYX_LONG_NAME,RSA_KEYX_MIN_BITS, RSA_KEYX_MAX_BITS,
     NULL,0},
    {CALG_DES,DES_BITS,DES_NAME,DES_LONG_NAME,DES_MIN_BITS, DES_MAX_BITS,NULL,0},
    {CALG_3DES_112,DES3_112_BITS,DES3_112_NAME,DES3_112_LONG_NAME,DES3_112_MIN_BITS, DES3_112_MAX_BITS,
     NULL,0},
    {CALG_3DES,DES3_BITS,DES3_NAME,DES3_LONG_NAME,DES3_MIN_BITS, DES3_MAX_BITS,NULL,0},
    {CALG_RC2,RC2_BITS,RC2_NAME,RC2_LONG_NAME,RC2_MIN_BITS, RC2_MAX_BITS,NULL,0},
    {CALG_RC4,RC4_BITS,RC4_NAME,RC4_LONG_NAME, RC4_MIN_BITS, RC4_MAX_BITS,NULL,0}
}; /**< Supported algorithms database.*/


/** \brief Microsoft® Windows® DLL main function.
 *
 *  This function is called when the DLL is attached, detached from a program.
 *  
 *  \param  hinstDLL    Handle to the DLL module.
 *  \param  fdwReason   Reason value of the DLL call.
 *  \param  lpvReserved RFU.
 *
 *  \return TRUE is everything is ok.
 *  
 */
BOOL WINAPI
DllMain(
  HINSTANCE hinstDLL,  // handle to the DLL module
  DWORD fdwReason,     // reason for calling function
  LPVOID lpvReserved)  // reserved
{
    switch( fdwReason ) 
    { 
    
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            g_hModule = hinstDLL;
            InitializeCriticalSection(&g_lock);

            {
                char szPath[MAX_PATH];
                char szMsg[512];
                char szTime[80];
                GetModuleFileNameA(NULL, szPath, MAX_PATH);
                time_t rawtime;
                struct tm * timeinfo;

                time ( &rawtime );
                timeinfo = localtime ( &rawtime );
                strftime (szTime,80,"%x-%X",timeinfo);
#ifdef _WIN64
                sprintf(szMsg, "\r\n\r\n%s (PID=%d): 64-bit CSP loaded by \"%s\"\r\n", szTime, GetCurrentProcessId(), szPath);
#else
                sprintf(szMsg, "\r\n\r\n%s (PID=%d): 32-bit CSP loaded by \"%s\"\r\n", szTime, GetCurrentProcessId(), szPath);
#endif
                DEBUG(1, "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\r\n");
                DEBUG(1, szMsg);
                
            }
            return TRUE;
            break;

        case DLL_PROCESS_DETACH:
            {
                char szPath[MAX_PATH];
                char szMsg[512];
                char szTime[80];
                GetModuleFileNameA(NULL, szPath, MAX_PATH);
                time_t rawtime;
                struct tm * timeinfo;

                time ( &rawtime );
                timeinfo = localtime ( &rawtime );
                strftime (szTime,80,"%x-%X",timeinfo);
#ifdef _WIN64
                sprintf(szMsg, "\r\n\r\n%s (PID=%d): 64-bit CSP detached from \"%s\"\r\n", szTime, GetCurrentProcessId(), szPath);
#else
                sprintf(szMsg, "\r\n\r\n%s (PID=%d): 32-bit CSP detached from \"%s\"\r\n", szTime, GetCurrentProcessId(), szPath);
#endif
                DEBUG(1, szMsg);
                DEBUG(1, "------------------------------------------------------------------------------------\r\n");
                closeDebug();
            }
            SecureZeroMemory(g_pinCache, sizeof(g_pinCache)); 
            DeleteCriticalSection(&g_lock);
            return TRUE;
            break;
    }
    return TRUE;
}


BOOL ReturnData(LPBYTE pbDestData, LPDWORD pcbDestDataLen, CONST BYTE *pbSrcData, DWORD cbSrcData)
{
    DWORD dwError = NO_ERROR;
	if (pcbDestDataLen == NULL)
		dwError = ERROR_INVALID_PARAMETER;
	else if (pbDestData == NULL) {
		*pcbDestDataLen = cbSrcData;
		return TRUE;
	}
	else if (*pcbDestDataLen < cbSrcData) {
		*pcbDestDataLen = cbSrcData;
		dwError = ERROR_MORE_DATA;
	}
    else
    {
	    memcpy(pbDestData, pbSrcData, cbSrcData);
        *pcbDestDataLen = cbSrcData;
	    return TRUE;
    }
    SetLastError(dwError);
    return FALSE;
}


BOOL ReturnString(LPBYTE pbDestData, LPDWORD pcbDestDataLen, LPCSTR szSrcStr)
{ 
    return ReturnData(pbDestData, pcbDestDataLen, (CONST BYTE *)(szSrcStr), (DWORD) strlen(szSrcStr)+1); 
}


BOOL ReturnValue(LPBYTE pbDestData, LPDWORD pcbDestDataLen, DWORD dwValue)
{ 
    return ReturnData(pbDestData, pcbDestDataLen, (CONST BYTE *)(&dwValue), sizeof DWORD); 
}


/** \brief Acquire a context handle to the PKCS #11 CSP.
 */
BOOL WINAPI
CPAcquireContext(
    OUT HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable)
{
    CLocker lock(g_lock);
    LPCSTR cName = NULL;            /*  Local copy of szContainer C string pointer */
    size_t nameSize = 0;        /* Size of the provided container name.*/
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    int verifyOnly  = FALSE;        /* If TRUE, the function only verify Cryptographic Context aquierement */
    HANDLE  heapHandle;             /* Handle to the context heap object. */

    char cReaderName[MAX_PATH] = {0};
    HWND FuncReturnedhWnd = 0;
    
    /** - Nullify the returned hProv.*/
    *phProv = (HCRYPTPROV)NULL; 
    
    /** - Test if dwFlags are correct */
    if (dwFlags & ~(CRYPT_SILENT|CRYPT_VERIFYCONTEXT|CRYPT_MACHINE_KEYSET))
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    /** - Test if CRYPT_VERIFYCONTEXT flag is set. */
    if (dwFlags & CRYPT_VERIFYCONTEXT)
    {
        cName = NULL;
        /*  - In VERIFYCONTEXT mode, container name must be empty. */
        if ((szContainer !=NULL) && szContainer[0])
        {
            SetLastError(NTE_BAD_KEYSET_PARAM);
            return FALSE;
        }
        verifyOnly = TRUE;
    }
    else
    {
        /** - If szContainer contains string address */
        if (szContainer != NULL)
        {
            /**  - Test if the container name is valid */
            nameSize = strlen(szContainer);
            /**  - Test if the name is not too long.*/
            if(nameSize >= MAX_PATH)
            {
                SetLastError(NTE_BAD_KEYSET_PARAM);
                return FALSE;
            }
            /**  - Test if the name is not empty.*/
            if(!szContainer[0])
            {
                szContainer = NULL;
            }
	        // splitting reader name and container name
	        if (szContainer) {
		        if (nameSize >= 4 && memcmp(szContainer, "\\\\.\\", 4) == 0) {
			        szContainer += 4;
			        nameSize = 0;
			        while (szContainer[nameSize] != '\\' && szContainer[nameSize] != '\0')
				        nameSize++;
			        if (nameSize > 0) {
                        strncpy(cReaderName, szContainer, nameSize);
                        cReaderName[nameSize] = '\0';
			        }
			        if (szContainer[nameSize] == '\\' && szContainer[nameSize + 1] != '\0') {
				        cName = szContainer + nameSize + 1;
			        }
		        }
		        else {
			        if (*szContainer != '\0')
				        cName = szContainer;
		        }
	        }
        }

        if (cName)
        {
            // check name validity
            PKCS11_CONTAINER_INFO info;
            if (!extractLabels(cName, &info))
            {
                SetLastError(NTE_BAD_KEYSET);
                return FALSE;
            }
        }
    }
    
    /** - Allocating provider context, initial size of sizeof(PROV_CTX),
     *    growable (limit =0). */
    heapHandle = HeapCreate(0, sizeof(PROV_CTX), 0);
    /** - Fill with zero to be clean.*/
    pProvCtx = (PROV_CTX*) HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, sizeof(PROV_CTX));
    /** - Test if allocation succeed.*/
    if (pProvCtx == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /** - Fill provider context handle pointer by the
    *    pointer to the acquired provider context.*/
    *phProv = (HCRYPTPROV) pProvCtx;
    /** - Grant the context.*/
    grantHandle((HANDLE **) &grantedContexts,
                                    &grantedContextsNb, (HANDLE) *phProv);
    /** - Fill context heap heandler and provider type */
    pProvCtx->heap = heapHandle;
    pProvCtx->dwProvType = pVTable->dwProvType;
    pProvCtx->silent = FALSE;
    pProvCtx->currentAlg = 0;
    pProvCtx->uiHandle = 0;
    pProvCtx->container.cName = NULL;
    pProvCtx->container.cReaderName = NULL;
    pProvCtx->container.dwFlags = 0;
    pProvCtx->container.dwContainerType = INVALID_CONTAINER;
    pProvCtx->container.hServiceInformation = NULL;
    /** - If the function returning the window handle is not NULL,*/
    if(pVTable->FuncReturnhWnd != NULL)
    {
        pVTable->FuncReturnhWnd(&FuncReturnedhWnd);
        if(IsWindow((HWND) FuncReturnedhWnd))
        {
            pProvCtx->uiHandle = (HWND) FuncReturnedhWnd;
        }
        else
        {
            pProvCtx->uiHandle = 0;
        }
    }
    /** - Transmit the cps11 instance handle to service.*/
    setCSPInstance(g_hModule);

    // Open a context on the MS CSP
    if (!CryptAcquireContext(&pProvCtx->hMSProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        CryptAcquireContext(&pProvCtx->hMSProv, NULL, MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    /** - Fill container flags. */
    pProvCtx->container.dwFlags = dwFlags;
    /** - Test if verify is not set.*/
    /** - Fill container type.*/
    if (verifyOnly)
    {
        /* only access public object.*/
        pProvCtx->container.dwContainerType = EPHE_CONTAINER;
    }
    else
    {
        pProvCtx->container.dwContainerType = SC_CONTAINER;
    }

    /** - Test if context have to be silent.*/
    if((pProvCtx->container.dwFlags & CRYPT_SILENT) || verifyOnly)
    {
        /**  - If set, silent context.*/
        pProvCtx->silent = TRUE;
    }
    /** - Store the wanted key container in the provider contexr. */
    /**  - if name set.*/
    if (cName)
    {
        /**   - Allocate space in the container.*/
        pProvCtx->container.cName = (LPSTR) HeapAlloc(pProvCtx->heap,
                                            HEAP_ZERO_MEMORY, strlen(cName)+1);
        /**   - Test if allocation succeed.*/
        if(pProvCtx->container.cName == NULL)
        {
            SetLastError(NTE_NO_MEMORY);
            CPReleaseContext(*phProv,0);
            return FALSE;
        }
        /**   - Copy name in the container.*/
        strcpy(pProvCtx->container.cName, cName);
    }

    if (cReaderName[0] != '\0')
    {
        pProvCtx->container.cReaderName = (LPSTR) HeapAlloc(pProvCtx->heap,
                                            HEAP_ZERO_MEMORY, strlen(cReaderName)+1);
        /**   - Test if allocation succeed.*/
        if(pProvCtx->container.cReaderName == NULL)
        {
            SetLastError(NTE_NO_MEMORY);
            CPReleaseContext(*phProv,0);
            return FALSE;
        }
        /**   - Copy reader name in the container.*/
        strcpy(pProvCtx->container.cReaderName, cReaderName);
    }
    
    if (!UpdateState())
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    if (!verifyOnly)
    {
        /** Find the specified container and fill container internal
         * information.*/
        /** - Open the container.*/
        if (!openContainer(pProvCtx))
        {
            DWORD dwError = GetLastError();
            CPReleaseContext(*phProv,0);
            SetLastError(dwError);
            return FALSE;
        }
    }

    /** - Return TRUE.*/
    return TRUE;

}


/** \brief  Releases the handle to the CSP-eleven, closing access to the card's key container.
 */
BOOL WINAPI
CPReleaseContext(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    HANDLE  heapHandle;             /* Handle to the context heap object. */
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    
    /** - Local good typed provider context pointer.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - Test if flags are set.*/
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    /** - Test if the context has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    UpdateState();

    /** - If there are service information, release context.*/
    if(pProvCtx->container.hServiceInformation != NULL)
    {
        if(!releaseContext(pProvCtx))
        {
            return FALSE;
        }
    }
    
    /** - Revoke the context handle.*/
    heapHandle = pProvCtx->heap;
    if(!revokeHandle((HANDLE **) &grantedContexts, &grantedContextsNb, (HANDLE) hProv))
    {
        return FALSE;
    }
    pProvCtx->heap = NULL;

    if (pProvCtx->container.cName)
    {
        HeapFree(heapHandle, 0, pProvCtx->container.cName);
    }
    if (pProvCtx->container.cOtherContainerName)
    {
        HeapFree(heapHandle, 0, pProvCtx->container.cOtherContainerName);
    }
    if (pProvCtx->container.cReaderName)
    {
        HeapFree(heapHandle, 0, pProvCtx->container.cReaderName);
    }

    CryptReleaseContext(pProvCtx->hMSProv, 0);

    /** - Free context .*/
    HeapFree(heapHandle, 0, pProvCtx);
    /** - Destroy context heap handle.*/
    HeapDestroy(heapHandle);
    return TRUE;
}


/** \brief Generate cryptographic session keys or keys pairs.
 */
BOOL WINAPI
CPGenKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HANDLE hKeyInformation = NULL;  /* Pointer to the adress where key info will be
                                   written.*/
    DWORD keySize = 0; /* Given key size.*/

    /** - Local copy of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Test if the context has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    /** - If request a key pair generation in VERIFY_CONTEXT mode: error.*/
    if((pProvCtx->container.dwFlags & CRYPT_VERIFYCONTEXT))
    {
        SetLastError(NTE_PERM);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    SetLastError(NTE_NOT_SUPPORTED);
    return FALSE;
}


/** \brief Generate nonrandom session keys (DES or 3DES) from input data.
 */
BOOL WINAPI
CPDeriveKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash = NULL;        /* Hash information.*/
    HANDLE hKeyInformation = NULL;  /* Pointer to the adress where key info will be
                                   written.*/
    
    /** - Nullify the returned pointer to the key handler.*/
    *phKey = (HCRYPTKEY)NULL;    
   
    /** - Local copy of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;
    /** - Test if the context has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    SetLastError(NTE_NOT_SUPPORTED);
    return FALSE;
}


/** \brief Release the given key handle.
 */

BOOL WINAPI
CPDestroyKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    KEY_INFO *pKeyInfo; /* Handle to the generated key.*/
   
    /** - Local copy of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - Local copy of the key handler.*/
    pKeyInfo = (KEY_INFO *) hKey;

    /** - Test if tha handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    /** - Test if key handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    UpdateState();
    
    /** - Destroy them.*/
    if(destroyKeys(pProvCtx, pKeyInfo->hKeyInformation))
    {
        /** - Revoke handle.*/
        if(revokeHandle((HANDLE **) &grantedKeys, &grantedKeysNb, (HANDLE) hKey))
        {
            if (pKeyInfo->iv) HeapFree(pProvCtx->heap, 0, pKeyInfo->iv);
            if (pKeyInfo->salt) HeapFree(pProvCtx->heap, 0, pKeyInfo->salt);
            /** - Free key info.*/
            HeapFree(pProvCtx->heap, 0, pKeyInfo);          
            return TRUE;
        }
        else
        {
            SetLastError(NTE_BAD_KEY);
            return FALSE;
        }
    }
    return FALSE;
}


/** \brief Customize operations of a key.
 */
BOOL WINAPI
CPSetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    KEY_INFO *pKeyInfo; /* Handle to the generated key.*/
    DWORD mode;         /* If dwParam is KP_MODE, the pbData pointed DWORD will
                           be copied here.*/
   
    /** - Local copy of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - Local copy of the key handler.*/
    pKeyInfo = (KEY_INFO *) hKey;

    /** - Test if tha handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - Test if key handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** - Test Flags validity.*/
    if (dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    if(pbData == NULL)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    /** - Switch on word parameter.*/
    switch(dwParam)
    {
        case KP_SALT:
        /** - KP_SALT:*/
            /**  - If salt initialized.*/
            if(pKeyInfo->salt != NULL)
            {
                /**   - Free it.*/
                HeapFree(pProvCtx->heap, 0, pKeyInfo->salt);
            }
            /**  - If salt length is more than 0 byte.*/
            if(pKeyInfo->saltLen > 0)
            {
                SetLastError(NTE_BAD_FLAGS);
                return FALSE;
            }
            /**  - Allocate salt.*/
            pKeyInfo->salt = (BYTE*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                            sizeof(BYTE)*pKeyInfo->saltLen);
            if(pKeyInfo->salt == NULL)
            {
                SetLastError(NTE_NO_MEMORY);
                return FALSE;
            }
            /**  - Copy pbData into salt.*/
            memcpy(pKeyInfo->salt, pbData, pKeyInfo->saltLen *
                   sizeof(BYTE));
            break;
        case KP_SALT_EX:
        /**  - KP_SALT_EX: Length of salt in bytes.*/
            /**  - Copy pbData DWORD into salt.*/
            pKeyInfo->saltLen = *((DWORD *) pbData);
            break;
        case KP_PERMISSIONS:
        /**  - KP_PERMISSIONS:*/
            /**  \todo complete set KP_PERMISSIONS */
            if (*((DWORD *)pbData) &
                ~(CRYPT_ENCRYPT|CRYPT_DECRYPT|CRYPT_EXPORT|CRYPT_WRITE|CRYPT_READ|CRYPT_MAC))
            {
                    SetLastError(NTE_BAD_FLAGS);
                    return FALSE;
            }
            else
            /**   - If permissions flags are recognized.*/
            {
                /**    - Copy the pbData pointed dword.*/
                pKeyInfo->permissions = *((DWORD *)pbData);
            }
            break;
        case KP_IV:
            /**  - KP_IV:*/
            /**   - If initialization vectors are managed.*/
            if((pKeyInfo->iv != NULL) && (pKeyInfo->ivLen))
            {
                /**    - Copy ivLen bytes from pbData.*/
                memcpy(pKeyInfo->iv, pbData, pKeyInfo->ivLen*sizeof(BYTE));
            }
            else
            {
                SetLastError(NTE_BAD_KEY);
                return FALSE;
            }
            break;
        case KP_PADDING:
            /**  - KP_PADDING: only support PKCS5_PADDING.*/
            /**   - If pbData is PKCS5_PADDING.*/
            if(*((DWORD *)pbData) == PKCS5_PADDING)
            {
                /**    - Copy dword.*/
                pKeyInfo->padding = *((DWORD *)pbData);
            }
            else
            {
                SetLastError(NTE_BAD_FLAGS);
                return FALSE;
            }
            break;
        case KP_MODE:
            /**  - KP_MODE: Depends on key algId.*/
            /**   - Copy pbData DWORD in mode.*/
            mode = *((DWORD *)pbData);
            /**   - Switch on key algorithm.*/
            switch (pKeyInfo->algId)
            {
                case CALG_DES:
                    /**    - Key is DES.*/
                    /**     - Switch on given mode.*/
                    switch (mode)
                    {
                        case CRYPT_MODE_ECB:
                        /**      - Electronic codebook:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to zero bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=0;
                            pKeyInfo->fLen=64;
                            break;
                        case CRYPT_MODE_CBC:
                        /**      - Cipher block chaining:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to eight bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_OFB:
                        /**      - Output feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    case CRYPT_MODE_CFB:
                        /**      - Cipher feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    default:
                            SetLastError(NTE_FAIL);
                            return FALSE;
                            break;
                    }
                    break;
                case CALG_3DES_112:
                /**  - Key is 3DES 128 bits.*/
                    switch (mode)
                    {
                        case CRYPT_MODE_ECB:
                        /**      - Electronic codebook:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to zero bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=0;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_CBC:
                        /**      - Cipher block chaining:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to eight bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_OFB:
                        /**      - Output feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    case CRYPT_MODE_CFB:
                        /**      - Cipher feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    default:
                            SetLastError(NTE_FAIL);
                            return FALSE;
                            break;
                    }
                    break;
            case CALG_3DES:
                    switch (mode)
                    {
                    case CRYPT_MODE_ECB:
                        /**      - Electronic codebook:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to zero bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=0;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_CBC:
                        /**      - Cipher block chaining:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to eight bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_OFB:
                        /**      - Output feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    case CRYPT_MODE_CFB:
                        /**      - Cipher feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    default:
                            SetLastError(NTE_FAIL);
                            return FALSE;
                            break;
                    }
                    break;
            case CALG_RC2:
            /**  - Key is a RC2 key:*/
                    switch (mode)
                    {
                    case CRYPT_MODE_ECB:
                        /**      - Electronic codebook:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to zero bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=0;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_CBC:
                        /**      - Cipher block chaining:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to sixty four bits, ivLen
                             * to eight bytes and feedback length to sixty four
                             * bits.*/
                            pKeyInfo->blockLen=64;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=64;
                            break;
                    case CRYPT_MODE_OFB:
                        /**      - Output feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    case CRYPT_MODE_CFB:
                        /**      - Cipher feedback mode:*/
                            /**       - Copy mode.*/
                            pKeyInfo->mode=mode;
                            /**       - Set blockLen to eight bits, ivLen
                             * to eight bytes and feedback length to eight
                             * bits.*/
                            pKeyInfo->blockLen=8;
                            pKeyInfo->ivLen=8;
                            pKeyInfo->fLen=8;
                            break;
                    default:
                            SetLastError(NTE_FAIL);
                            return FALSE;
                            break;
                    }
                    break;
            default:
                    SetLastError(NTE_BAD_KEY);
                    return FALSE;
                    break;
            }            
            break;
        case KP_MODE_BITS:
            /**  - KP_MODE_BITS: */
            /**   - Copy pbData DWORD in fLen.*/
            pKeyInfo->fLen = *((DWORD *)pbData);
            break;
        case KP_EFFECTIVE_KEYLEN:
            /**  - KP_KEYLEN: Only applicable on RC2 key.*/
            /**   - If key is a RC2 key,*/
            if(pKeyInfo->algId==CALG_RC2)
            {
                /**    - If pbData dword value < 128.*/
                if(*((DWORD *)pbData) < 128)
                {
                    /**     - Copy pbData dword value.*/
                    pKeyInfo->effectiveLen = *pbData;
                }
                else
                {
                    SetLastError(NTE_BAD_FLAGS);
                    return FALSE;
                }
            }
            else
            {
                SetLastError(NTE_BAD_FLAGS);
                return FALSE;
            }
                
            break;
        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }
    /** - If here, everything is ok.*/
    return TRUE;
}


/** \brief Get data governing the operations of a key.
 */
BOOL WINAPI
CPGetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    KEY_INFO *pKeyInfo; /* Handle to the generated key.*/

    /** - Local copy of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - Local copy of the key handler.*/
    pKeyInfo = (KEY_INFO *) hKey;
   
    /** - Test if tha handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - Test if key handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** - Test Flags validity.*/
    if (dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    if(pbData == NULL)
    /** - If first call, retrieve data length.*/
    /**   \warning This size is given in BYTES.*/
    {
        /** - Switch on word parameter.*/
        switch(dwParam)
        {
            case KP_ALGID:
            /**  - KP_ALGID: size of DWORD in Byte.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_BLOCKLEN:
            /**  - KP_BLOCKLEN: size of DWORD.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_KEYLEN:
            /**  - KP_KEYLEN: size of DWORD.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_SALT:
            /**  - KP_SALT: size of salt bytes array.*/
                *pcbDataLen = pKeyInfo->saltLen;
                break;
            case KP_PERMISSIONS:
            /**  - KP_PERMISSIONS: size of DWORD.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_IV:
            /**  - KP_IV: size of iv bytes array.*/
                *pcbDataLen = pKeyInfo->ivLen;
                break;
            case KP_PADDING:
            /**  - KP_PADDING: size of DWORD.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_MODE:
            /**  - KP_MODE: size of DWORD.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_MODE_BITS:
            /**  - KP_MODE_BITS: size of DWORD.*/
                *pcbDataLen = sizeof(DWORD);
                break;
            case KP_EFFECTIVE_KEYLEN:
            /**  - KP_EFFECTIVE_KEYLEN: size of DWORD.*/
                /**   - If key is a RC2 key,*/
                if(pKeyInfo->algId==CALG_RC2)
                {
                    *pcbDataLen = sizeof(DWORD);
                }
                else
                {
                    SetLastError(NTE_BAD_FLAGS);
                    return FALSE;
                }
                break;
            case KP_CERTIFICATE:
                {
                    return extractKeyCertificate(pProvCtx, pKeyInfo->hKeyInformation, pbData, pcbDataLen);
                }
                break;
            default:
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }
    else
    /** - If second call retrieving data.*/
    {
        /** - Switch on word parameter.*/
        switch(dwParam)
        {
            case KP_ALGID:
                /**  - KP_ALGID: */
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < sizeof(DWORD))
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                /**  - Fill with ALG_ID.*/
                memcpy(pbData, &(pKeyInfo->algId),sizeof(pcbDataLen));
                break;
            case KP_KEYLEN:
            /** \bug Not understanding KP_KEYLEN.*/
            /** \todo Correct KP_KEYLEN.*/
                
            /**  - KP_KEYLEN: */
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < sizeof(DWORD))
                {
                    *pcbDataLen = sizeof(DWORD);
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                /**  - If RSA key, get the key modulus.*/
                if((pKeyInfo->algId == CALG_RSA_KEYX) || (pKeyInfo->algId == CALG_RSA_SIGN))
                {
                    if(!getKeyModulusLength(pProvCtx, pKeyInfo->hKeyInformation, (DWORD *)pbData))
                    {
                        SetLastError(NTE_BAD_KEY);
                        return FALSE;
                    }
                    *pcbDataLen = sizeof(DWORD);
                }
                else
                {
                /**  - Else, return the *DES keylen:*/
                    switch(pKeyInfo->algId)
                    {
                        case CALG_DES:
                            /**   - CALG_DES: 64.*/
                            *pbData = 64;
                            break;
                        case CALG_3DES_112:
                            /**   - CALG_3DES_112: 128.*/
                            *pbData = 128;
                            break;
                        case CALG_3DES:
                            /**   - CALG_3DES: 192.*/
                            *pbData = 192;
                            break;
                        default:
                            /**   - Defaut: bad key.*/
                            SetLastError(NTE_BAD_KEY);
                            return FALSE;
                            break;
                    }
                }

                return TRUE;
                break;
            case KP_BLOCKLEN:
                /** \bug Not understanding KP_BLOCKLEN.*/
                /** \todo Correct KP_BLOCKLEN.*/
                /**  - KP_BLOCKLEN: */
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < (sizeof(DWORD)))
                {
                    *pcbDataLen = sizeof(DWORD);
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                /**  - If RSA key, get the key modulus length.*/
                if((pKeyInfo->algId == CALG_RSA_KEYX) || (pKeyInfo->algId == CALG_RSA_SIGN))
                {
                    if(!getKeyModulusLength(pProvCtx, pKeyInfo->hKeyInformation, (DWORD *)pbData))
                    {
                        SetLastError(NTE_BAD_KEY);
                        return FALSE;
                    }
                    *pcbDataLen = sizeof(DWORD);
                }
                else
                {
                    return FALSE;
                }
                
                return TRUE;
                break;
            case KP_SALT:
                /**  - KP_SALT: */
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < pKeyInfo->saltLen)
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                /**   - Copy salt bytes at pbData.*/
                memcpy(pbData, pKeyInfo->salt,
                       sizeof(BYTE)*pKeyInfo->saltLen);
                break;
            case KP_PERMISSIONS:
                /**  - KP_PERMISSIONS: */
                /**  \todo complete get KP_PERMISSIONS */
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < sizeof(DWORD))
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }

                /*  - Fill with Permissions flags.*/
                memcpy(pbData,&(pKeyInfo->permissions), sizeof(DWORD));
                return TRUE;                
                /*if(!getKeyPermissions(pProvCtx, hKey, (DWORD *)pbData))
                {
                    SetLastError(NTE_BAD_KEY);
                    return FALSE;
                }
                return TRUE;                */
                break;            
            case KP_IV:
            /**  - KP_IV: Initialization vectors bytes array.*/
                /**   - If enough space is allocated,*/
                if(*pcbDataLen < pKeyInfo->ivLen)
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                /**   - Copy iv to pbData.*/
                memcpy(pbData, pKeyInfo->iv,pKeyInfo->ivLen*sizeof(BYTE));
                break;
            case KP_PADDING:
            /**  - KP_PADDING: Used padding method dword.*/
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < sizeof(DWORD))
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }

                /*  - Fill with Permissions flags.*/
                memcpy(pbData, &(pKeyInfo->padding), sizeof(DWORD));
                break;
            case KP_MODE:
            /**  - KP_MODE: DWORD mode.*/
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < (sizeof(DWORD)))
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }

                /*  - Fill with Permissions flags.*/
                *pbData = (BYTE) pKeyInfo->mode;
                break;
            case KP_MODE_BITS:
            /**  - KP_MODE_BITS: DWORD width in bits of feedback.*/
                /**   - Test if data length is length enough.*/
                if(*pcbDataLen < (sizeof(DWORD)))
                {
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }

                /*  - Fill with Permissions flags.*/
                memcpy(pbData,&(pKeyInfo->fLen), sizeof(DWORD));
                break;
            case KP_EFFECTIVE_KEYLEN:
            /**  - KP_EFFECTIVE_KEYLEN: size of DWORD.*/
                /**   - If key is a RC2 key,*/
                if(pKeyInfo->algId==CALG_RC2)
                {
                    /**    - Test if data length is length enough.*/
                    if(*pcbDataLen < (sizeof(DWORD)))
                    {
                        SetLastError(ERROR_MORE_DATA);
                        return FALSE;
                    }

                    /*  - Fill with Permissions flags.*/
                    memcpy(pbData,&(pKeyInfo->padding), sizeof(DWORD));
                }
                else
                {
                    SetLastError(NTE_BAD_FLAGS);
                    return FALSE;
                }
                break;
            case KP_CERTIFICATE:
                {
                    return extractKeyCertificate(pProvCtx, pKeyInfo->hKeyInformation, pbData, pcbDataLen);
                }
                break;
            default:
                SetLastError(NTE_BAD_TYPE);
                return FALSE;
        }
    }
    
    /** - Everything is ok.*/
    return TRUE;
}


/** \brief Customize CSP-eleven.
 */
BOOL WINAPI
CPSetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    DWORD   dataLen = 0; /* Returned data lenth in bytes.*/
    char *localPin = NULL; /* The transmitted cached PIN.*/
    PROV_CTX *pProvCtx = NULL; /* The local casted copy of the provider
                                    context pointer.*/
    
    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;

    /** - Test if c handle has been granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** - Test flag existenz.*/
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    /** \todo Code the busy test !.*/
    switch(dwParam)
    {
        case PP_KEYEXCHANGE_PIN: /** - PP_KEYEXCHANGE_PIN:*/
            /**  - Copy pbData length to dataLen.*/
            dataLen = strlen((char*)pbData);
            /**  - Test if pbData length <= 8.*/
            if(dataLen>64)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }

            if(!validateKeyExchangePin(*pProvCtx, (char*)pbData))
            {
                return FALSE;
            }
            break;
        case PP_SIGNATURE_PIN: /**  - PP_SIGNATURE_PIN:*/
            /**  - Copy pbData length to dataLen.*/
            dataLen = strlen((char*) pbData);
            /**  - Test if pbData length <= 8.*/
            if(dataLen>64)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }

            if(!validateKeySigPin(*pProvCtx, (char*) pbData))
            {
                return FALSE;
            }
            
            break;
        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }
    return TRUE;
}


/** \brief  Retrieve operationals parameters of CSP-eleven.
 */
BOOL WINAPI
CPGetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    DWORD   dataLen = 0; /* Returned data lenth in bytes.*/
    PROV_ENUMALGS *enumAlg = NULL; /* The enumerated Alg.*/
    PROV_ENUMALGS_EX *enumAlgEx = NULL; /* The enumerated Alg.*/
    char *localPin = NULL; /* The transmitted cached PIN.*/
    PROV_CTX *pProvCtx = NULL; /* The local casted copy of the provider
                                    context pointer.*/
    ALGORITHM algorithm;    /* Local algorithm information.*/

    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;

    /** - Test if c handle has been granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** - Test flag colours.*/
    if(dwFlags && (dwFlags & ~(CRYPT_FIRST)))
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;

    }

    switch(dwParam)
    {
        case PP_CONTAINER: /**  - PP_CONTAINER:*/
        case PP_UNIQUE_CONTAINER:
            if (pProvCtx->container.cName)
                return ReturnString(pbData, pcbDataLen, pProvCtx->container.cName);
            else
                return ReturnString(pbData, pcbDataLen, "");
            break;
        case PP_IMPTYPE: /**  - PP_IMPTYPE:*/
            return ReturnValue(pbData, pcbDataLen, CRYPT_IMPL_MIXED);
            break;
        case PP_NAME: /**  - PP_NAME:*/
            return ReturnString(pbData, pcbDataLen, CSP_NAME);
            break;
        case PP_PROVTYPE: /**  - PP_PROVTYPE:*/
            return ReturnValue(pbData, pcbDataLen, PROV_RSA_FULL);
            break;
        case PP_KEYSPEC: /**  - PP_KEYSPEC:*/
            return ReturnValue(pbData, pcbDataLen, AT_SIGNATURE | AT_KEYEXCHANGE);
            break;
        case PP_KEYSET_TYPE:
            return ReturnValue(pbData, pcbDataLen, 0);
            break;
        case PP_VERSION: /**  - PP_VERSION:*/
            return ReturnValue(pbData, pcbDataLen, CSP_VERSION);
            break;
	    case PP_SIG_KEYSIZE_INC:
		    return ReturnValue(pbData, pcbDataLen, 32);
		    break;

	    case PP_KEYX_KEYSIZE_INC:
		    return ReturnValue(pbData, pcbDataLen, 32);
		    break;
        case PP_ENUMALGS: /**  - PP_ENUMALGS:*/
            /**   - If CRYPT_FIRST flagged.*/
            if(dwFlags & CRYPT_FIRST)
            {
                /**    - Set current Alg to 0.*/
                pProvCtx->currentAlg = 0;
            }
            /**   - Else,*/
            else
            {
                /**    - Next Algorithm.*/
                pProvCtx->currentAlg++;
            }
            /**   - If current Alg number >= number of supported algorithm:
                *      end.*/
            if(pProvCtx->currentAlg>=(sizeof(Algs) / sizeof(ALGORITHM)))
            {
                SetLastError(ERROR_NO_MORE_ITEMS);
                return FALSE;
            }
            /**   - Cast pcbData pointer to local enumAlg.*/
            enumAlg = (PROV_ENUMALGS *)pbData;
                
            /**   - Get the algorithm information.*/
            algorithm = Algs[pProvCtx->currentAlg];

            /**   - Fill enumAlg info.*/
            enumAlg->aiAlgid = algorithm.algId;
            enumAlg->dwBitLen = algorithm.dwBits;
            strcpy(enumAlg->szName, algorithm.cName);
            enumAlg->dwNameLen = strlen(algorithm.cName);
            break;
                
        case PP_ENUMALGS_EX: /**  - PP_ENUMALGS:*/
            /**   - If CRYPT_FIRST flagged.*/
            if(dwFlags & CRYPT_FIRST)
            {
                /**    - Set current Alg to 0.*/
                pProvCtx->currentAlg = 0;
            }
            /**   - Else,*/
            else
            {
                /**    - Next Algorithm.*/
                pProvCtx->currentAlg++;
            }
            /**   - If current Alg number >= number of supported algorithm:
                *      end.*/
            if(pProvCtx->currentAlg>=(sizeof(Algs) / sizeof(ALGORITHM)))
            {
                SetLastError(ERROR_NO_MORE_ITEMS);
                return FALSE;
            }
            /**   - Cast pcbData pointer to local enumAlg.*/
            enumAlgEx = (PROV_ENUMALGS_EX *)pbData;
                
            /**   - Get the algorithm information.*/
            algorithm = Algs[pProvCtx->currentAlg];

            /**   - Fill enumAlg info.*/
            enumAlgEx->aiAlgid = algorithm.algId;
            enumAlgEx->dwDefaultLen = algorithm.dwBits;
            enumAlgEx->dwMinLen = algorithm.dwMinBits;
            enumAlgEx->dwMaxLen = algorithm.dwMaxBits;
            strcpy(enumAlgEx->szName, algorithm.cName);
            enumAlgEx->dwNameLen = strlen(algorithm.cName);
            strcpy(enumAlgEx->szLongName, algorithm.cLongName);
            enumAlgEx->dwLongNameLen = strlen(algorithm.cLongName);

            enumAlgEx->dwProtocols = 0;
            if (    (algorithm.algId == CALG_MD5)
                ||  (algorithm.algId == CALG_SHA1)
                ||  (algorithm.algId == CALG_SHA_256)
                )
            {
                enumAlgEx->dwProtocols = CRYPT_FLAG_SIGNING;
            }
            if (    (algorithm.algId == CALG_RSA_KEYX)
                ||  (algorithm.algId == CALG_RSA_SIGN)
                )
            {
                enumAlgEx->dwProtocols = CRYPT_FLAG_SIGNING | CRYPT_FLAG_IPSEC;
            }
            break;
        case PP_ENUMCONTAINERS: /**  - PP_ENUMALGS:*/
            /**   - If CRYPT_FIRST flagged.*/
            if(dwFlags & CRYPT_FIRST)
            {
                pProvCtx->currentContainer = 0;
                if (!pbData)
                {
                    *pcbDataLen = MAX_PATH; // return maximum length
                    return TRUE;
                }
                else if (pProvCtx->container.dwContainerType == SC_CONTAINER)
                {
                    if (pProvCtx->container.cName == NULL)
                    {
                        SetLastError(ERROR_NO_MORE_ITEMS);
                        return FALSE;
                    }
                    if (*pcbDataLen < (strlen(pProvCtx->container.cName) + 1))
                    {
                        *pcbDataLen = MAX_PATH;
                        SetLastError(ERROR_MORE_DATA);
                        return FALSE;
                    }
                    strcpy((char*) pbData, pProvCtx->container.cName);
                    return TRUE;
                }
                else
                {
                    if (!openContainer(pProvCtx) || (pProvCtx->container.cName == NULL))
                    {
                        SetLastError(ERROR_NO_MORE_ITEMS);
                        return FALSE;
                    }
                    if (*pcbDataLen < (strlen(pProvCtx->container.cName) + 1))
                    {
                        *pcbDataLen = MAX_PATH;
                        SetLastError(ERROR_MORE_DATA);
                        return FALSE;
                    }
                    strcpy((char*) pbData, pProvCtx->container.cName);
                    return TRUE;
                }
            }
            else
            {
                pProvCtx->currentContainer++;
                // we only have two containers
                if(pProvCtx->currentContainer>=2)
                {
                    SetLastError(ERROR_NO_MORE_ITEMS);
                    return FALSE;
                }

                if (!pbData)
                {
                    pProvCtx->currentContainer--;
                    *pcbDataLen = MAX_PATH; // return maximum length
                    return TRUE;
                }

                if (pProvCtx->container.cOtherContainerName == NULL)
                {
                    SetLastError(ERROR_NO_MORE_ITEMS);
                    return FALSE;
                }                    

                if (*pcbDataLen < (strlen(pProvCtx->container.cOtherContainerName) + 1))
                {
                    pProvCtx->currentContainer--;
                    *pcbDataLen = MAX_PATH;
                    SetLastError(ERROR_MORE_DATA);
                    return FALSE;
                }
                strcpy((char*) pbData, pProvCtx->container.cOtherContainerName);
                return TRUE;
            }

        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }
                
    return TRUE;
}


/** \brief Set operationals data of a hash object.
 */
BOOL WINAPI
CPSetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash = NULL;        /* Hash information.*/
    DWORD     hashValLen=0;                    /* Hashval lenth.*/
    
    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;

    /** - Test if c handle has been granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - Test if hash handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    /** - Test if flags has been set.*/
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
 
    return CryptSetHashParam(pHash->hMSHash, dwParam, pbData, 0);
}


/** \brief  Retrieve operationals data of a hash object.
 */
BOOL WINAPI
CPGetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash = NULL;        /* Hash information.*/
    unsigned int     i=0;                    /* Iterator.*/
    DWORD   hashLen = 0;            /* Hash lenth in Bytes.*/
    
    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;

    /** - Test if c handle has been granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - Test if hash handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
 
    return CryptGetHashParam(pHash->hMSHash, dwParam, pbData, pcbDataLen, dwFlags);
}


/** \brief Export key(s) to a secure key blob.
 */
BOOL WINAPI
CPExportKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    PUBLICKEYSTRUC *pPubKeyBlob;   /* Returned public key blob.*/
    RSAPUBKEY *pRsaPubKeyBlob;  
    DWORD  blobLen;              /* Length in byte of the blob.*/
    KEY_INFO *pKeyInfo = NULL; /* Pointer to the key information structure.*/
    KEY_INFO *pPubKeyInfo = NULL; /* Pointer to the key information structure.*/
    HANDLE  hPubKeyInformation; /* Service public key information.*/
    DWORD   modulusLen, modulusBitlen;     /* The length of the public key modulus.*/
    DWORD   pubExp;         /* The RSA public exponent.*/
    

    /** - Local copy of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Test if the context has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - Test if the key handle has been granted. */
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    /**  - Copy cast key handle.*/
    pKeyInfo = (KEY_INFO *) hKey;
    if(hPubKey != 0)
    {
        /** - Test if the public key handle has been granted. */
        if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hPubKey))
        {
            SetLastError(NTE_BAD_PUBLIC_KEY);
            return FALSE;
        }
        /**  - Copy cast key handle.*/
        pPubKeyInfo = (KEY_INFO *) hPubKey;
        hPubKeyInformation = pPubKeyInfo->hKeyInformation;
    }
    else
    {
        hPubKeyInformation = NULL;
    }
        
    /** - Switch on required blob type.*/
    switch(dwBlobType)
    {
        case PUBLICKEYBLOB:
            /**  - If PUBLICKEYBLOB, the hPubKey must be 0.*/
            if(hPubKey != 0)
            {
                SetLastError(NTE_BAD_PUBLIC_KEY);
                return FALSE;
            }
            /**   - Get the public modulus length.*/
            if(!getKeyModulusLength(pProvCtx, pKeyInfo->hKeyInformation,
                                    &modulusBitlen))
            {
                SetLastError(NTE_BAD_KEY);
                return FALSE;
            }
            modulusLen = (modulusBitlen+7)/8;
            /**   - Compute the lenth of the BLOB.*/
            blobLen = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + modulusLen;

            /**  - If pbData is NULL, return*/
            if(pbData == NULL)
            {
                *pcbDataLen = blobLen;
                return TRUE;
            }
            else if (*pcbDataLen < blobLen)
            {
                *pcbDataLen = blobLen;
                SetLastError(ERROR_MORE_DATA);
                return FALSE;
            }

            /**  - Get the public key modulus.*/
            if(!extractKeyModulus(pProvCtx, pKeyInfo->hKeyInformation, pbData + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY),
                                 &modulusLen))
            {
                SetLastError(NTE_FAIL);
                return FALSE;
            }
            reverseBytesString(pbData + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY), modulusLen);
            pPubKeyBlob = (PUBLICKEYSTRUC *) pbData;
            /**  - Fill blob header.*/
            pPubKeyBlob->bType=PUBLICKEYBLOB;
            pPubKeyBlob->bVersion=CUR_BLOB_VERSION;
            pPubKeyBlob->reserved=0;
            pPubKeyBlob->aiKeyAlg=pKeyInfo->algId;

            pRsaPubKeyBlob = (RSAPUBKEY*) (pbData + sizeof(PUBLICKEYSTRUC));
            
            /**  - Get the RSA public exponent.*/
            if(!getPublicExponent(pProvCtx, pKeyInfo->hKeyInformation, &pubExp))
            {
                return FALSE;
            }
            /**  - Fill rsa public key structure.*/
            pRsaPubKeyBlob->magic=RSA1; /* RSA1 == public rsa key.*/
            pRsaPubKeyBlob->bitlen=modulusBitlen;
            pRsaPubKeyBlob->pubexp=pubExp;

            return TRUE;
            
        case PRIVATEKEYBLOB:
            SetLastError(NTE_PERM);
            return FALSE;
            break;

        case SIMPLEBLOB:
            if(!extractCryptedKey(pProvCtx, pKeyInfo->hKeyInformation, pbData,
                pcbDataLen, hPubKeyInformation))
            {
                return FALSE;
            }
            break;
        default:
            SetLastError(NTE_BAD_TYPE);
            return FALSE;
    }
    /**  - If the blob is NULL or exchange key not given, just return.*/
    if((pbData == NULL) || (hPubKey == 0))
    {
        /** \todo Export encryption, how to now the size ?!!
         *  Actualy; Add 32 bits to be sure.*/
        (*pcbDataLen) +=32;
        return TRUE;
    }
    /**  - If a exchange key is given, use it to crypt the blob.*/
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
    /*if(!CPEncrypt(hProv, hPubKey, NULL,TRUE, 0, pbData, pcbDataLen, cbBufLen))
    {
        return FALSE;
    }*/    
}


/** \brief  Import a session key or key pair from a key blob into the CSP.
 */
BOOL WINAPI
CPImportKey(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
    CLocker lock(g_lock);
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    PROV_CTX* pProvCtx = (PROV_CTX *) hProv;
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);

    return FALSE;
}


/** \brief  Encrypt data.
 */
BOOL WINAPI
CPEncrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen)
{
    CLocker lock(g_lock);
    *pcbDataLen = 0;
    PROV_CTX* pProvCtx = (PROV_CTX *) hProv;
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/** \brief Decrypt Data.
 */
BOOL WINAPI
CPDecrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
    CLocker lock(g_lock);
    *pcbDataLen = 0;
    PROV_CTX* pProvCtx = (PROV_CTX *) hProv;
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    /** - Test if key handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    if (!fFinal || !pbData || !pcbDataLen)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (dwFlags & (CRYPT_OAEP | CRYPT_DECRYPT_RSA_NO_PADDING_CHECK))
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }

    /**  - Copy cast key handle.*/
    KEY_INFO* pKeyInfo = (KEY_INFO *) hKey;

    if (*pcbDataLen != ((pKeyInfo->blockLen + 7) / 8))
    {
        SetLastError(NTE_BAD_DATA);
        return FALSE;
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/** \brief Instanciate a hash object and initialise hash on a data stream.
 */
BOOL WINAPI
CPCreateHash(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash; /* Local hash pointer copy.*/
    HCRYPTHASH hMSHash = NULL;
    
    /** - Nullify hHash.*/
    *phHash = (HCRYPTHASH)NULL;  
    /** - Local copu of the crypto handler.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - If context handle is granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** -  no flag supported.*/
    if(dwFlags)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    /** \todo complete hash algs.*/
    /** If algid is supported.*/
    if(!((Algid==CALG_SHA) || (Algid == CALG_SHA1) || (Algid == CALG_SHA_256) || (Algid == CALG_MD5) ||
        (Algid == CALG_SSL3_SHAMD5)))
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }

    if (hKey)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!CryptCreateHash(pProvCtx->hMSProv, Algid, NULL, 0, &hMSHash))
    {
        return FALSE;
    }
    
    /** - Allocate memory for hash information.*/
    pHash = (HASH_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                            sizeof(HASH_INFO));
    if (pHash == NULL)
    {
        CryptDestroyHash(hMSHash);
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /** - Initialize hash structure: everything to 0/NULL, Algid set.*/
    setHashAlgId(Algid,pHash);
    pHash->hMSHash = hMSHash;
    
    /** Copy cast pHash to hHash.*/
    *phHash = (HCRYPTHASH) pHash;
    
    /** Return the grant handle function result.*/
    return grantHandle((HANDLE **) &grantedHashes,
                                   &grantedHashesNb, (HANDLE) *phHash);
}


/** \brief  Feed data into a hash object.
 */
BOOL WINAPI
CPHashData(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash = NULL;        /* Hash information.*/
    DWORD   newLength;           /* The new to-hash value lenth in bytes.*/
    int     i=0;                    /* Iterator.*/
    
    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;
    
    newLength = 0;
    /** - If c handle is granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - If h handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
 
    /** - If no flag set.*/
    if(dwFlags)
    {
        /** \todo support CRYPT_USERDATA.*/
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    return CryptHashData(pHash->hMSHash, pbData, cbDataLen, 0);
}


/** \brief  Feed cryptographic key to a hash object.
 */
BOOL WINAPI
CPHashSessionKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash = NULL;        /* Hash information.*/
    BYTE    *keyValue = NULL;     /* Local copy of the key value.*/
    DWORD   keyValueLenth = 0;           /* The lenth of the key value.*/
    
    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;

    /** - If c handle is granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - If h handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
 
    /** - If no flag set.*/
    if(dwFlags)
    {
        /** \todo support CRYPT_USERDATA.*/
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }
    
    /** - Test if key handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
 
    /** - Get the specified key value lenth.*/
    if(!getKeyValue(pProvCtx, hKey, NULL, &keyValueLenth))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    
    /** - Allocate memory for the local copy of the key value.*/
    keyValue = (BYTE *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                            keyValueLenth);
    if(keyValue == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    
    /** - Get the key value.*/
    if(!getKeyValue(pProvCtx, hKey, keyValue, &keyValueLenth))
    {
        HeapFree(pProvCtx->heap, 0, keyValue);
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    
    /** - Feed the key value.*/
    BOOL bStatus = CryptHashData(pHash->hMSHash, keyValue, keyValueLenth, 0);
    
    DWORD dwError = GetLastError();    
    HeapFree(pProvCtx->heap, 0, keyValue);
    SetLastError(dwError);
    return bStatus;
}


/** \brief  Sign difitaly a hash object.
 */
BOOL WINAPI
CPSignHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash = NULL;        /* Hash information.*/
    DWORD   hashLen = 0;            /* Hash lenth in Bytes.*/
    BYTE   *pHashValue = NULL;     /* Hash value.*/
    HCRYPTKEY hKey = -1;          /* Handle to the key to use.*/
    DWORD   hashSizeLen = 4;    /* Size of an hash size data.*/
    KEY_INFO *pKeyInfo = NULL; /* Pointer to the key information structure.*/
    /* Local function convention: hash: the raw hash, digest the asn1 encoded
     * hash.*/
    DWORD   digestLen; /* The digest length.*/
    BYTE *pDigest; /* The digest length.*/
    
    
    /** - Local copy of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;

    /** - Test if c handle has been granted.*/
    if(!grantedHandle(grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }
    
    /** - Test if hash handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
 
    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    /** - Select key.*/
    if((dwKeySpec == AT_SIGNATURE) || (dwKeySpec == AT_KEYEXCHANGE))
    {
        if(!CPGetUserKey(hProv, dwKeySpec, &hKey))
        {
            return FALSE;
        }
    }
    /**  - If hKey is still -1 here, NTE_NO_KEY.*/
    if(hKey == -1)
    {
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }
    
    /**  - Copy cast key handle.*/
    pKeyInfo = (KEY_INFO *) hKey;

    if (!pbSignature && (pKeyInfo->blockLen != (DWORD) -1))
    {
        *pcbSigLen = (pKeyInfo->blockLen + 7) / 8;
        CPDestroyKey(hProv, hKey);
        return TRUE;
    }


    /** - Finish the hash !*/
    /**  - Get the hash lenth.*/
    if(!CPGetHashParam(hProv, hHash, HP_HASHSIZE,(LPBYTE) &hashLen, &hashSizeLen, 0))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    /**  - Allocate memory for the hash.*/
    pHashValue = (BYTE *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                    hashLen*sizeof(BYTE));
    if(pHashValue == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /**  - Get the Hash value.*/
    if(!CPGetHashParam(hProv, hHash, HP_HASHVAL, pHashValue, &hashLen, 0))
    {
        HeapFree(pProvCtx->heap, 0, pHashValue);
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    /** - If flags are present.*/
    if(dwFlags)
    {
        /**  - If no OID has to be prepend, the raw hash is signed.*/
        if(dwFlags != CRYPT_NOHASHOID)
        {
            HeapFree(pProvCtx->heap, 0, pHashValue);
            SetLastError(NTE_BAD_FLAGS);
            return FALSE;
        }
        digestLen = hashLen;
        pDigest = pHashValue;
    }
    else
    {
        /**  - Compute the digest bytes length.*/
        digestLen = hashLen + pHash->oidLen;
        /**  - Allocate memory for the OID and the hash.*/
        pDigest = NULL;
        pDigest = (BYTE*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, digestLen);
        if(pDigest == NULL)
        {
            SetLastError(NTE_NO_MEMORY);
            return FALSE;
        }
        if(pHash->oid == NULL)
        {
            SetLastError(NTE_BAD_HASH);
            return FALSE;
        }
        /**  - Copy the hash OID at the begining of the digest.*/
        memcpy(pDigest, pHash->oid, pHash->oidLen);
        /**  - Copy the hash after it.*/
        memcpy(pDigest + pHash->oidLen, pHashValue, hashLen);

        HeapFree(pProvCtx->heap, 0, pHashValue);
    }

    /** - Compute the signature & sig lenth.*/
    if(!simpleSignData(pProvCtx, pKeyInfo, pDigest,
                           digestLen, pbSignature, pcbSigLen))
    {
        DWORD dwError = GetLastError();
        HeapFree(pProvCtx->heap, 0, pDigest);
        SetLastError(dwError);
        return FALSE;
    }

    HeapFree(pProvCtx->heap, 0, pDigest);

    /** - If the signature has been computed, reverse it.*/
    if(pbSignature != NULL)
    {
        reverseBytesString(pbSignature, *((int *)pcbSigLen));
        if (pKeyInfo->dwKeySpec == AT_SIGNATURE)
        {
            InvalidatePIN(pProvCtx);
        }
    }
        
    CPDestroyKey(hProv, hKey);
    return TRUE;
}


BOOL WINAPI
CPDestroyHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash; /* Local hash pointer copy.*/
    
    /** - Local copu of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;
    
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    
    /** - if given handle is not NULL.*/
    if(pHash == NULL)
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    /** - If hhandle is granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    CryptDestroyHash(pHash->hMSHash);
 
    /** - Revoke handle to the hash object.*/
    if(revokeHandle((HANDLE **) &grantedHashes, &grantedHashesNb, 
                    (HANDLE) hHash))
    {
        /**  - Free hash structure memory.*/
        HeapFree(pProvCtx->heap, 0, pHash);
        return TRUE;
    }
    else
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
}


/** \brief  Verify a digital signature.
 */
BOOL WINAPI
CPVerifySignature(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash; /* Local hash pointer copy.*/

    /** - Local copu of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;
    
    /** - If dwFlags is 0 */
    if(dwFlags != 0)
    {
        SetLastError(NTE_BAD_FLAGS);
        return FALSE;
    }

    /** - If szDescription is NULL.*/
    if(szDescription != NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** - if given hash handle is not NULL.*/
    if(pHash == NULL)
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    /** - If hash handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
        /** - Test if key handle has been granted.*/
    if(!grantedHandle((HANDLE *) grantedKeys, grantedKeysNb, (HANDLE) hPubKey))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);

    return FALSE;
}


/** \brief  Fill a buffer with random bytes.
 */
BOOL WINAPI
CPGenRandom(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */

    /** - Local copy of the context handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - Test if the context has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    { 
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    return CryptGenRandom(pProvCtx->hMSProv, cbLen, pbBuffer);   
}


/** \brief  Retrieves a handle to a permanent key pair.
 */
BOOL WINAPI
CPGetUserKey(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    KEY_INFO *pKeyInfo; /* Handle to the generated key.*/

    /** - Nullify returned key handle.*/
    *phUserKey = 0;
    /** - Local copy of the context handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    
    /** - Test if the context has been granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    if ((pProvCtx->container.hServiceInformation == NULL) || (pProvCtx->container.dwContainerType == EPHE_CONTAINER))
    {
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }

    /** - If requested key is not signature key, not implemented.*/
    if((dwKeySpec != AT_SIGNATURE) && (dwKeySpec != AT_KEYEXCHANGE))
    {
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }

    /** - Allocate memory for key information.*/
    pKeyInfo = (KEY_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                      sizeof(KEY_INFO));
    if(pKeyInfo == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /** - Prefill the key information structure. -1 for algId unknown.*/
    if(!initKey(pProvCtx, pKeyInfo, -1))
    {
        DWORD dwError = GetLastError();
        HeapFree(pProvCtx->heap, 0, pKeyInfo);
        SetLastError(dwError);
        return FALSE;
    }
    
    /** - Set dwKeySpec.*/
    pKeyInfo->dwKeySpec = dwKeySpec;

    /** - Existing (or freshly newly created) key set must be used.*/
    /**  - We load it. Here the algId is correctly filled*/
    if(!loadUserKey(pProvCtx, pKeyInfo))
    {
        DWORD dwError = GetLastError();
        HeapFree(pProvCtx->heap, 0, pKeyInfo);
        SetLastError(dwError);
        return FALSE;
    }

    /**  - Fill key handle.*/
    *phUserKey = (HCRYPTKEY) pKeyInfo;
    /** - Grant key handle.*/
    grantHandle((HANDLE **) &grantedKeys, &grantedKeysNb, (HANDLE) *phUserKey);
    return TRUE;

}


/** \brief  Create an exact copy of a hash and of his states.
 */
BOOL WINAPI
CPDuplicateHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
    CLocker lock(g_lock);
    PROV_CTX *pProvCtx = NULL;      /* Provider context */
    HASH_INFO *pHash; /* Local hash pointer copy.*/
    HASH_INFO *pDestHash; /* Duplicated hash pointer.*/
    HCRYPTHASH hDupHash;

    /** - Local copu of the crypto handle.*/
    pProvCtx = (PROV_CTX *) hProv;
    /** - Local copy of the hash handle.*/
    pHash = (HASH_INFO *) hHash;
    /** - Nullify the returned hash duplicate.*/
    *phHash = (HCRYPTHASH)NULL; 
    
    /** - If pdwReserved is NULL & dwFlags is 0 */
    if((pdwReserved != NULL) || (dwFlags != 0))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }
    
    /** - if given handle is not NULL.*/
    if(pHash == NULL)
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }
    /** - If hhandle is granted.*/
    if(!grantedHandle((HANDLE *) grantedHashes, grantedHashesNb, (HANDLE) hHash))
    {
        SetLastError(NTE_BAD_HASH);
        return FALSE;
    }

    if (!CryptDuplicateHash(pHash->hMSHash, NULL, 0, &hDupHash))
        return FALSE;
    
    /** - Allocate memory for duplicated hash information.*/
    pDestHash = (HASH_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                            sizeof(HASH_INFO));
    if (pDestHash == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /** - Copy the hash state to the duplicated hash.*/
    setHashAlgId(pHash->Algid, pDestHash);
    pDestHash->hMSHash = hDupHash;

    /** Copy cast duplicated Hash to hHash.*/
    *phHash = (HCRYPTHASH) pDestHash;
    
    /** Return the grant handle function result.*/
    return grantHandle((HANDLE **) &grantedHashes,
                                   &grantedHashesNb, (HANDLE) *phHash);
}


/** \brief  Create a exact copy of a key and his states.
 */
BOOL WINAPI
CPDuplicateKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
    CLocker lock(g_lock);
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    PROV_CTX* pProvCtx = (PROV_CTX *) hProv;
    /** - If c handle is granted.*/
    if(!grantedHandle((HANDLE *) grantedContexts, grantedContextsNb, (HANDLE) hProv))
    {
        SetLastError(NTE_BAD_UID);
        return FALSE;
    }

    UpdateState();
    if (!IsValidContext(pProvCtx))
    {
        SetLastError(SCARD_W_REMOVED_CARD);
        return FALSE;
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}



/** \brief Return the wanted handler index in the granted handlers list.*/
int findGrantedHandle(HANDLE *grantedHandles, int max_len, HANDLE wantedHandle)
{
    HANDLE *current;    /* Current handler index in the handlers list.*/
    int index;  /* Position index in the handlers list.*/
    BOOL found; /* If the handle is found.*/
    
    /** - Copy the grantedHandles start pointer to a local copy.*/
    current = grantedHandles;
    index = 0;
    
    /** - If not NULL.*/
    if(current == NULL)
    {
        return -1;
    }
    
    /** - Not found.*/
    found = FALSE;
    /** - Check each entry until we found a empty one or end of list.*/
    while(!found && (index <max_len))
    {
        /**  - If not the same,next.*/
        if(*current != wantedHandle)
        {
            current++;
            index++;
        }
        /**  - Else found.*/
        else
        {
            found = TRUE;
        }
    }
    /** - If found.*/
    if (found)
    {
        /**  - Return the index position.*/
        return index;
    }
    /** - Else.*/
    else
    {
        /**  - Return negative value.*/
        return -1;
    }
}
     

/** \brief Grants a handler.*/
BOOL grantHandle(HANDLE **grantedHandles, int *length, HANDLE handle)
{
    int index, i;  /* Position indexes in the handlers list.*/
    HANDLE *localList; /* Local copy of the list. */
    HANDLE *localTemp; /* Local reciepient copy for the list.*/
    HANDLE *newList; /* Address of the new list.*/

    /** - NULL pointer given, error.*/
    if((grantedHandles == NULL) || (length == NULL))
    {
        SetLastError(E_INVALIDARG);
        return FALSE;
    }
    
    /** - If GetProcessHeap() == NULL, create one.*/
    /*if(GetProcessHeap() == NULL)
    {
        **  - Allocating provider context, growable. *
        GetProcessHeap() = HeapCreate(0, sizeof(HANDLE), 0);
    }*/
    /** - If given list lenth < 0, set to 0.*/
    if(*length<0)
    {
        *length = 0;
    }
    /*- If length == 0, this is a new list.
    if(!*length)
    {
        printf("+New List\n");
        *  - Set grantedHandles pointed address to NULL to be secure.*
        *grantedHandles = NULL;
    }
    else
    {
        printf("+(0x%x, %d)\n", *grantedHandles, *length);
    }*/
    /** - Copy the granted handlers list to the local copy.*/
    localList = *grantedHandles;
    
    /** - Allocate space for the new handle.*/

    localTemp = (HANDLE*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                 sizeof(HANDLE) * ((*length)+1));
    /** - Remember the new list address before changing it.*/
    newList = localTemp;
    /**  - If cannot allocate, error. */
    if(localTemp == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        *grantedHandles = localList;
        return FALSE;
    }
    
    /**  - Copy old list to new list.*/
    for(i=0; i<*length; i++)
    {
        *localTemp = *localList;
        localTemp++;
        localList++;
    }
    /**  - Index is set to the last position.*/
    index = *length;
        
    /** - If the context index is valid.*/
    if (index>=0 && index<(*length)+1)
    {
        /**  - Fill the new list with the provided context.*/
        newList[index] = handle;
        /**  - Free old list if not NULL.*/
        if(*grantedHandles != NULL)
        {   
            HeapFree(GetProcessHeap(), 0, *grantedHandles);
        }
        /**  - Copy new list address to the grantedHandles pointer.*/
        *grantedHandles = newList;
        /**  - Now the list is 1 more lenth.*/
        *length=(*length) + 1;
         /**  - Return TRUE.*/
        return TRUE;
    }
    else
    {
        /** - Else, return FALSE.*/
        return FALSE;
    }
}
            

/** \brief Revokes a granted cryptographic handler.*/
BOOL revokeHandle(HANDLE **grantedHandles, int *length, HANDLE handle)
{
    int index, i;  /* Position indexes in the handlers list.*/
    HANDLE *localList; /* Local copy of the list. */
    HANDLE *localTemp; /* Local reciepient copy for the list.*/
    HANDLE *newList; /* Local copy of the new list.*/
    
    /** - NULL pointer given, error.*/
    if((grantedHandles == NULL) || (length == NULL))
    {
        SetLastError(E_INVALIDARG);
        return FALSE;
    }
    
    /** - Find the revoked handler position index. */
    index = findGrantedHandle(*grantedHandles, *length, handle);
    
    /** - If length is 0, no possible granted handles.*/
    if (*length <= 0)
    {
        SetLastError(E_INVALIDARG);
        return FALSE;
    }
    /** - If index < 0, no such granted handle.*/
    if (index < 0)
    {
        SetLastError(E_INVALIDARG);
        return FALSE;
    }
    /** - If there is more than one, after remove, it will some left.*/
    if(*length > 1)
    {
        /** - Local granted handlers pointer copy.*/
        localList = *grantedHandles;
        /** - Allocate for length handlers if there are still some.*/
        localTemp = (HANDLE*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                 sizeof(HANDLE) * (*length)-1);
        /** - Remember new list address before using it.*/
        newList = localTemp;
        /** - If cannot allocate, error. */
        if(localTemp == NULL)
        {
            SetLastError(NTE_NO_MEMORY);
            *grantedHandles = localList;
            return FALSE;
        }
        /** - Walk list and new list for copy left handles.*/
        for(i=0; i<*length; i++)
        {
            /**  - If i different from revoked handler index, copy.*/
            if(i != index)
            {
                *localTemp = *localList;
                localTemp++;
            }
            localList++;
        }
    }
    /** - Else, there will no more left after revoking.*/
    else
    {
        newList = NULL;
    }
    

    /** - Now the list is 1 less length.*/
    *length=*length - 1;
    /** - Free memory used by the old list.*/
    HeapFree(GetProcessHeap(), 0, *grantedHandles);
    /** - Set the granted handlers pointer to the new list address.*/
    *grantedHandles = newList;
    return TRUE;
}

BOOL grantedHandle(HANDLE *grantedHandles, int length, HANDLE handle)
{
    /** - If the wanted handle has a position index >=0, it has been granted.*/
    if(findGrantedHandle(grantedHandles, length, handle)>=0)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

int getHashSize(ALG_ID Algid)
{
    switch(Algid)
    {
        case CALG_MD2:
            /** - MD2: size 16.*/
            return 16;
        case CALG_MD5:
            /** - MD5: size 16.*/
            return 16;
        case CALG_SHA:
            /** - SHA: size 20.*/
            return 20;
        case CALG_SHA_256:
            /** - SHA256: size 32.*/
            return 32;
        case CALG_SSL3_SHAMD5:
            /** - SHAMD5: SHA + MD5.*/
            return 20+16;
        default:
            /** - Everything else: -1.*/
            return -1;
    }
}

BOOL getAlgorithm(ALG_ID algId, ALGORITHM *algorithm)
{
    int tableLenth = 0; /* The translation table lenth, computed here.*/
    int i = 0; /* Iterator.*/
    
    tableLenth = sizeof(Algs) / sizeof(ALGORITHM);

    for(i=0; i<tableLenth; i++)
    {
        if(algId == Algs[i].algId)
        {
            *algorithm = Algs[i];
            return TRUE;
        }
    }    
    return FALSE;
}
    
BOOL getOIDFromAlgId(ALG_ID algId, BYTE **ppOid, DWORD *pOidLen)
{
    ALGORITHM algorithm;

    if(!getAlgorithm(algId, &algorithm))
    {
        return FALSE;
    }

    *ppOid = algorithm.oid;
    *pOidLen = algorithm.oidLen;
    
    return TRUE;
}

BOOL initKey(PROV_CTX *pProvCtx, KEY_INFO *pKey, ALG_ID algId)
{
    if(!setKeyAlgId(algId, pKey))
    {
        SetLastError(NTE_BAD_ALGID);
    }
    /** - Set the key spec to AT_SIGNATURE.*/
    pKey->dwKeySpec = AT_SIGNATURE;
    /** - blockLen set to unset.*/
    pKey->blockLen = -1 ;
    /** - The total key length unset.*/
    pKey->length = -1; 
    /** - salt length: 1 byte.*/
    pKey->saltLen = 1;
    /** - salt defaut: 0.*/
    /**  - Allocate memory for salt.*/
    pKey->salt = (BYTE*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, sizeof(BYTE));
    if(pKey->salt == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /**  - Set salt to 0.*/
    *(pKey->salt) = 0;
    /**  - Permissions default to 0xFFFFFFFF.*/
    pKey->permissions = 0xFFFFFFFF;
    /** - Initialization  vectors length set to eight.*/
    pKey->ivLen = 8;
    /** - Initialization vectors set to 0.*/
    /**  - Allocate memory for iv.*/
    pKey->iv = (BYTE*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                         sizeof(BYTE)*pKey->ivLen);
    if(pKey->iv == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /**  - Initialization vectors set to sixty four 0s.*/
    memset(pKey->iv,0,pKey->ivLen*sizeof(BYTE));
    /**  - Padding method set ot PKCS5_PADDING.*/
    pKey->padding = PKCS5_PADDING;
    /**  - Mode set to CRYPT_MODE_CBC.*/
    pKey->mode = CRYPT_MODE_CBC; 
    /**  - Mode feedback length set to 8 bits.*/
    pKey->fLen = 8;
    /**  - Effective length unset.*/
    pKey->effectiveLen = -1;
    /**  - dwContainerType specific information to NULL.*/
    pKey->hKeyInformation = NULL;
    return TRUE;
}

void reverseBytesString(BYTE *pBytes, DWORD stringLen)
{
    BYTE byteBuffer;      /* A byte used to buffer during byte reversing.*/
    DWORD middle;       /* The length in byte of a middle of signature.*/
    DWORD i;              /* iterator.*/

    middle = stringLen/2;
    /**  - Reversing means that the first will become the last, until the
     * middle-1 became the middle+1. So no need to walk after the middle of
     * the bits string.*/
    for(i=0;i<middle; i++)
    {
        byteBuffer = pBytes[i];
        /**  - The byte to put at the 'i' position is at the position obtain by
         * a symetric computation, with the middle as axis. In others words, the
         * (i+1)th before the last byte, so, i byte(s) before the last one, so
         * i-1 byte index.*/
        pBytes[i] = pBytes[stringLen-i-1];
        pBytes[stringLen-i-1] = byteBuffer;
    }
}

BOOL setHashAlgId(ALG_ID algId, HASH_INFO *pHash)
{
    /** - Set the key algId to the given one.*/
    pHash->Algid = algId;
    /**  - Get the alg OID.*/
    if(!getOIDFromAlgId(algId, &(pHash->oid), &(pHash->oidLen)))
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }
    return TRUE;
}

BOOL setKeyAlgId(ALG_ID algId, KEY_INFO *pKey)
{
    /** - Set the key algId to the given one.*/
    pKey->algId = algId;

    return TRUE;
}

