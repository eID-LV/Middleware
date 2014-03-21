/** \file pkcs11-services.c
 *
 * Corrected and modified by Mounir IDRASSI
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
#include <winscard.h>
#include <stdio.h>
#include <conio.h>
#include <vector>

#include <tchar.h>
#include "missdef.h"

#include "pkcs11.h"
#include "csp11.h"
#include "pkcs11-services.h"
#include "pkcs11-helpers.h"
#include "ui-pin.h"
#include "csp-debug.h"

extern HINSTANCE g_hModule;
static HINSTANCE module = NULL; /**< The PKCS11 used module. */
extern CK_FUNCTION_LIST_PTR p11; /**< The PKCS #11 API functions pointers. */

#define TOKEN_LABEL_SIGNATURE   "LATVIA ID (Signature PIN)"
#define TOKEN_LABEL_USER        "LATVIA ID (User PIN)"

PIN_CACHE g_pinCache[128] = {0}; // support up to 64 slots


void AddPinToCache(CK_SLOT_ID slotID, const char* pin)
{
    int i;
    for (i = 0; i < 128; i++)
    {
        if (g_pinCache[i].slotID == slotID)
            break;
    }

    if (i == 128)
    {
        for (i = 0; i < 128; i++)
        {
            if (g_pinCache[i].slotID == 0)
                break;
        }
    }

    if (i < 128)
    {
        g_pinCache[i].slotID = slotID;
        strcpy(g_pinCache[i].ExchPin, pin);
    }
}

BOOL GetPinFromCache(CK_SLOT_ID slotID, char* pin)
{
    int i;
    for (i = 0; i < 128; i++)
    {
        if (g_pinCache[i].slotID == slotID)
        {
            strcpy(pin, g_pinCache[i].ExchPin);
            return TRUE;
        }
    }
    return FALSE;
}

void ClearPinFromCache(CK_SLOT_ID slotID)
{
    int i;
    for (i = 0; i < 128; i++)
    {
        if (g_pinCache[i].slotID == slotID)
        {
            memset(g_pinCache[i].ExchPin, 0, sizeof(g_pinCache[i].ExchPin));
            break;
        }
    }
}


/** \fn CK_BBOOL * getDECRYPT(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Handle to the object.
 *  \param pulCount Number of returned CK boolean.
 *  \return True if the object can decrypt.
 */
PATTRIBUTE_FUNCTION_MACRO(DECRYPT, CK_BBOOL);

/** \fn CK_BBOOL * getENCRYPT(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Handle to the object.
 *  \param pulCount Number of returned CK boolean.
 *  \return True if the object can decrypt.
 */
PATTRIBUTE_FUNCTION_MACRO(ENCRYPT, CK_BBOOL);

/** \fn CK_BBOOL * getEXTRACTABLE(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Handle to the object.
 *  \param pulCount Number of returned CK boolean.
 *  \return True if the object is extractable.
 */
PATTRIBUTE_FUNCTION_MACRO(EXTRACTABLE, CK_BBOOL);

/** \fn unsigned char * getID(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object identified by the returned ID.
 *  \param pulCount Number of returned unsigned bytes.
 *  \return The Object ID.
 */
PATTRIBUTE_FUNCTION_MACRO(ID, unsigned char);

/** \fn CK_KEY_TYPE * getKEY_TYPE(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx,CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)
 *  \brief Get the Key type of the specified object.
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Key object of the returned key type.
 *  \param pulCount Number of returned CK_KEY_TYPE.
 *  \return The Object ID.
 */
PATTRIBUTE_FUNCTION_MACRO(KEY_TYPE, CK_KEY_TYPE);

/** \fn CK_UTF8CHAR * getLABEL(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)  
 *  \brief Get the Label of the specified object.
 *  
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object identified by the returned ID.
 *  \param pulCount Number of returned unsigned chars.
 *  \return the object label.
 */
PATTRIBUTE_FUNCTION_MACRO(LABEL, CK_UTF8CHAR);

/** \fn unsigned char * getMODULUS(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object of the returned Modulus.
 *  \param pulCount Number of returned unsigned char.
 *  \return The Object modulus.
 */
PATTRIBUTE_FUNCTION_MACRO(MODULUS, unsigned char);

/** \fn CK_ULONG * getMODULUS_BITS(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object of the returned Modulus lenth in bit.
 *  \param pulCount Number of returned unsigned char.
 *  \return The Object modulus length.
 */
PATTRIBUTE_FUNCTION_MACRO(MODULUS_BITS, CK_ULONG);

/** \fn CK_BYTE * getPUBLIC_EXPONENT(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)  
 *  \brief Get the public exponent of the specified object.
 *  
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object.
 *  \param pulCount Number of returned CK_BYTE. (3)
 *  \return the object public exponent.
 */
PATTRIBUTE_FUNCTION_MACRO(PUBLIC_EXPONENT, CK_BYTE);

/** \fn CK_BBOOL * getSIGN(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)  
 *  \brief Get the Label of the specified object.
 *  
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object.
 *  \param pulCount Number of returned CK_BBOOL.
 *  \return the object label.
 */
PATTRIBUTE_FUNCTION_MACRO(SIGN, CK_BBOOL);

/** \fn CK_BYTE *getVALUE(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) 
 * \brief Get the ID of the specified object. 
 *  \param p11  Pointer to the PKCS #11 functions.
 *  \param pProvCtx Pointer to the provider context.
 *  \param obj Object where the value will be extracted.
 *  \param pulCount Number of returned CK_BYTE.
 *  \return The Object value.
 */
PATTRIBUTE_FUNCTION_MACRO(VALUE, unsigned char);


bool IsCharHex(char c)
{
	return isxdigit(c) != 0;
}

bool IsHexString(LPCSTR szStr,size_t len)
{
	for(size_t i=0;i<len;i++)
		if(!IsCharHex(szStr[i]))
			return false;
	return true;
}

BYTE ConvertHexChar(char c)
{
	if(c >= _T('0') && c <= _T('9'))
		return c - _T('0');
	if(c >= _T('a') && c <= _T('f'))
		return 10 + c - _T('a');
	else
		return 10 + c - _T('A');
}

void ConvertHexString(LPCSTR szStr,size_t len,BYTE *pData)
{
	LPSTR ptr = (LPSTR) szStr;
	for(size_t i=0;i<len/2;i++)
	{
		pData[i] = (ConvertHexChar(ptr[0]) << 4) | ConvertHexChar(ptr[1]);
		ptr += 2;
	}
}

void ConvertToHex(BYTE* pbData, size_t len, LPSTR szHexStr)
{
    static char* g_hex = "0123456789ABCDEF";
    for (size_t i=0; i < len; i++)
    {
        BYTE b = *pbData++;
        *szHexStr++ = g_hex[(b >> 4) & 0x0F];
        *szHexStr++ = g_hex[(b     ) & 0x0F];
    }
    *szHexStr = 0;
}

BOOL keyObjectCanEncrypt(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    CK_ULONG encryptAttrsNumber; /* Number of founded key types.*/
    CK_BBOOL *p11Bool; /* PKCS#11 true boolean value.*/
    
    /** - Get the Key Type.*/
    p11Bool = getENCRYPT(p11, pProvCtx, (CK_OBJECT_HANDLE) hKey,  &encryptAttrsNumber);
    if(!(encryptAttrsNumber == 1))
    {
        /** \todo Find appropriate error code. */
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }
    return *p11Bool;
}

BOOL keyObjectCanDecrypt(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    CK_ULONG decryptAttrsNumber; /* Number of founded key types.*/
    CK_BBOOL *p11Bool; /* PKCS#11 true boolean value.*/
    
    /** - Get the Key Type.*/
    p11Bool = getDECRYPT(p11, pProvCtx, (CK_OBJECT_HANDLE) hKey,  &decryptAttrsNumber);
    if(!(decryptAttrsNumber == 1))
    {
        /** \todo Find appropriate error code. */
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }
    return *p11Bool;
}

BOOL keyObjectIsExportable(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    CK_ULONG extractableAttrsNumber; /* Number of founded key types.*/
    CK_BBOOL *p11Bool; /* PKCS#11 true boolean value.*/
    
    /** - Get the Key Type.*/
    p11Bool = getEXTRACTABLE(p11, pProvCtx, (CK_OBJECT_HANDLE) hKey,  &extractableAttrsNumber);
    if(!(extractableAttrsNumber == 1))
    {
        /** \todo Find appropriate error code. */
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }
    return *p11Bool;
}

BOOL keyObjectParametersCanBeRead(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    /** \warning No sense in PKCS#11, permissions are per attributes and not
     * global !!! Attributes can be read, others not...*/
    /** \todo find a way to handle canBeRead properly.*/
    /** \bug Return always 1.*/
    return 1;
}

BOOL keyObjectParametersCanBeSet(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    /** \warning No sense in PKCS#11, permissions are per attributes and not
     * global !!! Attributes can be set, others not...*/
    /** \todo find a way to handle canBeSet properly.*/
    /** \bug Return always 1.*/
    return 1;
}

BOOL keyObjectCanBeUsedWithMAC(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    /** \todo Code it properly, I (Romain) do not know how to do it.*/
    /** \bug return always 0.*/
    return 0;
}


BOOL keyObjectCanSign(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey)
{
    CK_ULONG signAttrsNumber; /* Number of founded key types.*/
    CK_BBOOL *p11Bool; /* PKCS#11 true boolean value.*/
    
    /** - Get the Key Type.*/
    p11Bool = getSIGN(p11, pProvCtx, (CK_OBJECT_HANDLE) hKey,  &signAttrsNumber);
    if(!(signAttrsNumber == 1))
    {
        /** \todo Find appropriate error code. */
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }
    return *p11Bool;
}


BOOL openContainer(PROV_CTX *pProvCtx)
{
    CK_SLOT_ID	slotId = NO_SLOT;     /* The currently used slot. Default: no slot used. */
    
    /** - Initialize the cryptoki library. */
    if (!PKCS11_initialize())
    {
        return FALSE;
    }

    if (pProvCtx->container.hServiceInformation)
    {
        /* this is a verify context */
        if (IsValidContext(pProvCtx))
            return TRUE;
        else
        {
            PKCS11_closeSession(pProvCtx);
            pProvCtx->container.hServiceInformation = NULL;
            if (pProvCtx->container.cName)
            {
                HeapFree(pProvCtx->heap, 0, pProvCtx->container.cName);
                pProvCtx->container.cName = NULL;
            }
            if (pProvCtx->container.cOtherContainerName)
            {
                HeapFree(pProvCtx->heap, 0, pProvCtx->container.cOtherContainerName);
                pProvCtx->container.cOtherContainerName = NULL;
            }
            if (pProvCtx->container.cReaderName)
            {
                HeapFree(pProvCtx->heap, 0, pProvCtx->container.cReaderName);
                pProvCtx->container.cReaderName = NULL;
            }
        }
    }
    /** - Find a slot with the specified container. */
    while(slotId == NO_SLOT)
    {
        if(!PKCS11_findSlot(*pProvCtx, &slotId))
        {
            if (pProvCtx->silent)
            {
                SetLastError(NTE_BAD_KEYSET);
                return FALSE;
            }
            else
            {
                if(!unreadableCard(&(pProvCtx->uiHandle)))
                {
                    SetLastError(SCARD_W_CANCELLED_BY_USER);
                    return FALSE;
                }
            }
        }
    }
    
    /** - Add this container to the context. */
    return PKCS11_addContainer(pProvCtx, slotId);
}

BOOL destroyKeys(PROV_CTX *pProvCtx, HANDLE hKeyInformation)
{
    /** - Free keys information.*/
    if(!HeapFree(pProvCtx->heap, 0, hKeyInformation))
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    return TRUE;
}

BOOL fillP11Key(PROV_CTX *pProvCtx,
                   CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE certificate, PKCS11_KEY_INFO *pKeyInfo)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    
    /** - Local copy of key information pointer.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    /** - Fill structure info.*/
    //pSigKey->signPrivateKey = privateKey;
    pKeyInfo->hKey = publicKey;
    pKeyInfo->hCert = certificate;
    
    return TRUE;
}

BOOL getPublicExponent(PROV_CTX *pProvCtx, HANDLE hKeyInformation, 
                       DWORD *pPubExp)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    CK_BYTE *pPublicExponent=NULL;
    CK_ULONG bytesNumber=0;
    CK_OBJECT_HANDLE hKey; /* Specified key object handle.*/
    PKCS11_KEY_INFO  keyInformation; /* PKCS11 key information.*/
    

    /** - Retrieve service information and slot ID.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    /** - Retrieve key information.*/
    keyInformation = *((PKCS11_KEY_INFO *) hKeyInformation);
    hKey = keyInformation.hKey;
    /** - Get the public exponent attribute.*/
    pPublicExponent = getPUBLIC_EXPONENT(p11, pProvCtx, hKey,  &bytesNumber);
    if(bytesNumber != 3)
    {
        SetLastError(NTE_BAD_KEY);
        return FALSE;
    }
    memset(pPubExp,0, sizeof(DWORD));
    memcpy(pPubExp, pPublicExponent, 3);
    //*pPubExp = (*pPubExp)>>8;
    HeapFree(pProvCtx->heap, 0, pPublicExponent);
    return TRUE;
}

BOOL extractKeyModulus(PROV_CTX *pProvCtx, HANDLE hKeyInformation,
                      LPBYTE pBlob, LPDWORD pBlobLen)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    unsigned char *keyValue=NULL;
    CK_BYTE *modulus=NULL;
    CK_ULONG bytesNumber=0;
    CK_OBJECT_HANDLE hKey; /* Specified key object handle.*/
    PKCS11_KEY_INFO  keyInformation; /* PKCS11 key information.*/
    DWORD i = 0;
    
    CK_ULONG modulusBits; /* Where the length of the key modulus will be
                              locally copied.*/
    CK_ULONG *pModulusBits; /* Address of the getted modulus bits length.*/
    CK_ULONG bitsNumber;

    /** - Retrieve service information and slot ID.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    /** - Retrieve key information.*/
    keyInformation = *((PKCS11_KEY_INFO *) hKeyInformation);
    hKey = keyInformation.hKey;
    /** - Get the key modulus lenth.*/
    pModulusBits = getMODULUS_BITS(p11, pProvCtx, hKey,  &bitsNumber);
    /** - Local copy it.*/
    modulusBits = *pModulusBits;
    /** - Free the allocated one.*/
    HeapFree(pProvCtx->heap, 0, pModulusBits);
    if(bitsNumber > 1)
    {
        /** \todo Find appropriate error code. */
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }
    if(pBlob == NULL)
    {
        *pBlobLen = (modulusBits+7)/8;
        return TRUE;
    }
    else
    {
        if(*pBlobLen < ((modulusBits+7)/8))
        {
            *pBlobLen = (modulusBits+7)/8;
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }
    }
    /**  - Get the key modulus (key value).*/
    modulus = getMODULUS(p11, pProvCtx, hKey, &bytesNumber);
    /* The value is the value of the object, with asn.1 bytes etc.
    keyValue = getVALUE(p11, pProvCtx, hKey, &bytesNumber);*/
    keyValue = (unsigned char *) modulus;
    if(keyValue != NULL)
    {
        /**  - Copy the modulus on modulusBits bits length.*/
        memcpy(pBlob, modulus, bytesNumber);
        *pBlobLen = bytesNumber;
        /**  - Free the getted modulus.*/
        HeapFree(pProvCtx->heap, 0, modulus);
    }
    else
    {

    }

    return TRUE;
}

BOOL extractKeyCertificate(PROV_CTX *pProvCtx, HANDLE hKeyInformation,
                      LPBYTE pBlob, LPDWORD pBlobLen)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    CK_OBJECT_HANDLE hCert; /* Specified key object handle.*/
    PKCS11_KEY_INFO  keyInformation; /* PKCS11 key information.*/

    /** - Retrieve service information and slot ID.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    /** - Retrieve key information.*/
    keyInformation = *((PKCS11_KEY_INFO *) hKeyInformation);
    hCert = keyInformation.hCert;

    if (hCert == CK_INVALID_HANDLE)
    {
        SetLastError(NTE_BAD_DATA);
        return FALSE;
    }

    CK_ATTRIBUTE valueAttr[] = {
        {CKA_VALUE, NULL, 0}
    };

    CK_RV rv = p11->C_GetAttributeValue(hServiceInfo->hSession, hCert, valueAttr, 1);
    if ((rv == CKR_OK) && (valueAttr[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) && (valueAttr[0].ulValueLen != 0))
    {
        if (!pBlob)
        {
            *pBlobLen = valueAttr[0].ulValueLen;
            return TRUE;
        }
        else if (*pBlobLen < valueAttr[0].ulValueLen)
        {
            *pBlobLen = valueAttr[0].ulValueLen;
            SetLastError(ERROR_MORE_DATA);
            return FALSE;
        }

        valueAttr[0].pValue = pBlob;
        rv = p11->C_GetAttributeValue(hServiceInfo->hSession, hCert, valueAttr, 1);
        if ((rv == CKR_OK) && (valueAttr[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) && (valueAttr[0].ulValueLen != 0))
        {
            *pBlobLen = valueAttr[0].ulValueLen;
            return TRUE;
        }
        else
        {
            SetLastError(NTE_FAIL);
            return FALSE;
        }
    }
    else
    {
        SetLastError(NTE_BAD_DATA);
        return FALSE;
    }
}

BOOL extractCryptedKey(PROV_CTX *pProvctx, HANDLE hKeyInformation,
                      LPBYTE pBlob, LPDWORD pBlobLen,
                      HANDLE hPubKeyInformation)
{
    return FALSE;
}


BOOL genKeyPair(PROV_CTX *pProvCtx, CK_ULONG modulusBits, 
                   HANDLE *phKeyInformation, ALG_ID algId)
{
    CK_OBJECT_HANDLE *phPublicKey = NULL; /* Pointer to PKCS #11 Handle to the public key object.*/
    CK_OBJECT_HANDLE *phPrivateKey = NULL; /* Pointer to PKCS #11 Handle to the private key object.
                                      */
    PKCS11_KEY_INFO  *pKeyInformation=NULL; /* PKCS11 key information.*/
    
    /** - Test if algId is correct.*/
    if((algId != AT_SIGNATURE) && (algId != AT_KEYEXCHANGE))
    {
        return FALSE;
    }
    
    /** - Test if user can read and write on the card. */
    if(!PKCS11_rwUserFnSession(pProvCtx, algId))
    {
        return FALSE;
    }
    /** - Call service specific key pair generation function.*/
    if(PKCS11_genKeyPair(pProvCtx, modulusBits, &phPrivateKey, &phPublicKey))
    {
        /**  - Allocate memory for pkcs11 key information structure.*/
        pKeyInformation = (PKCS11_KEY_INFO*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                    sizeof(PKCS11_KEY_INFO));
        if(pKeyInformation == NULL)
        {
            SetLastError(NTE_NO_MEMORY);
            return FALSE;
        }
        /**  - Fill key structure.*/
        if(!fillP11Key(pProvCtx, *phPublicKey, 0, pKeyInformation))
        {
            SetLastError(NTE_FAIL);
            return FALSE;
        }
        *phKeyInformation = (HANDLE) pKeyInformation;
        return TRUE;
    }
    /** - If fail, NTE_FAIL.*/
    SetLastError(NTE_FAIL);
    return FALSE;
}

BOOL PKCS11_getSignatureLen(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey, 
                            DWORD *pSignatureLen)
{
    BYTE buffer[1];
    int bufferLen = 1;
    BYTE *pSignature;
    CK_RV rv; /* PKCS #11 API return value. */
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    CK_MECHANISM    mechanism = {
        CKM_RSA_PKCS, NULL, 0 };  /* Mechanism used in order to simple sign.*/


    /** - Locally copy the pointer to the key information structure.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    /**  - Initialise signature.*/
    rv = p11->C_SignInit(hServiceInfo->hSession, &mechanism, hKey);
    if (rv != CKR_OK)
    {
        return FALSE;
    }

    /**  - Get the signature.*/
    rv = p11->C_Sign(hServiceInfo->hSession, buffer, bufferLen, NULL,
                     pSignatureLen);
    if (rv != CKR_OK)
    {
        return FALSE;
    }
    
    pSignature = NULL;
    pSignature = (BYTE*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, *pSignatureLen);
    if(pSignatureLen == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    /**  - Get the signature.*/
    rv = p11->C_Sign(hServiceInfo->hSession, buffer, bufferLen, pSignature,
                     pSignatureLen);
    if (rv != CKR_OK)
    {
        HeapFree(pProvCtx->heap, 0, pSignature);
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    
    HeapFree(pProvCtx->heap, 0, pSignature);

    return TRUE;
}

BOOL getKeyAlgId(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey, ALG_ID *algId, 
                 DWORD dwKeySpec)
{
    CK_KEY_TYPE *keyType; /* Pointer to the requested key PKCS#11 type.*/
    CK_ULONG keyTypesNumber = 0; /* Number of founded key types.*/

    /** - Get the Key Type.*/
    keyType = getKEY_TYPE(p11, pProvCtx, (CK_OBJECT_HANDLE) hKey,  &keyTypesNumber);
    if(keyTypesNumber != 1)
    {
        if (keyType) HeapFree(pProvCtx->heap, 0, keyType);
        /** \todo Find appropriate error code. */
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }
    /** - If RSA key, get the signature boolean attribute to RSA_SIGN or
     *    RSA_KEYX.*/
    if(*keyType == CKK_RSA)
    {
        /**  - If key spec is AT_SIGNATURE, algId ic CALG_RSA_SIGN.*/
        if(dwKeySpec == AT_SIGNATURE)
        {
            *algId = CALG_RSA_SIGN;
        }
        else
        /**  - Else, RSA_KEYX.*/
        {
            *algId = CALG_RSA_KEYX;
        }
    }
    else
    {
        *algId = getAlgIdFromType(*keyType);
    }
    HeapFree(pProvCtx->heap, 0, keyType);
    return TRUE;
}

BOOL getKeyModulus(PROV_CTX *pProvCtx, HCRYPTKEY hKey, DWORD *keyModulus)
{
    /*CK_BYTE *modulus; * The key modulus.*/
    return FALSE;
}

BOOL getKeyModulusLength(PROV_CTX *pProvCtx, HANDLE hKeyInformation, 
                    DWORD *keyModulusLength)
{
    CK_ULONG bitsNumber = 0; /* Number of modulus length attributes.*/
    CK_ULONG *pModulusBits; /* Adress where the length of the key modulus will be
                              locally copied.*/
    CK_ULONG modulusBits; /* Where the length of the key modulus will be
                              locally copied.*/
    CK_OBJECT_HANDLE hKey; /* Specified key object handle.*/
    PKCS11_KEY_INFO  keyInformation; /* PKCS11 key information.*/
    
    keyInformation = *((PKCS11_KEY_INFO *) hKeyInformation);
    hKey = keyInformation.hKey;
    
    /** - Get the key modulus lenth.*/
    pModulusBits = getMODULUS_BITS(p11, pProvCtx, hKey,  &bitsNumber);
    if (!pModulusBits || (bitsNumber != 1))
    {
        if (pModulusBits) HeapFree(pProvCtx->heap, 0, pModulusBits);
        SetLastError(NTE_BAD_KEYSET); 
        return FALSE;
    }

    /** - Local copy it.*/
    modulusBits = *pModulusBits;
    /** - Free the allocated one.*/
    HeapFree(pProvCtx->heap, 0, pModulusBits);
    /** - Store it at the keyModulusLength pointed address.*/
    *keyModulusLength = modulusBits;
    return TRUE;

}

BOOL getKeyPermissions(PROV_CTX *pProvCtx, HCRYPTKEY hKey, 
                    DWORD *keyPermissions)
{
    DWORD permissions = 0; /* Local permissions.*/
    
    /** \todo keyObjectCanEncrypt*/
    if(keyObjectCanEncrypt(pProvCtx, hKey))
    {
        permissions = CRYPT_ENCRYPT;
    }
    /** \todo keyObjectCanDecrypt*/
    if(keyObjectCanDecrypt(pProvCtx, hKey))
    {
        permissions = permissions | CRYPT_DECRYPT;
    }
    /** \todo keyObjectIsExportable*/
    if(keyObjectIsExportable(pProvCtx, hKey))
    {
        permissions = permissions | CRYPT_EXPORT;
    }
    /** \todo keyObjectParametersCanBeRead*/
    if(keyObjectParametersCanBeRead(pProvCtx, hKey))
    {
        permissions = permissions | CRYPT_READ;
    }
    /** \todo keyObjectParametersCanBeSet*/
    if(keyObjectParametersCanBeSet(pProvCtx, hKey))
    {
        permissions = permissions | CRYPT_WRITE;
    }
    /** \todo keyObjectCanEncrypt*/
    if(keyObjectCanBeUsedWithMAC(pProvCtx, hKey))
    {
        permissions = permissions | CRYPT_MAC;
    }
    *keyPermissions = permissions;
    return TRUE;
}

BOOL getKeyValue(PROV_CTX *pProvCtx, HCRYPTKEY hKey, 
                    BYTE *keyValue, DWORD *valueLenth)
{
    return PKCS11_getObjectValue(pProvCtx, (CK_OBJECT_HANDLE) hKey,
                                 keyValue, valueLenth);
}

BOOL setCSPInstance(HINSTANCE csphInstance)
{
    if(csphInstance != NULL)
    {
        return setUIInstance(csphInstance);
    }
    return FALSE;
}

BOOL PKCS11_createSessionKeyObject(PROV_CTX *pProvCtx, ALGORITHM keyAlg,
                            CK_OBJECT_HANDLE *pKeyObject, 
                            CK_BYTE *value, DWORD valueLen)
{
    CK_RV rv; /* PKCS #11 API return value. */
    CK_SESSION_HANDLE   hSession;   /* Local copy of the session handler.*/
    CK_KEY_TYPE keyType;    /* The PKCS #11 key type.*/
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    CK_OBJECT_CLASS     keyClass = CKO_SECRET_KEY; /* The created key is a
                                                      secret (session) key*/
    /** - Local copy of key information pointer.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    /** - Local copy the session handler.*/
    hSession = hServiceInfo->hSession;
    /** - Nullify the pointer to the key object handle.*/
    pKeyObject = NULL;
    
    /** - Get the key type.*/
    keyType = getTypeFromAlgId(keyAlg.algId);
    /**  - If the value lenth is at least greater than key lenth.*/
    if((value != NULL) && (valueLen >= keyAlg.dwBits))
    {
        /**   - Declare and set up the key template.*/
        CK_BBOOL trueVal = TRUE;
        /* Session key can crypt and decrypt.*/
        CK_ATTRIBUTE objTemplate[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_DERIVE, &trueVal, sizeof(trueVal)},
            {CKA_ENCRYPT, &trueVal, sizeof(trueVal)},
            {CKA_DECRYPT, &trueVal, sizeof(trueVal)},
            {CKA_VALUE, value, keyAlg.dwBits}
        };              
    
        /**   - Create Key object.*/
        rv = p11->C_CreateObject(hSession, objTemplate, 6, pKeyObject);
        if (rv == CKR_OK)
        {
            return TRUE;
        }
    }
    /** - If we are here, there is a problem, we return FALSE.*/
    return FALSE;
}
   
BOOL PKCS11_genKeyPair(PROV_CTX *pProvCtx, CK_ULONG modulusBits,
                       CK_OBJECT_HANDLE** phPublicKey, CK_OBJECT_HANDLE** phPrivateKey)
{
    CK_RV rv; /* PKCS #11 API return value. */
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY; /* The public key PKCS#11
                                                   class.*/
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY; /* The private key PKCS#11
                                                   class.*/
    CK_BBOOL p11True = TRUE;                   /* PKCS #11 TRUE value. */
    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0}; /* User
                                                key pair generation mechanism. */
    CK_BYTE id[] = {0x45};
    CK_BYTE publicExponent[] = {3};
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_ENCRYPT, &p11True, sizeof(p11True)},
        {CKA_VERIFY, &p11True, sizeof(p11True)},
        {CKA_WRAP, &p11True, sizeof(p11True)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
    }; /* Public key generation template.*/
    int pubAttrNb = 6;  /* Number of public key generation template attributes.*/
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_TOKEN, &p11True, sizeof(p11True)},
        {CKA_PRIVATE, &p11True, sizeof(p11True)},
        {CKA_SENSITIVE, &p11True, sizeof(p11True)},
        {CKA_DECRYPT, &p11True, sizeof(p11True)},
        {CKA_SIGN, &p11True, sizeof(p11True)},
        {CKA_ID, id, sizeof(id)},
        {CKA_UNWRAP, &p11True, sizeof(p11True)}
    }; /* Private key generation template. */
    int privAttrNb = 8;  /* Number of private key generation template attributes.*/
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    
    
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    /** - Generate key pair.*/
    rv = p11->C_GenerateKeyPair(hServiceInfo->hSession, &mechanism,
                    publicKeyTemplate, pubAttrNb, privateKeyTemplate,
                    privAttrNb, *phPublicKey, *phPrivateKey);
    if(rv != CKR_OK)
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    return TRUE;
}

BOOL PKCS11_getObjectValue(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hObject, 
                    BYTE *objectValue, DWORD *valueLenth)
{
    CK_SESSION_HANDLE   hSession;   /* Local copy of the session handler.*/
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    CK_RV rv; /* PKCS #11 API return value. */
    
    /** - Locally copy the pointer to the key information structure.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    /** - Locally copy the session handler.*/
    hSession = hServiceInfo->hSession;
    
    /** - If objectValue is NULL, this is the first call.*/
    if(objectValue == NULL)
    {
        CK_ATTRIBUTE objTemplate[] = {
            {CKA_VALUE, NULL, *valueLenth}
        };
        rv = p11->C_GetAttributeValue(hSession, hObject, objTemplate, 1);
        if (rv != CKR_OK)
        {
            return FALSE;
        }
        
        if(valueLenth<0)
        {
            return FALSE;
        }
        
    }
    /** - If objectValue is not NULL, this is the final call.*/
    else
    {
        CK_ATTRIBUTE objTemplate[] = {
            {CKA_VALUE, objectValue, *valueLenth}
        };
        rv = p11->C_GetAttributeValue(hSession, hObject, objTemplate, 1);
        if (rv != CKR_OK)
        {
            return FALSE;
        }
    }
    return TRUE;

}

BOOL loadUserKey(PROV_CTX *pProvCtx, KEY_INFO *pKeyInfo)
{
    PKCS11_KEY_INFO  *pKeyInformation=NULL; /* PKCS11 key information.*/

    /** - Initialize the cryptoki library. */
    if (!PKCS11_initialize())
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    
    /** - Allocate memory for PKCS11 key information.*/
    pKeyInformation = (PKCS11_KEY_INFO*) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY,
                                sizeof(PKCS11_KEY_INFO));
    if(pKeyInformation == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    
    /** - Load keys in the container. */
    if(!PKCS11_loadUserKey(pProvCtx, pKeyInformation, pKeyInfo->dwKeySpec))
    {
        DWORD dwError = GetLastError();
        HeapFree(pProvCtx->heap, 0, pKeyInformation);
        SetLastError(dwError);
        return FALSE;
    }

    /** - Fill Key Information algorithm ID.*/
    if(!getKeyAlgId(pProvCtx, pKeyInformation->hKey, &(pKeyInfo->algId),
                    pKeyInfo->dwKeySpec))
    {
        HeapFree(pProvCtx->heap, 0, pKeyInformation);
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }

    CK_ULONG ulCount = 0;
    CK_ULONG *pBitLength  = getMODULUS_BITS(p11, pProvCtx, (CK_OBJECT_HANDLE) pKeyInformation->hKey,  &ulCount);
    if (pBitLength && ulCount == 1)
    {
        pKeyInfo->blockLen = (DWORD) (*pBitLength);
    }
    if (pBitLength)
        HeapFree(pProvCtx->heap, 0, pBitLength);
    /** - Copy cast in the keyInformation entry of the key handle.*/
    pKeyInfo->hKeyInformation = (HANDLE) pKeyInformation;

    pKeyInfo->permissions = CRYPT_READ | CRYPT_WRITE | (pKeyInfo->algId == CALG_RSA_KEYX?(CRYPT_ENCRYPT | CRYPT_EXPORT_KEY | CRYPT_DECRYPT):0);

    /** - Everything ok, return TRUE.*/
    return TRUE;
}

BOOL PKCS11_LogIn(PROV_CTX *pProvCtx, PKCS11_SERVICE_INFO *hServiceInfo,
                  char *pp_pin, DWORD keySpec)
{
    CK_RV rv; /* PKCS #11 API return value. */
    char pin[128] = {0}; /* The entered pin.*/
    CK_SESSION_HANDLE hSession; /* The session handle.*/

    hSession = hServiceInfo->hSession;
    
    /** \todo Use threaf security context.*/
    /**  - We assume the pin is incorrect if no pin is entered yet.*/
    rv = CKR_PIN_INCORRECT;
    
    /** - Before everything, if pp_pin is NULL, and caching is permitted,*/
    if((pp_pin == NULL))
    {
        /**   - Try cached PIN if exists.*/
        switch(keySpec)
        {
            case AT_KEYEXCHANGE:
                if(GetPinFromCache(hServiceInfo->slotId, pin))
                {
                    /** - Log into the card once. */
                    rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) pin, strlen(pin));
                    if (rv == CKR_OK)
                    /** - If logged, ok.*/
                    {
                        return TRUE;
                    }
                    else
                    /** - Else free cache.*/
                    {
                        ClearPinFromCache(hServiceInfo->slotId);
                    }
                }
                break;
        }
    }
    else
    {
        ClearPinFromCache(hServiceInfo->slotId);
        rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) pp_pin, strlen(pp_pin));
        switch(rv)
        {
            case CKR_PIN_LOCKED:
                if (!pProvCtx->silent)
                    displayPinLocked(pProvCtx->uiHandle, keySpec);                
                switch(keySpec)
                {
                    case AT_KEYEXCHANGE:
                        hServiceInfo->kxPinLocked = TRUE;
                        break;
                    case AT_SIGNATURE:
                        hServiceInfo->sigPinLocked = TRUE;
                        break;
                }
                SetLastError(SCARD_W_CHV_BLOCKED);
                return FALSE;
                break;
            case CKR_PIN_INCORRECT:
                if (!pProvCtx->silent)
                    displayPinIncorrect(pProvCtx->uiHandle, keySpec);                
                SetLastError(SCARD_W_WRONG_CHV);
                return FALSE;
                break;
            case CKR_ARGUMENTS_BAD:
                if (!pProvCtx->silent)
                    displayBadPin(pProvCtx->uiHandle, keySpec);
                SetLastError(NTE_BAD_DATA);
                return FALSE;
                break;
            case CKR_OK:
                {
                    switch(keySpec)
                    {
                        case AT_KEYEXCHANGE:
                            AddPinToCache(hServiceInfo->slotId, pin);
                            break;
                    }
                }
                return TRUE;
                break;
            default:
                SetLastError(NTE_FAIL);
                return FALSE;
        }

    }
    
    if(pProvCtx->silent)
    {
        SetLastError(NTE_SILENT_CONTEXT);
        return FALSE;
    }

    /** - Look if the pin is not locked.*/
    switch(keySpec)
    {
        case AT_KEYEXCHANGE:
            if(hServiceInfo->kxPinLocked)
            {
                displayPinLocked(pProvCtx->uiHandle, AT_KEYEXCHANGE);                
                SetLastError(SCARD_W_CHV_BLOCKED);
                rv = CKR_PIN_LOCKED;
            }
            break;
        case AT_SIGNATURE:
            if(hServiceInfo->sigPinLocked)
            {
                displayPinLocked(pProvCtx->uiHandle, AT_SIGNATURE);
                SetLastError(SCARD_W_CHV_BLOCKED);
                rv = CKR_PIN_LOCKED;
            }
            break;
    }

    /**  - Ask for PIN while, the pin is incorrect or unblocked.*/
    while((rv != CKR_OK) && (rv != CKR_PIN_LOCKED))
    {
        if (hServiceInfo->TokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
        {
            rv = PinPadGUI(&(pProvCtx->uiHandle), hSession, keySpec);
            if (rv == CKR_FUNCTION_CANCELED)
            {
                SetLastError(SCARD_W_CANCELLED_BY_USER);
                return FALSE;
            }
        }
        else
        {
            memset(pin, 0, sizeof(pin));
            if(!ChvGUI(&(pProvCtx->uiHandle), keySpec, pin, 128))
            {
                SetLastError(SCARD_W_CANCELLED_BY_USER);
                return FALSE;
            }
            /** - Log into the card. */
            rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) pin,strlen(pin));
        }
        /** - Switch on return value.*/
        switch(rv)
        {
            case CKR_PIN_LOCKED:
                displayPinLocked(pProvCtx->uiHandle, keySpec);                
                switch(keySpec)
                {
                    case AT_KEYEXCHANGE:
                        hServiceInfo->kxPinLocked = TRUE;
                        break;
                    case AT_SIGNATURE:
                        hServiceInfo->sigPinLocked = TRUE;
                        break;
                }
                SetLastError(SCARD_W_CHV_BLOCKED);
                break;
            case CKR_PIN_INCORRECT:
                displayPinIncorrect(pProvCtx->uiHandle, keySpec);                
                SetLastError(SCARD_W_WRONG_CHV);
                break;
            case CKR_ARGUMENTS_BAD:
                displayBadPin(pProvCtx->uiHandle, keySpec);
                SetLastError(NTE_FAIL);
                break;
            case CKR_OK:
                {
                    switch(keySpec)
                    {
                        case AT_KEYEXCHANGE:
                            AddPinToCache(hServiceInfo->slotId, pin);
                            break;
                    }
                }
                memset(pin, 0, sizeof(pin));
                return TRUE;
                break;
            default:
                SetLastError(NTE_FAIL);
                return FALSE;
        }
    }

    return FALSE;
}


BOOL releaseContext(PROV_CTX *pProvCtx)
{
    /** - Close PKCS11 session.*/
    return PKCS11_closeSession(pProvCtx);
}

BOOL simpleSignData(PROV_CTX *pProvCtx, KEY_INFO* pKeyInfo, BYTE *pData, DWORD dataLen,
              BYTE *pSignature, DWORD *pSignatureLen)
{
    PKCS11_KEY_INFO  keyInformation; /* PKCS11 key information.*/
    CK_OBJECT_HANDLE hKey; /* PKCS11 handle to the key.*/
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the service info structure. */

    
    HANDLE hKeyInformation = pKeyInfo->hKeyInformation;
    keyInformation = *((PKCS11_KEY_INFO *) hKeyInformation);
    hKey = keyInformation.hKey;
    /** - Local copy of key information pointer.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    
    
    return PKCS11_simpleSignData(pProvCtx, hKey, pKeyInfo->dwKeySpec, pData, dataLen,
                           pSignature, pSignatureLen);
}
    
BOOL extractLabels(LPCSTR cName, PKCS11_CONTAINER_INFO *containerInfo)
{
    char         *c;         /* Current character in the cName.*/
    CK_ULONG            counter;    /* Counter of characters.*/  

    counter = 0;
    memset(containerInfo, 0, sizeof(PKCS11_CONTAINER_INFO));
    c = (char*) cName;
    if(c == NULL)
    {
        return TRUE;
    }

    while(*c != '|' && counter < 33)
    {
        containerInfo->tokenLabel[counter] = *c;
        counter++;
        c++;
    }
    if(*c != '|')
    {
        memset(containerInfo, 0, sizeof(PKCS11_CONTAINER_INFO));
        return FALSE;
    }
    containerInfo->tokenLabel[counter] = '\0';

    // check that it is latvia ID
    if (    strcmp(containerInfo->tokenLabel, TOKEN_LABEL_SIGNATURE)
        &&  strcmp(containerInfo->tokenLabel, TOKEN_LABEL_USER)
        )
    {
        memset(containerInfo, 0, sizeof(PKCS11_CONTAINER_INFO));
        return FALSE;
    }
    counter = 0;
    c++;

    size_t hexLen = strlen(c);
    if ((hexLen == 0) || ((hexLen % 2) != 0) || !IsHexString(c,hexLen) || ((hexLen/2) > 64))
    {
        memset(containerInfo, 0, sizeof(PKCS11_CONTAINER_INFO));
        return FALSE;
    }

    ConvertHexString(c, hexLen, containerInfo->keyId);
    containerInfo->keyIdLen = hexLen/2;

    if (0 == strcmp(containerInfo->tokenLabel, TOKEN_LABEL_SIGNATURE))
        containerInfo->bIsSignature = TRUE;
    
    return TRUE;
}


BOOL PKCS11_addContainer(PROV_CTX *pProvCtx, CK_SLOT_ID slotId)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the service info structure. */
    CK_RV rv; /* PKCS #11 API return value. */
    CK_SLOT_INFO slotInfo;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
    CK_BBOOL bTrue = TRUE;
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE, hCert = CK_INVALID_HANDLE;
    CK_ULONG ulCount = 0;
    BYTE id[64];

    CK_ATTRIBUTE    keyTemplate[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
        {CKA_ID, id, 0}
    };

    CK_ATTRIBUTE idTemplate[] = {
        {CKA_ID, id, 64}
    };

    CK_ATTRIBUTE    certTemplate[] = {
        {CKA_CLASS, &certClass, sizeof(certClass)},
        {CKA_TOKEN, &bTrue, sizeof(CK_BBOOL)},
        {CKA_ID, id, 0}
    };

    rv = p11->C_GetSlotInfo(slotId, &slotInfo);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }   
    /** - If container type is supported.*/
    if ((pProvCtx->container.dwContainerType != SC_CONTAINER) &&
        (pProvCtx->container.dwContainerType != EPHE_CONTAINER))
    {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    }
    
    /** - Allocate memory for the container structure. */
    hServiceInfo = (PKCS11_SERVICE_INFO *) HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, sizeof(PKCS11_SERVICE_INFO));
    if (hServiceInfo == NULL)
    {
        SetLastError(NTE_NO_MEMORY);
        return FALSE;
    }
    
    /** - Initialize hServiceInfo structure.*/
    hServiceInfo->hSession = 0;
    hServiceInfo->slotId = NO_SLOT;
    hServiceInfo->kxPinLocked = FALSE;
    hServiceInfo->sigPinLocked = FALSE;
    
    /** - Open a PKCS #11 session on the card. */
    if(!PKCS11_openSession(slotId, hServiceInfo, pProvCtx))
    {
        HeapFree(pProvCtx->heap, 0, hServiceInfo);
        SetLastError(NTE_FAIL);
        return FALSE;
    }
        
    memset(&hServiceInfo->TokenInfo, 0, sizeof(CK_TOKEN_INFO));
    
    /** - Get token (card) information. */
    rv = p11->C_GetTokenInfo(slotId, &hServiceInfo->TokenInfo);
    if (rv != CKR_OK)
    {        
        HeapFree(pProvCtx->heap, 0, hServiceInfo);
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    // check the presence of the container
    if (pProvCtx->container.cName != NULL)
    {
        PKCS11_CONTAINER_INFO info;
        extractLabels(pProvCtx->container.cName, &info);
        memcpy(id, info.keyId, info.keyIdLen);
        keyTemplate[2].ulValueLen = info.keyIdLen;
        ulCount = 0;
        rv = p11->C_FindObjectsInit(hServiceInfo->hSession, keyTemplate, 3);
        if (rv == CKR_OK)
        {
            rv = p11->C_FindObjects(hServiceInfo->hSession, &hKey, 1, &ulCount);
            p11->C_FindObjectsFinal(hServiceInfo->hSession);
        }

        if ((rv == CKR_OK) && ulCount && (hKey != CK_INVALID_HANDLE))
        {
            ulCount = 0;
            certTemplate[2].ulValueLen = info.keyIdLen;
            rv = p11->C_FindObjectsInit(hServiceInfo->hSession, certTemplate, 3);
            if (rv == CKR_OK)
            {                
                rv = p11->C_FindObjects(hServiceInfo->hSession, &hCert, 1, &ulCount);
                p11->C_FindObjectsFinal(hServiceInfo->hSession);
            }

            if ((rv == CKR_OK) && ulCount && (hCert != CK_INVALID_HANDLE))
            {
                hServiceInfo->hPubKey = hKey;
                hServiceInfo->hCert = hCert;
            }
        }

        if ((hServiceInfo->hPubKey == 0) ||(hServiceInfo->hCert == 0))
        {
            HeapFree(pProvCtx->heap, 0, hServiceInfo);
            SetLastError(NTE_BAD_KEYSET);
            return FALSE;
        }
    }

   
    /** - Store the slot ID in the key information structure. */
    hServiceInfo->slotId = slotId;
    /** - Store the key information in the key container. */
    pProvCtx->container.hServiceInformation = (HANDLE) hServiceInfo;

    if (pProvCtx->container.cReaderName == NULL)
    {
        // get effective length
        int i = 63;
        while ( (i>=0) && (slotInfo.slotDescription[i] == ' '))
            i--;
        i++;

        if (i > 0)
        {
            pProvCtx->container.cReaderName = (char*) HeapAlloc(pProvCtx->heap,
                                                    HEAP_ZERO_MEMORY, i+1);
            if (pProvCtx->container.cReaderName)
                memcpy(pProvCtx->container.cReaderName, slotInfo.slotDescription, i);
        }
    }


    if (pProvCtx->container.cName == NULL)
    {
        // Get the public key and the certificate
        // find public key and get its CKA_ID
        rv = p11->C_FindObjectsInit(hServiceInfo->hSession, keyTemplate, 2);
        if (rv == CKR_OK)
        {
            do
            {
                rv = p11->C_FindObjects(hServiceInfo->hSession, &hKey, 1, &ulCount);
                if ( (rv == CKR_OK) && ulCount)
                {               
                    idTemplate[0].ulValueLen = 64;
                    rv = p11->C_GetAttributeValue(hServiceInfo->hSession, hKey, idTemplate, 1);
                    if ((rv == CKR_OK) 
                        && (idTemplate[0].ulValueLen != CK_UNAVAILABLE_INFORMATION)
                        && (idTemplate[0].ulValueLen > 2)
                        )
                    {
                        break;
                    }
                }
                hKey = CK_INVALID_HANDLE;
            }
            while ((rv == CKR_OK) && ulCount);
            p11->C_FindObjectsFinal(hServiceInfo->hSession);
        }

        if (hKey != CK_INVALID_HANDLE)
        {
            // search for certificate
            certTemplate[2].ulValueLen = idTemplate[0].ulValueLen;
            rv = p11->C_FindObjectsInit(hServiceInfo->hSession, certTemplate, 3);
            if (rv == CKR_OK)
            {
                rv = p11->C_FindObjects(hServiceInfo->hSession, &hCert, 1, &ulCount);
                p11->C_FindObjectsFinal(hServiceInfo->hSession);
            }

            if ((rv == CKR_OK) && ulCount)
            {
                hServiceInfo->hPubKey = hKey;
                hServiceInfo->hCert = hCert;
            }
        }

        if((hServiceInfo->hPubKey != 0) && (hServiceInfo->hCert != 0))
        {
            // get effective length
            int labelLength = 31;
            while ( (labelLength>=0) && (hServiceInfo->TokenInfo.label[labelLength] == ' '))
                labelLength--;
            labelLength++;

            if (labelLength > 0)
            {
                int nameLength = labelLength + 1 + (2*idTemplate[0].ulValueLen);
                pProvCtx->container.cName = (char*) HeapAlloc(pProvCtx->heap,
                                                        HEAP_ZERO_MEMORY, nameLength+1);
                if (pProvCtx->container.cName)
                {
                    memcpy(pProvCtx->container.cName, hServiceInfo->TokenInfo.label,labelLength);
                    pProvCtx->container.cName[labelLength] = '|';
                    ConvertToHex(id, idTemplate[0].ulValueLen, pProvCtx->container.cName +labelLength + 1);
                }
            }
        }
        else if (pProvCtx->container.dwContainerType != EPHE_CONTAINER)
        {
            pProvCtx->container.hServiceInformation = NULL;
            HeapFree(pProvCtx->heap, 0, hServiceInfo);
            SetLastError(NTE_BAD_KEYSET);
            return FALSE;
        }
    }

    {
        // get the name of the other container
        CK_SLOT_ID_PTR pSlots = NULL;
        CK_SLOT_INFO otherSlotInfo;
        CK_TOKEN_INFO otherTokenInfo;
        CK_ULONG i;
        std::vector<CK_SLOT_ID> vSlots;
        
        ulCount = 0;
        rv = p11->C_GetSlotList(TRUE, NULL, &ulCount);
        if ((CKR_OK == rv) && ulCount)
        {
            vSlots.resize(ulCount);
            pSlots = &vSlots[0];
            rv = p11->C_GetSlotList(TRUE, pSlots, &ulCount);
        }
        if (rv == CKR_OK)
        {
            // look of the one in the same reader
            for (i=0; i<ulCount; i++)
            {
                if (pSlots[i] == slotId)
                    continue;
                rv = p11->C_GetSlotInfo(pSlots[i], &otherSlotInfo);
                if ((rv == CKR_OK) 
                    && (0 == memcmp(slotInfo.slotDescription, otherSlotInfo.slotDescription, 64))
                    )
                {
                    rv = p11->C_GetTokenInfo(pSlots[i], &otherTokenInfo);
                    if (rv == CKR_OK)
                        break;
                }
            }

            if (i < ulCount)
            {
                CK_SESSION_HANDLE hSession;
                rv = p11->C_OpenSession(pSlots[i],CKF_SERIAL_SESSION, NULL,NULL, &hSession);
                if (rv == CKR_OK)
                {
                    // Get the public key and the certificate
                    // find public key and get its CKA_ID
                    hKey = CK_INVALID_HANDLE;
                    hCert = CK_INVALID_HANDLE;
                    ulCount = 0;
                    rv = p11->C_FindObjectsInit(hSession, keyTemplate, 2);
                    if (rv == CKR_OK)
                    {
                        do
                        {
                            rv = p11->C_FindObjects(hSession, &hKey, 1, &ulCount);
                            if ( (rv == CKR_OK) && ulCount)
                            {               
                                idTemplate[0].ulValueLen = 64;
                                rv = p11->C_GetAttributeValue(hSession, hKey, idTemplate, 1);
                                if ((rv == CKR_OK) 
                                    && (idTemplate[0].ulValueLen != CK_UNAVAILABLE_INFORMATION)
                                    && (idTemplate[0].ulValueLen > 2)
                                    )
                                {
                                    break;
                                }
                            }
                            hKey = CK_INVALID_HANDLE;
                        }
                        while ((rv == CKR_OK) && ulCount);
                        p11->C_FindObjectsFinal(hSession);
                    }

                    if (hKey != CK_INVALID_HANDLE)
                    {
                        // search for certificate
                        certTemplate[2].ulValueLen = idTemplate[0].ulValueLen;
                        rv = p11->C_FindObjectsInit(hSession, certTemplate, 3);
                        if (rv == CKR_OK)
                        {
                            rv = p11->C_FindObjects(hSession, &hCert, 1, &ulCount);
                            p11->C_FindObjectsFinal(hSession);
                        }
                    }

                    if((hKey != CK_INVALID_HANDLE) && (hCert != CK_INVALID_HANDLE))
                    {
                        // get effective length
                        int labelLength = 31;
                        while ( (labelLength>=0) && (otherTokenInfo.label[labelLength] == ' '))
                            labelLength--;
                        labelLength++;

                        if (labelLength > 0)
                        {
                            int nameLength = labelLength + 1 + (2*idTemplate[0].ulValueLen);
                            pProvCtx->container.cOtherContainerName = (char*) HeapAlloc(pProvCtx->heap,
                                                                    HEAP_ZERO_MEMORY, nameLength+1);
                            if (pProvCtx->container.cOtherContainerName)
                            {
                                memcpy(pProvCtx->container.cOtherContainerName, otherTokenInfo.label, labelLength);
                                pProvCtx->container.cOtherContainerName[labelLength] = '|';
                                ConvertToHex(id, idTemplate[0].ulValueLen, pProvCtx->container.cOtherContainerName +labelLength + 1);
                            }
                        }
                    }

                    p11->C_CloseSession(hSession);
                }
            }
        }
    }
    return TRUE;
}

BOOL PKCS11_loadUserKey(PROV_CTX *pProvCtx, 
                        PKCS11_KEY_INFO *pKeyInformation, 
                        DWORD dwKeySpec)
{   
    CK_ULONG        objectsFoundNumber = 0; /* The number of objects found on the token.*/
    CK_SLOT_ID slotId = NO_SLOT; /* The selected slot Id. */
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */


    CK_BBOOL trueVal = TRUE;
    CK_MECHANISM mechanism = {0,0,0};           /* Used hash mechanism.*/
    PKCS11_CONTAINER_INFO   containerInfo;      /* The container information.*/
    char *cIdentifier;  /* The c string hash algo identifier.*/
    unsigned char *keyId; /* The key ID.*/
    char *keyHash; /* the key hash.*/

    cIdentifier = NULL;
    keyId = NULL;
    keyHash = NULL;
    /** - Retrieve service information and slot ID.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    slotId = hServiceInfo->slotId;

    if (hServiceInfo->hPubKey == 0)
    {
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }

    if (!extractLabels(pProvCtx->container.cName, &containerInfo))
    {
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }

    if (    ((dwKeySpec == AT_SIGNATURE) && (!containerInfo.bIsSignature))
        ||  ((dwKeySpec == AT_KEYEXCHANGE) && (containerInfo.bIsSignature))
        )
    {
        SetLastError(NTE_NO_KEY);
        return FALSE;
    }
    
    if(!fillP11Key(pProvCtx, hServiceInfo->hPubKey, hServiceInfo->hCert, pKeyInformation))
    {
        return FALSE;
    }
    return TRUE;
}

    
BOOL PKCS11_findSlot(PROV_CTX provCtx, CK_SLOT_ID *slotId)
{
    
    CK_SLOT_ID_PTR slots;    /* The avaible slots. */
    CK_ULONG slotsNumber = 0;       /* The avaible slots number. */
    CK_SLOT_INFO	slotInfo;   /* Information about the selected slot. */
    CK_TOKEN_INFO	tokenInfo;  /* Information about the inserted token. */
    CK_ULONG	        slotIndex = 0;  /* The actual slot number. */
    CK_RV		rv;         /* PKCS #11 function return value. */
    PKCS11_CONTAINER_INFO containerInfo; /* The container informaiton.*/
    std::vector<CK_SLOT_ID> vSlots;

    if(!extractLabels(provCtx.container.cName, &containerInfo))
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    
    rv = p11->C_GetSlotList(TRUE, NULL, &slotsNumber);
    if ((rv == CKR_OK) && (slotsNumber != 0))
    {
        vSlots.resize(slotsNumber);
        slots = &vSlots[0];
        rv = p11->C_GetSlotList(TRUE, slots, &slotsNumber);
    }

    if (rv != CKR_OK)
    {
        SetLastError(ERROR_DEVICE_NOT_AVAILABLE);
        return FALSE;
    }
    
    /* - Try each slot to find the correct one, with the correct card. */
    while(slotIndex<slotsNumber)
    {
        *slotId = slots[slotIndex];
        
        /**  - Get the current slot info.*/
        rv = p11->C_GetSlotInfo(*slotId, &slotInfo);
        if (rv == CKR_OK)   /* The slot is available.*/
        {
            if (provCtx.container.cReaderName != NULL)
            {
                if (    (strlen(provCtx.container.cReaderName) > 64)
                    ||  (0 != memcmp(slotInfo.slotDescription, provCtx.container.cReaderName, strlen(provCtx.container.cReaderName)))
                    )
                {
                    // not the desired reader
                    continue;
                }
            }
          
            /**   - Get the token info.*/
            rv = p11->C_GetTokenInfo(*slotId, &tokenInfo);
            if (rv == CKR_OK)
            {
                //remove trailing spaces from tokenInfo.label
                int labelLength = 31;
                while ((labelLength >= 0) && tokenInfo.label[labelLength] == (CK_UTF8CHAR) ' ')
                    labelLength--;

                labelLength++;

                if (    ( (labelLength == strlen(TOKEN_LABEL_USER)) && (0 == memcmp(tokenInfo.label, TOKEN_LABEL_USER, labelLength)))
                    ||  ( (labelLength == strlen(TOKEN_LABEL_SIGNATURE)) && (0 == memcmp(tokenInfo.label, TOKEN_LABEL_SIGNATURE, labelLength)))
                    )
                {
	                if(provCtx.container.cName == NULL)
                    {
                        break;
                    }
                    else
                    {
                        if(     (labelLength == (int) strlen(containerInfo.tokenLabel))
                            &&  (0 == memcmp(containerInfo.tokenLabel, tokenInfo.label, labelLength)) 
                          )
                        {
                            /**   - If slot found, break*/
                            break;
                        }
                    }
                }
            }
        }
        /**   - Next slot.*/
        slotIndex++; /* Forward to the next slot.*/
    }
    /** - If found ok.*/
    if (slotIndex >= slotsNumber)
    {
        *slotId = NO_SLOT;
        return FALSE;
    }
    return TRUE;

}

BOOL PKCS11_initialize()
{
    CK_RV rv; /* PKCS #11 API return value. */
    CK_C_GetFunctionList pC_GetFunctionList = NULL;  /* Pointer to the PKCS
                                                          #11 C_GetFunctionList
                                                          function.*/
    CK_C_INITIALIZE_ARGS initArgs; /* Cryptoki inialization arguments.*/
    
    TCHAR	dllName[]=_T("OTLvP11.dll");
    TCHAR szPath[512] = {0};

    /** - Set cryptoki initialization arguments.*/
    /** - No mutex function pointers used.*/
    initArgs.CreateMutex = NULL;
    initArgs.DestroyMutex = NULL;
    initArgs.LockMutex = NULL;
    initArgs.UnlockMutex = NULL;
    /** - Application will be performing multithreaded access.*/
    initArgs.flags = CKF_OS_LOCKING_OK;
    initArgs.pReserved = NULL;
    
    /** Test if p11 is already initialized.*/
    if (p11)
    {
        return TRUE;
    }
    
    /** - Load PKCS11 module.*/
    if (GetModuleFileName(g_hModule, szPath, 512))
    {
        TCHAR* ptr = &szPath[_tcslen(szPath) - 1];
        while ((ptr != szPath) && (*ptr != _T('\\')) && (*ptr != _T('/')))
            ptr--;

        if (ptr != szPath)
        {
            ptr++;
            _tcscpy(ptr, dllName);
        }
        else
            _tcscpy(szPath, dllName);
    }
    else
        _tcscpy(szPath, dllName);

    module = LoadLibrary(szPath);
    if (module == NULL)
    {   
        SetLastError(NTE_PROVIDER_DLL_FAIL);
        return FALSE;
    }
    
    
    /** - Get pointer to the C_GetFunctionList function.*/
    pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(module,
                                                    "C_GetFunctionList");
    if (pC_GetFunctionList == NULL)
    {
        SetLastError(NTE_PROVIDER_DLL_FAIL);
        return FALSE;
    }
    
    /** - Get pointer to the PKCS11 function list. */
    rv = (*pC_GetFunctionList)(&p11);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_PROVIDER_DLL_FAIL);
        return FALSE;
    }
    
    /** - Initialize PKCS 11 library.*/
    rv = p11->C_Initialize(&initArgs);
    if (rv != CKR_OK)
    {
        /**  - If C_Initialize faild because cryptoki is already initialized.*/
        if(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
        {
            /**   - No problem, we will use it.*/
            return TRUE;
        }

        SetLastError(NTE_PROVIDER_DLL_FAIL);
        return FALSE;
    }
    return TRUE;
}


BOOL PKCS11_openSession(CK_SLOT_ID slotId, PKCS11_SERVICE_INFO *hServiceInfo, PROV_CTX
                        *pProvCtx)
{
    CK_RV rv; /* PKCS #11 API return value. */
    CK_SESSION_HANDLE hSession = NULL; /* PKCS #11 API session handler.*/
    
    
    /** - The CKF_SERIAL_SESSION is madatory. We want R/W session.*/
    rv = p11->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                            NULL, &hSession);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_BAD_KEYSET);
        return FALSE;
    }
    /** - Copy the session handle to the context.*/
    hServiceInfo->hSession = hSession;
    return TRUE;
}

BOOL PKCS11_closeSession(PROV_CTX *pProvCtx)
{
    CK_SESSION_HANDLE   hSession;   /* Local copy of the session handler.*/
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    
    /** - Locally copy the pointer to the key information structure.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    /** - If there are service information.*/
    if(hServiceInfo != NULL)
    {
        /** - Locally copy the session handler.*/
        hSession = hServiceInfo->hSession;
    
        /** - Close the PKCS #11 Session. */
        if (p11)
            p11->C_CloseSession(hSession);
    
        /** - Free memory used for service information.*/
        HeapFree(pProvCtx->heap, 0, hServiceInfo);
        pProvCtx->container.hServiceInformation = NULL;
        return TRUE;
    }
    return FALSE;
}

/*BOOL PKCS11_destroyKeys(PROV_CTX *pProvCtx, HANDLE hKey)
{

}*/

BOOL PKCS11_getSignatureKey(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hPubKeyObject, DWORD dwKeySpec,
                     CK_OBJECT_HANDLE *hSignatureKey)
{
    CK_RV rv; /* PKCS #11 API return value. */
    CK_ATTRIBUTE    objTemplate[2];   /* The PKCS #11 key research template (type, etc...).*/
    /*CK_OBJECT_CLASS objectClass;    * The researched object PKCS #11 class. */
    CK_ULONG        objectsFoundNumber = 0; /* The number of objects found on the token.*/
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    /*unsigned char       *pucSignId = NULL;   * The signature key object ID. */
    unsigned char       *pucPubId = NULL;   /* The public key object ID. */
    CK_ULONG            idsNumber = 0; /* The number of goten IDs of the
                                            found keys.*/
    CK_OBJECT_HANDLE     hSignKey;     /* Handle to the PKCS11 signature key.*/
    CK_SLOT_ID slotId = NO_SLOT; /* The selected slot Id. */
    CK_BBOOL trueVal = TRUE;

    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    slotId = hServiceInfo->slotId;

    /** - Test if user can read and write on the card. */
    if(!PKCS11_rwUserFnSession(pProvCtx, dwKeySpec))
    {
        return FALSE;
    }
   
    /** - Get the public Key ID.*/
    pucPubId = getID(p11, pProvCtx, hPubKeyObject,  &idsNumber);
 
    objTemplate[0].type = CKA_ID;
    objTemplate[0].pValue = pucPubId;
    objTemplate[0].ulValueLen = idsNumber;   /* The PKCS #11 key ID*/
                                                            /* attribute*/
    /** - Set up ID attribute template.*/
    //objTemplate[0].type = CKA_CLASS;
    //objectClass = CKO_PRIVATE_KEY;
    //objTemplate[0].pValue = &objectClass;
    //objTemplate[0].ulValueLen = 0;
    //objTemplate[0].ulValueLen = sizeof(objectClass);   /*We want a public key
    /*                                                  class object.*/ 
    /** \todo Filter key to sign. */
    objTemplate[1].type = CKA_SIGN;
    objTemplate[1].pValue = &trueVal;
    objTemplate[1].ulValueLen= sizeof(trueVal);
    /** - Initiate signature key research.*/
    rv = p11->C_FindObjectsInit(hServiceInfo->hSession, objTemplate, 2); 
    //rv = p11->C_FindObjectsInit(hServiceInfo->hSession, objTemplate, 1); 
    if (rv != CKR_OK)
    {
        SetLastError(NTE_BAD_KEYSET);
        return FALSE;
    }

    /** - Find the first corresponding object and add it to the key set structure. */
    rv = p11->C_FindObjects(hServiceInfo->hSession, &hSignKey, 1, &objectsFoundNumber);
    if (rv != CKR_OK)
    {
        rv = p11->C_FindObjectsFinal(hServiceInfo->hSession);
        SetLastError(NTE_BAD_KEYSET);
        return FALSE;
    }
    
    /** - Close the public key research.*/
    rv = p11->C_FindObjectsFinal(hServiceInfo->hSession);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_BAD_KEYSET);
        return FALSE;
    }
    
    /** - If no object found, return false. */
    if(objectsFoundNumber < 1)
    {
        SetLastError(NTE_BAD_KEYSET);
        return FALSE;
    }
    
    *hSignatureKey = hSignKey;
    return TRUE;
}   


BOOL PKCS11_rwUserFnSession(PROV_CTX *pProvCtx, DWORD keySpec)
{
    CK_RV rv; /* PKCS #11 API return value. */
    CK_SESSION_INFO     sessionInfo;    /* Debug purpose. */
    CK_SLOT_ID slotId = NO_SLOT; /* The selected slot Id. */
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    // char		*pin = NULL;    /* Local pointer on the pin string. */
    //char		*pin = "1234";    /* Local pointer on the pin string
                                            //For testing purpose: 1234. */
    
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    slotId = hServiceInfo->slotId;
    
    /** - If session can not write.*/
    rv = p11->C_GetSessionInfo(hServiceInfo->hSession, &sessionInfo);
    if (rv != CKR_OK)
    {   
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    if (sessionInfo.state == CKS_RW_USER_FUNCTIONS)
    {
        return TRUE;
    }
    /** - Query P.I.N. if needed */
    if (hServiceInfo->TokenInfo.flags & CKF_LOGIN_REQUIRED)
    {
        if(!PKCS11_LogIn(pProvCtx, hServiceInfo, NULL, keySpec))
        {
            return FALSE;
        }
    }
    rv = p11->C_GetSessionInfo(hServiceInfo->hSession, &sessionInfo);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }
    /** - If user can write: ok.*/
    if (sessionInfo.state == CKS_RW_USER_FUNCTIONS)
    {
        return TRUE;
    }

    SetLastError(NTE_FAIL);
    return FALSE;
}

BOOL PKCS11_simpleSignData(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey, DWORD dwKeySpec, BYTE *pData, DWORD dataLen,
              BYTE *pSignature, DWORD *pSignatureLen)
{
    CK_RV rv; /* PKCS #11 API return value. */
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    CK_OBJECT_HANDLE     signatureKey; /* Pointer to the key used to sign.*/
    CK_MECHANISM    mechanism = {
        CKM_RSA_PKCS, NULL, 0 };  /* Mechanism used in order to simple sign.*/
    
    /** - Locally copy the pointer to the key information structure.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;

    /** - If pSignature is NULL, then the signature is initialized, and the size
     *    of the produced signature is grabbed.*/
    /**  - Get the private key Object handle.*/
    if(!PKCS11_getSignatureKey(pProvCtx, hKey, dwKeySpec, &signatureKey))
    {
        return FALSE;
    }
    
    /** - If pSignature is NULL, fill length and return.*/
    if(pSignature == NULL)
    {
        PKCS11_getSignatureLen(pProvCtx, signatureKey, pSignatureLen);
        return TRUE;
    }
 
    /**  - Initialise signature.*/
    rv = p11->C_SignInit(hServiceInfo->hSession, &mechanism, signatureKey);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    /**  - Get the signature.*/
    rv = p11->C_Sign(hServiceInfo->hSession, pData, dataLen, pSignature,
                     pSignatureLen);
    if (rv != CKR_OK)
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    return TRUE;
}

BOOL validateKeyExchangePin(PROV_CTX provCtx, char *pin)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    
    /** - Locally copy the pointer to the key information structure.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) provCtx.container.hServiceInformation;

    // logout first
    p11->C_Logout(hServiceInfo->hSession);
    /** \todo Differenciate Sig & key echange CHV.*/
    return PKCS11_LogIn(&provCtx, hServiceInfo,
                        pin, AT_KEYEXCHANGE);
}
BOOL validateKeySigPin(PROV_CTX provCtx, char *pin)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */
    
    /** - Locally copy the pointer to the key information structure.*/
    hServiceInfo = (PKCS11_SERVICE_INFO *) provCtx.container.hServiceInformation;

    // logout first
    p11->C_Logout(hServiceInfo->hSession);
    /** \todo Differenciate Sig & key echange CHV.*/
    return PKCS11_LogIn(&provCtx, hServiceInfo, pin, AT_SIGNATURE);
}

BOOL UpdateState()
{
    static SCARDCONTEXT g_hGlobalContext = NULL;
    if (!g_hGlobalContext)
        SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &g_hGlobalContext);
    else if (SCARD_S_SUCCESS != SCardIsValidContext(g_hGlobalContext))
    {
        g_hGlobalContext = NULL;
        if (p11)
        {
            p11->C_Finalize(NULL);
            FreeLibrary(module);
            module = NULL;
            p11 = NULL;
            SecureZeroMemory(g_pinCache, sizeof(g_pinCache)); 
        }
    }
    else if (p11)
    {

        // List all slots to update internal P11 state
        CK_SLOT_ID pSlots[64];
        CK_ULONG ulCount = 64;
        CK_RV rv;
        p11->C_GetSlotList(FALSE, pSlots, &ulCount);

        do
        {
            rv = p11->C_WaitForSlotEvent(CKF_DONT_BLOCK, pSlots, NULL);
            if (rv == CKR_OK)
            {
                // an event occured. Clear PIN cache on this slot
                ClearPinFromCache(pSlots[0]);
            }
        } while(rv == CKR_OK);
    }

    if (g_hGlobalContext)
        return TRUE;
    else
        return FALSE;
}

BOOL IsValidContext(PROV_CTX* pProvCtx)
{
    CK_SESSION_INFO info;
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */      
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;

    if (p11 && hServiceInfo)    
        return (CKR_OK == p11->C_GetSessionInfo(hServiceInfo->hSession, &info));
    else
    {
        if (pProvCtx->container.dwContainerType == EPHE_CONTAINER)
            return TRUE;
        else
            return FALSE;
    }
}

void InvalidatePIN(PROV_CTX* pProvCtx)
{
    PKCS11_SERVICE_INFO    *hServiceInfo = NULL;  /* Pointer to the key container structure. */      
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation;
    
    if (p11)
        p11->C_Logout(hServiceInfo->hSession);
}
