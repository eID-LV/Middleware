/** \file pkcs11-helpers.c
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

         
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#ifdef _MSC_VER

#include "missdef.h"
#else
#include "misscrypt.h"
#endif
#include "pkcs11.h"
#include "pkcs11-helpers.h"

CK_FUNCTION_LIST_PTR p11 = NULL; /**< The PKCS #11 API functions pointers. */

PKCS11_KEY_TYPE keyAlgTypes[]={
    {CALG_DES,CKK_DES},
    {CALG_3DES_112,CKK_DES3},
    {CALG_3DES,CKK_DES3},
    {CALG_RC2,CKK_RC2},
    {CALG_RC4,CKK_RC4},
    {CALG_RSA_KEYX,CKK_RSA},
    {CALG_RSA_SIGN,CKK_RSA},
    {AT_SIGNATURE,CKK_RSA},
    {AT_KEYEXCHANGE,CKK_RSA},
}; /**< \brief  CAPI <==> PKCS#11 key algorithms translation table.
    *   
    *   \warning If CAPI makes a diffence between RSA signature and exchange
    *   key, PKCS#11 not. We have to test the sign & echange attribute.
    *   \warning PKCS #11 separates the key type from the generation mechanisms.
    *   How handle CKM_DES2_KEY_GEN ?
    */

ALG_ID getAlgIdFromType(CK_KEY_TYPE keyType)
{
    int tableLenth = 0; /* The translation table lenth, computed here.*/
    int i = 0; /* Iterator.*/
    
    tableLenth = sizeof(keyAlgTypes) / sizeof(PKCS11_KEY_TYPE);

    for(i=0; i<tableLenth; i++)
    {
        if(keyType == keyAlgTypes[i].keyType)
        {
            return keyAlgTypes[i].algId;
        }
    }
    return -1;
}


CK_KEY_TYPE getTypeFromAlgId(ALG_ID algId)
{
    int tableLenth = 0; /* The translation table lenth, computed here.*/
    int i = 0; /* Iterator.*/
    
    tableLenth = sizeof(keyAlgTypes) / sizeof(PKCS11_KEY_TYPE);

    for(i=0; i<tableLenth; i++)
    {
        if(algId == keyAlgTypes[i].algId)
        {
            return keyAlgTypes[i].keyType;
        }
    }
    return -1;
}

BOOL findPrivateKey(CK_SESSION_HANDLE hSession,
                    unsigned char pubKeyId, CK_OBJECT_HANDLE *phPrivKey)
{   
    CK_RV rv; /* PKCS #11 API return value. */
    CK_ATTRIBUTE    objTemplate[2];   /* The PKCS #11 key research template (type, etc...).*/
    CK_OBJECT_CLASS objectClass;    /* The researched object PKCS #11 class. */
    CK_ULONG        objectsFoundNumber = 0; /* The number of objects found on the token.*/

    
    /**  - Set up generic class template.*/
    objTemplate[0].type = CKA_CLASS;
    objTemplate[0].pValue = &objectClass;
    objTemplate[0].ulValueLen = 0;
    
    /** - Find a public key in order to crypt data. */
    objectClass = CKO_PRIVATE_KEY;
    objTemplate[0].ulValueLen = sizeof(objectClass);  /* We want a public key
                                                      class object.*/ 

    /** - Find a object with ID == {key object ID}.*/
    objTemplate[1].type =CKA_ID;
    /**  - key object ID == sigKeyId.*/
    objTemplate[1].pValue = &pubKeyId;
    objTemplate[1].ulValueLen=sizeof(unsigned char);
    /** - Initiate public key research with the three templates.*/
    rv = p11->C_FindObjectsInit(hSession, objTemplate, 2);
    if (rv != CKR_OK)
    {
        rv = p11->C_FindObjectsFinal(hSession);
        return FALSE;
    }
    /** - Find the first corresponding object and add it to the key set structure. */
    rv = p11->C_FindObjects(hSession, phPrivKey, 1, &objectsFoundNumber);
    if (rv != CKR_OK)
    {
        rv = p11->C_FindObjectsFinal(hSession);
        SetLastError(NTE_BAD_KEYSET);
        return FALSE;
    }
    
    /** - Close the public key research.*/
    rv = p11->C_FindObjectsFinal(hSession);
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
    
    return TRUE;
}
