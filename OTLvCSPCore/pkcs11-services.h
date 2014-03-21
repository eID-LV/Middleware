/** \file pkcs11-services.h
 * $Id: pkcs11-services.h 259 2005-03-17 16:06:25Z rchantereau $ 
 *
 * CSP #11 -- PKCS11 Cryptographic Services.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  This file declares and documents all the necessary functions and types
 *  in order to provide PKCS #11 Cryptographic Services.
 *  The documentation written here is used by documentation manager.
 *
 *  \note Each funtion name that needs pkcs #11 API begins by PCKS11_.
 * 
 * \author  Romain Chantereau <rchantereau@entrouvert.com>
 * \date    2004
 * \version  0.1
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

/** \defgroup   SInterface Services interface with CSP functions.
 *
 *  Theses functions are used for wrapp services specific functions and the
 *  general CSP calls.
 */

/** \defgroup   SSpecific Services specific functions.
 *
 *  Theses functions are only called from other services specific functions or
 *  by the services interface functions.
 */

/** \defgroup   SHelper   Internal helpers functions.
 *  
 *  These functions are used in order to help the poor developper translating
 *  one API data to another, etc...
 */

#ifndef _PKCS11_SERVICES_H_

#define _PKCS11_SERVICES_H_     /**< pkcs11_services.h inclusion tag. */

#define NO_SLOT ((CK_SLOT_ID) -1)   /**< A -1 slot number means no choosen
                                        slot. */

/** \brief Container information.
 *  
 *  This structure describe the key to use according to the container name.
 *  
 *  \ingroup SSpecific
 */
typedef struct _PKCS11_CONTAINER_INFO {
    char     tokenLabel[33];     /**< Token label.*/
    unsigned char   keyId[64];         /**< key CKA_ID.*/
    CK_ULONG        keyIdLen;
    CK_BBOOL        bIsSignature;
} PKCS11_CONTAINER_INFO;

/** \brief Card information.
 *
 *  This structure is an attempts to gather all necessary contextual information
 *  about a card and how to access it.
 *  \ingroup SSpecific
 */
typedef struct _PKCS11_SERVICE_INFO {
    CK_SESSION_HANDLE       hSession;    /**< Handler to the PKCS#11 Session. */
    CK_TOKEN_INFO           TokenInfo;    /**< PKCS #11 Information about the used token. */
    CK_SLOT_ID          slotId;             /**< The token slot ID. */
    BOOL                kxPinLocked;    /**< True if the key exchange pin is
                                             locked.*/
    BOOL                sigPinLocked;   /**< True if the signature pin is
                                             locked.*/
    CK_OBJECT_HANDLE hPubKey;
    CK_OBJECT_HANDLE hCert;
} PKCS11_SERVICE_INFO;

typedef struct _PKCS11_KEY_INFO {
    CK_OBJECT_HANDLE        hKey;       /**< Handle to the key
                                                public object*/
    CK_OBJECT_HANDLE        hCert;      /**< Handle to the certificate object
                                             associated with the key.*/
} PKCS11_KEY_INFO;


/** \brief Attribute accessor macro.
 *  
 *  \param ATTRIBUTE The wanted attribute PKCS11 name.
 *  \param TYPE The type of the wanted attribute.
 *
 *  \ingroup SSpecific
 *  \return NULL if the attribute is not accessible for some raison, if the
 *          attribute has been retrieved, pointer to the value is returned.
 */
#define PATTRIBUTE_FUNCTION_MACRO(ATTRIBUTE, TYPE) \
TYPE * get##ATTRIBUTE(CK_FUNCTION_LIST_PTR p11, PROV_CTX *pProvCtx, \
                      CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) \
{ \
    CK_ATTRIBUTE    attribute = { CKA_##ATTRIBUTE, NULL, 0 }; /**< Wanted 
                                                                attribute
                                                                template*/ \
    CK_RV           rv; /**< C_GetAttributeValue return value.*/ \
    PKCS11_SERVICE_INFO *hServiceInfo = NULL; /**< Pointer to the key information
                                           structure.*/\
    hServiceInfo = (PKCS11_SERVICE_INFO *) pProvCtx->container.hServiceInformation; \
    /** - Get the object #ATTRIBUTE value size.*/ \
    rv = p11->C_GetAttributeValue(hServiceInfo->hSession, obj,\
                                  &attribute, 1); \
    if (rv != CKR_OK)\
    {\
        return NULL;\
    }\
    /** - Allocate space for the object ##ATTRIBUTE size in the attribute 
     * template. Add one for the Lord... No, only for the \0... Same thing ?*/ \
    attribute.pValue = HeapAlloc(pProvCtx->heap, HEAP_ZERO_MEMORY, \
                                 attribute.ulValueLen +1); \
    if(attribute.pValue == NULL)\
    {\
        return NULL;\
    }\
    /** - Get the object ##ATTRIBUTE. */ \
    rv = p11->C_GetAttributeValue(hServiceInfo->hSession, obj,\
                                  &attribute, 1);\
    if (rv != CKR_OK)\
    {\
        return NULL;\
    }\
    /** - If pointer to attribute count given, fill the pointed ULONG by the
     * number of gotten attributes.*/\
    if(pulCount)\
    {\
        *pulCount = attribute.ulValueLen / sizeof(TYPE);\
    }\
    /** - Return pointer to the goten attribute(s). */ \
    return (TYPE *)attribute.pValue;\
}

/** \brief TRUE is the key object can be used to crypt data.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object can be used to encrypt data.
 */
BOOL keyObjectCanEncrypt(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);

/** \brief TRUE is the key object can be used to decrypt data.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object can be used to decrypt data.
 */
BOOL keyObjectCanDecrypt(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);

/** \brief TRUE is the key object can be exported.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object can be exported.
 */
BOOL keyObjectIsExportable(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);

/** \brief TRUE is the key object parameters can be read.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the derivated key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object parameters can be read.
 */
BOOL keyObjectParametersCanBeRead(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);

/** \brief TRUE is the key object parameters can be set.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the derivated key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object parameters can be set.
 */
BOOL keyObjectParametersCanBeSet(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);

/** \brief TRUE is the key object can be used to sign data.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the derivated key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object can be used to sign data.
 */
BOOL keyObjectCanSign(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);

/** \brief TRUE is the key object can be used with MACs.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  phKey   Pointer to the handle of the derivated key.
 *
 *  \ingroup SHelper
 *  \return  True if the key object can be used with MACs.
 */
BOOL keyObjectCanBeUsedWithMAC(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey);


/** \brief Open an existing key container.
 *  
 *  If container name is not null,
 *  Each {} is max 32 characters long.
 *  Following the container name:
 *  {token label}-{SigKey object ID}-{Sigpublic keys
 *  label}-{SigMD5 hash}-{KX Key object ID}-{KX public key label}-{KX MD5 Hash}
 *  - Try to find a card labeled 'token label'.
 *  - Get the object id {Key object ID} & label {public key label}.
 *  - Compute the key modulus hash, and compare it.
 *  - If the same, we have our key.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  
 *  \return TRUE if a container is opened; FALSE if not, more in the
 *          last error.
 *          - NTE_KEYSET_NOT_DEF: No corresponding container.
 *          - NTE_BAD_KEYSET:   Bad container (may exists, but cannot open it.).
 *
 *  \ingroup SInterface
 */
BOOL openContainer(PROV_CTX *pProvCtx);

/** \brief Destroy handler to key pair.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  hKey    Handler to the key pair information.
 *  
 *  \return TRUE if keys are destroyed; FALSE if not, more in the
 *          last error.
 *
 *  \ingroup SInterface
 */
BOOL destroyKeys(PROV_CTX *pProvCtx, HANDLE hKeyInformation);

/** \brief Extract in a raw blob a key.
 *
 *  \param  pProvCtx pointer to the actual csp-eleven context.
 *  \param  hKeyInformation    handler to the key pair information.
 *  \param  pBlob      address where the key will be stored. if null, the
 *                     pbloblen is filled with the length of key blob.
 *  \param  pBlobLen    pointer to the blob length. 
 *  
 *  
 *  \return TRUE if key is exported.
 *
 *  \ingroup SInterface
 */
BOOL extractKeyModulus(PROV_CTX *pProvCtx, HANDLE hKeyInformation,
                      LPBYTE pBlob, LPDWORD pBlobLen);

/** \brief extract in a blob a session key.
 *
 *  \param  pProvCtx pointer to the actual csp-eleven context.
 *  \param  hKeyInformation    handler to the key pair information.
 *  \param  pBlob      address where the public key will be stored. if null, the
 *                     pbloblen is filled with the length of public key blob.
 *  \param  pBlobLen    pointer to the blob length. 
 *  \param  hPubKeyInformation    handler to the public key information.
 *  
 *  
 *  \return TRUE if key is exported.
 *
 *  \ingroup SInterface
 */
BOOL extractCryptedKey(PROV_CTX *pProvCtx, HANDLE hKeyInformation,
                      LPBYTE pBlob, LPDWORD pBlobLen, 
                      HANDLE hPubKeyInformation);

/** \brief Get the public exponent of the RSA key.
 *
 *  \param  pProvCtx pointer to the actual csp-eleven context.
 *  \param  hKeyInformation    handler to the key pair information.
 *  \param  pPubExp         Address where the public exponent will be copied.
 */
BOOL getPublicExponent(PROV_CTX *pProvCtx, HANDLE hKeyInformation, 
                       DWORD *pPubExp);

/** \brief Generate a key pair.
 *
 *  Difference between signature and key-exchange keys is the same that the
 *  difference between certificate with or without non-repudation bit. OMHO.
 *  Romain.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param modulusBits  Key Size (768, 1024, 2048)
 *  \param phKey    Pointer to the crypto handle to the key pair.
 *  \param algId    The CAPI algId.
 *
 *  \return TRUE if key pair has been generated.
 *  \ingroup SInterface
 */
BOOL genKeyPair(PROV_CTX *pProvCtx, CK_ULONG modulusBits, 
                HANDLE *phKeyInformation, ALG_ID algId);


/** \brief Get the CAPI Algorithm ID of a key.
 *
 *  \param pProvCtx Pointer to the actual CSP-eleven context.
 *  \param hKey Handle to the key.
 *  \param algId    Pointer to where the Alg ID will be stored.
 *  \param dwKeySpec The CAPI key specification.
 *
 *  \ingroup SInterface
 *  \return TRUE if the key has a supported ALG_ID, FALSE if not.
 */
BOOL getKeyAlgId(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey, ALG_ID *algId,
                 DWORD dwKeySpec);

/** \brief Get the key modulus.
 *
 *  \param pProvCtx Pointer to the actual CSP-eleven context.
 *  \param hKey Handle to the key.
 *  \param keyModulus  Address where the returned key value will be written,
 *  \ingroup    SHelper
 *  \return             TRUE if keyModulus is filled.
 */
BOOL getKeyModulus(PROV_CTX *pProvCtx, HCRYPTKEY hKey, 
                    DWORD *keyModulus);

/** \brief Get the key modulus length.
 *
 *  \param pProvCtx Pointer to the actual CSP-eleven context.
 *  \param hKeyInformation Handle to the key.
 *  \param keyModulusLength  Address where the returned key value will be written,
 *  \ingroup    SHelper
 *  \return             TRUE if keyModulusLength is filled.
 */
BOOL getKeyModulusLength(PROV_CTX *pProvCtx, HANDLE hKeyInformation, 
                    DWORD *keyModulusLength);

/** \brief Get the key permissions.
 *
 *  \param pProvCtx Pointer to the actual CSP-eleven context.
 *  \param hKey Handle to the key.
 *  \param keyPermissions  Address where the returned key permissions will be written,
 *  \ingroup    SHelper
 *  \return             TRUE if keyPermissions is filled.
 */
BOOL getKeyPermissions(PROV_CTX *pProvCtx, HCRYPTKEY hKey, 
                    DWORD *keyPermissions);

/** \brief Get the value off an key.
 *
 *  \param pProvCtx Pointer to the actual CSP-eleven context.
 *  \param hKey Handle to the key.
 *  \param keyValue  Address where the returned key value will be written,
 *                      If NULL, the valueLenth is filled with the value lenth
 *                      in byte.
 *  \param valueLenth   Address where the key value lenth will be filled if
 *                      keyValue is NULL, or address where the lenth of the
 *                      allocated keyValue is stored. In Bytes.
 *  \ingroup    SHelper
 *  \return             TRUE if valueLenth is filled or if keyValue is filled
 *                      the specified key value.
 *                      FALSE if the valueLenth is less than the key value
 *                      lenth.
 */
BOOL getKeyValue(PROV_CTX *pProvCtx, HCRYPTKEY hKey, 
                    BYTE *keyValue, DWORD *valueLenth);



/** \brief Load existing keys into her container.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  pKeyInfo Pointer to a initialized CSP11 key information structure.
 *  
 *  \return TRUE if keys are loaded; FALSE if not, more in the
 *          last error.
 *          - NTE_BAD_KEYSET:   Bad container (may exists, but cannot open it.).
 *
 *  \ingroup SInterface
 */
BOOL loadUserKey(PROV_CTX *pProvCtx, KEY_INFO *pKeyInfo);

/** \brief Release crytographic context. 
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *
 *  \return TRUE if context is released.
 *  \ingroup SInterface
 */
BOOL releaseContext(PROV_CTX *pProvCtx);

/** \brief Sign the supplied data.
 *
 *  If the pSignature pointer is NULL, the DWORD pointed by pSignatureLen is
 *  filled with the number of bytes used by the signature data.
 *  If the pSignature pointer is not NULL, it is interpreted as a allocated
 *  space of *pSignatureLen bytes for storing the signature.
 *  
 *  \param  pProvCtx        Pointer a CSP-eleven context.
 *  \param  hKeyInformation The handle to the Key to use.
 *  \param  pData           The data to sign.
 *  \param  dataLen         The lenth of the data to sign.
 *  \param  pSignature      Pointer to the data buffer to use.
 *  \param  pSignatureLen   Pointer a DWORD of the signature lenth.
 *
 *  \return FALSE if something went wrong, TRUE if everything went ok. The
 *          detail of error is set in SetLastError:
 *          - ERROR_MORE_DATA: The pSignatureLen is too small.
 */
BOOL simpleSignData(PROV_CTX *pProvCtx, KEY_INFO* keyInfo, BYTE *pData, DWORD dataLen,
              BYTE *pSignature, DWORD *pSignatureLen);

/** \brief Set the instance to use for Windows UI.
 *
 *  \param csphInstance Handle to the CSP DLL instance.
 *
 *  \return TRUE if the instance is set, FALSE if the given parameter is NULL.
 */
BOOL setCSPInstance(HINSTANCE csphInstance);

/** \brief Fill container information structure.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  slotId  The slot id containing the smart card, or CSP key container
 *                  to add to the context.
 *
 *  \todo   Code a graphical UI for PIN entry.
 *  \warning    Insecure PIN code enter scheme. See todo to know what is planned
 *              to fix this security hole.
 *
 *  \return TRUE if a corresponding slot is found; FALSE if not, more in the
 *          last error, slotId set to the last visited slot.
 *
 *  \return Last error set to NTE_BAD_KEYSET_PARAM is the slot ID contains no
 *          key container.
 *  \ingroup SSpecific
 */
BOOL PKCS11_addContainer(PROV_CTX *pProvCtx, CK_SLOT_ID slotId);

/** \brief Close a card session.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *
 *  \return TRUE if the session is closed.
 *  \ingroup SSpecific
 */
BOOL PKCS11_closeSession(PROV_CTX *pProvCtx);

/** \brief Create a PKCS #11 secret key object.
 *
 *  The csp11 algorithm definition structure is passed, translated to PKCS #11
 *  data in order to create the object.
 *  Value is read from value if not NULL or valueLen is different from zero.
 *  If the value lenth is less than the key lenth specified in the keyAlg
 *  parameter, there is an error.
 *
 *  The created key is designed to be a session key (so symetric).
 *  
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  keyAlg  The key object algorithm to use.
 *  \param  keyObject Pointer to the created key object.
 *  \param  value   Pointer to the key value to use.
 *  \param  valueLen Lenth of the key value.
 *
 *  \ingroup SSpecific
 *  \return TRUE if the key object was successfuly created. FALSE if not.
 */
BOOL PKCS11_createSessionKeyObject(PROV_CTX *pProvCtx, ALGORITHM keyAlg,
                            CK_OBJECT_HANDLE *pKeyObject,
                            CK_BYTE *value, DWORD valueLen);

/* \brief Destroy keys information structure. 
 *
 *  \param  provCtx The actual CSP-eleven context.
 *  \param  hKey    Handle to the key pair.
 *
 *  \return TRUE if the key are created; FALSE if not, more in the
 *          last error,
 *
 *  \ingroup SSpecific
 */
/*BOOL PKCS11_destroyKeys(PROV_CTX *pProvCtx, HCRYPTKEY hKey);*/

/** \brief Initialize PKCS #11 Library.
 *
 *  \param  provCtx The actual CSP-eleven context.
 *  \param  slotId  The founded slot id.
 *
 *  \return TRUE if a corresponding slot is found; FALSE if not, more in the
 *          last error, slotId set to the last visited slot.
 *          - NTE_NO_MEMORY: No memory available for container memory allocation.
 *  \ingroup SSpecific
 */
BOOL PKCS11_findSlot(PROV_CTX provCtx, CK_SLOT_ID *slotId);

/** \brief Generate RSA token key pair.
 * 
 *  \param  pProvCtx The actual CSP-eleven context.
 *  \param  modulusBits Modulus length.
 *  \param  phPublicKey Pointer to the PKCS #11 handle to the public key object.
 *  \param  phPrivateKey Pointer to the PKCS #11 handle to the private key object.
 *
 *  \return TRUE if keys have been generated.
 *  \ingroup SSpecific
 *
 */
BOOL PKCS11_genKeyPair(PROV_CTX *pProvCtx, CK_ULONG modulusBits,
                       CK_OBJECT_HANDLE **phPublicKey, CK_OBJECT_HANDLE
                       **phPrivateKey);

/** \brief Get the value off an PKCS #11 object.
 *
 *  \param pProvCtx Pointer to the actual CSP-eleven context.
 *  \param hObject Handle to the PKCS #11 object.
 *  \param objectValue  Address where the returned object value will be written,
 *                      If NULL, the valueLenth is filled with the value lenth
 *                      in byte.
 *  \param valueLenth   Address where the object value lenth will be filled if
 *                      objectValue is NULL, or address where the lenth of the
 *                      allocated objectValue is stored. In Bytes.
 *  \return             TRUE if valueLenth is filled or if objectValue is filled
 *                      the specified object value.
 *                      FALSE if the valueLenth is less than the object value
 *                      lenth.
 */
BOOL PKCS11_getObjectValue(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hObject, 
                    BYTE *objectValue, DWORD *valueLenth);

/** \brief Get key suitable to sign data.
 *
 *  \param provCtx          Provider context.
 *  \param  hPubKeyObject    Handle to the Key associated to the wanted key. If this key is
 *                          suitable for signing, it will be used.
 *  \param  hSignatureKey    Address where the PKCS #11 handle to the signature
 *                          key will be stored.
 *  \return TRUE if a signature key has been found, FALSE if not.
 */
BOOL PKCS11_getSignatureKey(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hPubKeyObject, DWORD dwKeySpec,
                     CK_OBJECT_HANDLE *hSignatureKey);

/** \brief Compute the signature length.
 *
 *  It is used because as said in the mozilla crypto library, there are some bad
 *  PKCS11 DLL that do not return modulus length (and modulus length == length
 *  of a digital signature). We can think about getModulusLength too, but here,
 *  this is a security :-).
 *  So we compute a useless signature, useless, but this way, we have the
 *  signature length.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  signatureKey   PKCS#11 Handle to the signature key.
 *  \param  pSignatureLen   Address where the signature length will be stored.
 */
BOOL PKCS11_getSignatureLen(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey, 
                            DWORD *pSignatureLen);

/** \brief Initialize PKCS #11 Library.
 *
 *
 *  \return TRUE if the functions list is acquired; FALSE if not, more in the
 *          last error, p11 set to NULL.
 *  \ingroup SSpecific
 */
BOOL PKCS11_initialize();

/** \brief Load *existing* keys into context key information structure. 
 *
 *  Find a public/private key pair and add it to the context.
 * 
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param phKey    Pointer to the crypto handle to the key pair.
 *  \param  dwKeySpec CAPI key specification.
 *
 *  \return TRUE if the key are loaded; FALSE if not, more in the
 *          last error,
 *          - NTE_BAD_KEYSET: The key pair was not found or worse.
 *
 *  \ingroup SSpecific
 */
BOOL PKCS11_loadUserKey(PROV_CTX *pProvCtx,
                        PKCS11_KEY_INFO *pKeyInformation,
                        DWORD dwKeySpec);

/** \brief Log into the token.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  hServiceInfo The PKCS#11 session information structure.
 *  \param  dwKeySpec   Requested key usage specification.
 *  \param  pp_pin    pin code
 *
 *  If hInst or pProvCtx->uiHandle is NULL, no GUI. If pp_pin NULL, ask with GUI.
 *
 *  \return TRUE if the user log in.
 */
BOOL PKCS11_LogIn(PROV_CTX *pProvCtx, PKCS11_SERVICE_INFO *hServiceInfo,
                  char *pp_pin, DWORD keySpec);

/** \brief Log out from the token.
 *
 *  \param  hServiceInfo    Handle to the card info structure.
 *
 *  \ingroup SSpecific
 *  \return TRUE if user is logged out.
 */
BOOL PKCS11_logout(PKCS11_SERVICE_INFO *hServiceInfo);

/** \brief Open a session on the smart card. 
 *
 *  \param slotId  The container slot id.
 *  \param hKeyInfo Pointer to the corresponding key information structure.
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *
 *  \return TRUE if the session is opened; FALSE if not, more in the
 *          last error,
 *          - NTE_BAD_KEYSET: The session has not been successfuly opened.
 *  \ingroup SSpecific
 */
BOOL PKCS11_openSession(CK_SLOT_ID slotId, PKCS11_SERVICE_INFO *hKeyInfo, PROV_CTX *pProvCtx);


/** \brief Acquire a R/W user functions session state.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *
 *  \return TRUE if the RW access is granted; FALSE if not, more in the
 *          last error,
 *  \ingroup SSpecific
 */
BOOL PKCS11_rwUserFnSession(PROV_CTX *pProvCtx, DWORD keySpec);

/** \brief  Fill the signature key pair structure.
 *
 *  \param  pProvCtx Pointer to the actual CSP-eleven context.
 *  \param  publicKey    The public part of the pair.
 *  \param  certificate  Associated certificate.
 *  \param  pSigKey     Pointer to the signature key pair structure.
 *  \return TRUE The structure is valide. FALSE if not.
 *
 *  \ingroup SSprecific
 */
BOOL fillP11Key(PROV_CTX* pProvCtx,
                   CK_OBJECT_HANDLE publicKey, CK_OBJECT_HANDLE certificate, PKCS11_KEY_INFO *pKeyInfo);

/** \brief Sign the supplied data.
 *
 *  If the pSignature pointer is NULL, the DWORD pointed by pSignatureLen is
 *  filled with the number of bytes used by the signature data.
 *  If the pSignature pointer is not NULL, it is interpreted as a allocated
 *  space of *pSignatureLen bytes for storing the signature.
 *  
 *  \param  pProvCtx        Pointer a CSP-eleven context.
 *  \param  hKey            The handle to PKCS11 object Key to use.
 *  \param  pData           The data to sign.
 *  \param  dataLen         The lenth of the data to sign.
 *  \param  pSignature      Pointer to the data buffer to use.
 *  \param  pSignatureLen   Pointer to the signature lenth.
 *
 *  \return FALSE if something went wrong, TRUE if everything went ok. The
 *          detail of error is set in SetLastError:
 *          - ERROR_MORE_DATA: The pSignatureLen is too small.
 */
BOOL PKCS11_simpleSignData(PROV_CTX *pProvCtx, CK_OBJECT_HANDLE hKey, DWORD dwKeySpec, BYTE *pData, DWORD dataLen,
              BYTE *pSignature, DWORD *pSignatureLen);

/** \brief Extract token label, and keys label, id and md5 from container Name.
 *
 *  \param  cName container name
 *  \param  containerInfo Container information from container name.
 *
 *  \return TRUE if the label are extracted.
 */
BOOL extractLabels(LPCSTR cName, PKCS11_CONTAINER_INFO *containerInfo);


/** \brief Validate key echange PIN.
 *  
 *  \param  provCtx The provider context.
 *  \param  pin The Personnal Identification Number to validate.
 *  
 *  \return TRUE if the PIN validates.
 */
BOOL validateKeyExchangePin(PROV_CTX provCtx, char *pin);

/** \brief Validate signature PIN.
 *  
 *  \param  provCtx The provider context.
 *  \param  pin The Personnal Identification Number to validate.
 *  
 *  \return TRUE if the PIN validates.
 */
BOOL validateKeySigPin(PROV_CTX provCtx, char *pin);

BOOL extractKeyCertificate(PROV_CTX *pProvCtx, HANDLE hKeyInformation,
                      LPBYTE pBlob, LPDWORD pBlobLen);

void AddPinToCache(CK_SLOT_ID slotID, const char* pin);
BOOL GetPinFromCache(CK_SLOT_ID slotID, char* pin);
void ClearPinFromCache(CK_SLOT_ID slotID);


BOOL UpdateState(); /* return FALSE if no PC/SC context is available */
BOOL IsValidContext(PROV_CTX* pProvCtx);
void InvalidatePIN(PROV_CTX* pProvCtx);

#endif // _PKCS11_SERVICES_H_

