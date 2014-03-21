/** \file csp11.h
 * $Id: csp11.h 259 2005-03-17 16:06:25Z rchantereau $ 
 *
 * CSP #11 -- Cryptographic Service Provider PKCS #11.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  This file declares and documents all the necessary function and type for
 *  CSP-eleven.
 *  The documentation written here is used by documentation manager.
 * 
 * \author  Romain Chantereau <rchantereau@entrouvert.com>
 * \author  Fabio Petagna <fabpet@gmail.com> who gave us the MD2 OID header.
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
 *
 */


/** \defgroup   SPInternal Service Provider internal functions.
 *
 *  Theses functions are used for internal purpose.
 */

/** \defgroup   SPFunctions Service Provider functions.
 *
 * Theses functions are directly related to operational operation on the service
 * provider. They permit to set it up, create and destroy it.
 */

/** \defgroup   KeyGenEx    Key Generation and exchange functions
 *
 *  Theses functions permit generation and exchange of session key or key pair.
 *  They extend the Microsoft® Base Cryptographic Provider functions.
 */

/** \defgroup   HashSign    Hashing and Digital Signature functions
 *
 * Theses functions permit creation, set up and generation of hash and digital
 * signature.
 */

/** \defgroup   DataEnc Data encryption functions
 *
 * Theses functions permit to crypt and decrypt data.
 */

#ifndef _CSP11_H_

#define _CSP11_H_       /**< csp11.h inclusion tag. */
#ifdef __cplusplus
extern "C" {
#endif


class CLocker
{
public:
    CLocker(CRITICAL_SECTION& cs) : m_cs(cs)
    {
        EnterCriticalSection(&m_cs);
    }

    ~CLocker()
    {
        LeaveCriticalSection(&m_cs);
    }

protected:
    CRITICAL_SECTION& m_cs;
};

// PIN cache handling
typedef struct
{
    CK_SLOT_ID slotID;
    char ExchPin[65];
} PIN_CACHE;

/********************** CSP-ELEVEN DECLARATION ************************/

#define SC_CONTAINER    0   /**< The container is a smart card. */
#define EPHE_CONTAINER  1   /**< The container is ephemeral. (VERIFY_CONTEXT
                                 for example). */
#define INVALID_CONTAINER 2 /**< Invalid container.*/

#define CSP_NAME    "Oberthur LATVIA-EID CSP"        /**< The csp name.*/
#define CSP_VERSION 0x00000200     /**< CSP Version number.*/

//
// Callback prototypes
//

typedef BOOL (WINAPI *CRYPT_VERIFY_IMAGE_A)(LPCSTR  szImage, CONST BYTE *pbSigData);
typedef BOOL (WINAPI *CRYPT_VERIFY_IMAGE_W)(LPCWSTR szImage, CONST BYTE *pbSigData);
typedef void (WINAPI *CRYPT_RETURN_HWND)(HWND *phWnd);

typedef struct _VTableProvStruc {
    DWORD                Version;
    CRYPT_VERIFY_IMAGE_A FuncVerifyImage;
    CRYPT_RETURN_HWND    FuncReturnhWnd;
    DWORD                dwProvType;
    BYTE                *pbContextInfo;
    DWORD                cbContextInfo;
    LPSTR                pszProvName;
} VTableProvStruc,      *PVTableProvStruc;

typedef struct _VTableProvStrucW {
    DWORD                Version;
    CRYPT_VERIFY_IMAGE_W FuncVerifyImage;
    CRYPT_RETURN_HWND    FuncReturnhWnd;
    DWORD                dwProvType;
    BYTE                *pbContextInfo;
    DWORD                cbContextInfo;
    LPWSTR               pszProvName;
} VTableProvStrucW,     *PVTableProvStrucW;

typedef struct {
    DWORD dwVersion;
    DWORD dwCrcOffset;
    BYTE rgbSignature[88];  // 1024-bit key, plus 2 DWORDs of padding.
} InFileSignatureResource;


/** \brief Public key BLOB
 *
 *  This is the representation of the MS C base provider public key BLOB.
 *  \ingroup SPInternal
 */
typedef struct _RSAPUBLICKEY_BLOB {
    PUBLICKEYSTRUC  publicKeyStruc; /**< The blob header.*/
    RSAPUBKEY       rsaPubKey;      /**< The rsa public key description.*/
    BYTE            *modulus;       /**< The key modulus.*/
} RSAPUBLICKEY_BLOB;

/** \brief Key container structure.
 *
 *  This a representation of the smartcard keys (exchange and signature).
 *  \ingroup    SPInternal
 */
typedef struct _CONTAINER {
    LPSTR cName;       /**<  Key container name in C string format */
    LPSTR cOtherContainerName;
    LPSTR cReaderName;
    DWORD dwFlags; /**< Flags values. Can be zero or the following flags,
                                            - CRYPT_VERIFYCONTEXT,
                                            - CRYPT_NEWKEYSET,
                                            - CRYPT_MACHINE_KEYSET,
                                            - CRYPT_DELETEKEYSET,
                                            - CRYPT_SILENT. */
    DWORD   dwContainerType;    /**< The container type, one of the following value:
                                        - SC_CONTAINER,
                                        - EPHE_CONTAINER.
										- INVALID_CONTAINER
                                        */
    HANDLE    hServiceInformation;  /**< dwContainerType specific information.*/
    
} CONTAINER;

/** \brief Provider context.
 *
 * This structure permits handling of multiple client.
 *
 * Each client has a provider context attached to him.
 *
 * A client can be ether a program than to part of a same programm.
 *  \ingroup    SPInternal
 */
typedef struct _PROV_CTX {
	DWORD dwProvType;             /**<  Provider Type. CSP-eleven is a FULL RSA Provider (0x01) */
	HANDLE containerHnd;                /**< Handle to the container which is using this context. */
    HANDLE heap;        /**< The handle to the allocated heap.*/
	CONTAINER container;    /**< The selected key container. */
    unsigned long currentAlg;   /**< The latest enumerated alg (CPGetProvParam with PP_ENUMFLAGS) */
    unsigned long currentContainer; /**< The latest enumerated container (CPGetProvParam with PP_ENUMCONTAINERS) */
    BOOL    silent;        /**< If set, no UI is to be used.*/
    HWND    uiHandle;       /**< Windows handle to interact with the user.*/
    HCRYPTPROV hMSProv;
} PROV_CTX;

/** \brief Hash information
 *
 *  This structure is an attenmpts to gather all necessary information in order
 *  to handle a hash.
 *
 *  If the feeded data are not gathered, it is because, the data length can be
 *  as length as a unsigned double value !
 *  And double variables and memory pointers are not so friend as we can think...
 *
 */
typedef struct _HASH_INFO {
    ALG_ID              Algid;   /**< Used Hash mechanism.*/
    HCRYPTHASH          hMSHash; /* handle to the MS CSP hash */
    BYTE *        oid;    /**< The hash algorithm OID.*/
    DWORD         oidLen;    /**< The hash algorithm OID length in bytes.*/
} HASH_INFO;

/** \brief Key information
 *
 *  This structure is an attenmpts to gather all necessary information in order
 *  to handle a key.
 *
 *  A '-1' or NULL value means 'unset'.
 */
typedef struct  _KEY_INFO {
    ALG_ID              algId;  /**< Used key algId.*/
    DWORD           dwKeySpec;  /**< The key usage specification (signature or
                                     key exchange.*/
    DWORD            blockLen;  /**< Granularity of a key pair. For RSA, that
                                     means modulus. In bits.*/
    DWORD              length;  /**< The total key length in bits, without any other
                                     data (like parity bits).*/
    DWORD             saltLen;  /**< Key salt value length in Bytes (salt_ex).*/
    BYTE                *salt;  /**< Key salt value.*/
    DWORD         permissions;  /**< CAPI key permissions.*/
    DWORD               ivLen;  /**< Length of initialisation vector. Depends on
                                     Alg and mode. In Bytes.*/
    BYTE                  *iv;  /**< Initialisation vector.*/
    DWORD             padding;  /**< Padding method. Only PKCS #5 method used
                                     (PKCS5_Padding).*/
    DWORD                mode;  /**< Used cipher mode, if applicable one of:
                                     - CRYPT_MODE_ECB,
                                     - CRYPT_MODE_CBC,
                                     - CRYPT_MODE_OFB,
                                     - CRYPT_MODE_CFB.*/
    DWORD                fLen;  /**< If mode is OFB or CFB, feedback length in
                                     bits.*/
    DWORD        effectiveLen; /**< if key use RC2 algorithm, effective
                                    key length in bits.*/
    HANDLE    hKeyInformation;  /**< dwContainerType specific information.*/
    BYTE * oid;       /**< The Key alg OID.*/
    CK_OBJECT_HANDLE hPubKey;
    CK_OBJECT_HANDLE hCertKey;
    BYTE             keyId[64];
    CK_ULONG         keyIdLen;

} KEY_INFO;

/** \brief Algorithm helper structure.
 *
 *  Special thanks to the OpenCSP, this is a copy/paste.
 */
typedef struct _ALGORITHM {
    ALG_ID  algId;  /**< The Algorithm ID.*/
    DWORD   dwBits; /**< Algorithm default key lenth.*/
    char *cName; /**< Algorith Name.*/
    char *cLongName; /**< Algorith Name.*/
    DWORD   dwMinBits; /**< Algorithm minimal length.*/
    DWORD   dwMaxBits;  /**< Algorithm maximal length.*/
    BYTE    *oid; /**< Algorithm OID.*/
    DWORD   oidLen; /**< Algorithm OID length.*/
} ALGORITHM;

#define MD2_NAME "MD2"
#define MD2_LONG_NAME "Message Digest 2 (MD2)"
#define MD2_MIN_BITS 128
#define MD2_MAX_BITS 128
#define MD2_BITS 128
#define MD2_OID "\x30\x20\x30\x0C\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02\x05\x00\x04\x10"
#define MD5_NAME "MD5"
#define MD5_LONG_NAME "Message Digest 5 (MD5)"
#define MD5_BITS 128
#define MD5_MIN_BITS 128
#define MD5_MAX_BITS 128
#define MD5_OID "\x30\x20\x30\x0C\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05\x05\x00\x04\x10"
#define MD5_OID_LEN 18
#define SHA_NAME "SHA-1"
#define SHA_LONG_NAME "Secure Hash Algorithm (SHA-1)"
#define SHA_BITS 160
#define SHA_MIN_BITS 160
#define SHA_MAX_BITS 160
#define SHA1_OID "\x30\x21\x30\x09\x06\x05\x2b\x0E\x03\x02\x1A\x05\x00\x04\x14"  
#define SHA1_OID_LEN    15 
#define SHA256_NAME "SHA-256"
#define SHA256_LONG_NAME "Secure Hash Algorithm 256 (SHA-256)"
#define SHA256_BITS 256
#define SHA256_MIN_BITS 256
#define SHA256_MAX_BITS 256
#define SHA256_OID "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
#define SHA256_OID_LEN    19 
#define SSL3_SHAMD5_NAME "SSL3 SHAMD5"
#define SSL3_SHAMD5_LONG_NAME "SSL3 SHAMD5"
#define SSL3_SHAMD5_BITS 288
#define SSL3_SHAMD5_MIN_BITS 288
#define SSL3_SHAMD5_MAX_BITS 288
#define SSL3_SHAMD5_OID ""
#define SSL3_SHAMD5_OID_LEN    0
#define RSA_SIGN_NAME "RSA_SIGN"
#define RSA_SIGN_LONG_NAME "RSA Signature"
#define RSA_SIGN_MIN_BITS 512
#define RSA_SIGN_BITS 2048
#define RSA_SIGN_MAX_BITS 4096
#define RSA_KEYX_NAME "RSA_KEYX"
#define RSA_KEYX_LONG_NAME "RSA Key Exchange"
#define RSA_KEYX_MIN_BITS 512
#define RSA_KEYX_BITS 2048
#define RSA_KEYX_MAX_BITS 4096
#define DES_NAME "DES"
#define DES_LONG_NAME "Data Encryption Standard (DES)"
#define DES_MIN_BITS 56
#define DES_BITS 56
#define DES_MAX_BITS 56
#define DES3_112_NAME "3DES TWO KEY"
#define DES3_112_LONG_NAME "Two Key Triple DES"
#define DES3_112_MIN_BITS 112
#define DES3_112_BITS 112
#define DES3_112_MAX_BITS 112
#define DES3_NAME "3DES"
#define DES3_LONG_NAME "Three Key Triple DES"
#define DES3_MIN_BITS 168
#define DES3_BITS 168
#define DES3_MAX_BITS 168
#define RC2_NAME "RC2"
#define RC2_LONG_NAME "RSA Data Security's RC2"
#define RC2_MIN_BITS 128
#define RC2_BITS 128
#define RC2_MAX_BITS 128
#define RC4_NAME "RC4"
#define RC4_LONG_NAME "RSA Data Security's RC4"
#define RC4_MIN_BITS 128
#define RC4_BITS 128
#define RC4_MAX_BITS 128

#define ALG_COUNT  11   /**< Number of supported algorithm.*/


/** \brief Acquire a context handle to the PKCS #11 CSP.
 *
 *  
 *  The handle is then used to call the CSP-eleven and the card container
 *  container that holds key and certificate files.
 *
 *  A heap is allocated by context, the size of the heap is initialy set to the
 *  size of a context structure. The allocated heap is growable.
 *
 *
 *  \param  phProv      Handle to CSP-eleven.
 *  \param  szContainer Key container name.
 *                      The function ignores this parameter if 
 *                      CRYPT_VERIFYCONTEXT is set in dwFlags.
 *                      The cryptographic token is a key container, so this 
 *                      C string is the requested token (container) label.
 *  \param  dwFlags     Flags values. Can be zero or the following flags,
 *                      - CRYPT_VERIFYCONTEXT:
 *                          Only card public data can be accessed.
 *
 *                      - CRYPT_NEWKEYSET,
 *                      - CRYPT_MACHINE_KEYSET:
 *                          No information is cached by the CSP.
 *                          
 *                      - CRYPT_DELETEKEYSET,
 *                      - CRYPT_SILENT:
 *                          Suppress PIN dialog box. PIN must be send by the
 *                          progam.
 *                          
 *  \param  pVTable     Pointer to a VTableProvStruc structure containing a
 *                      list of callback functions provided by the operating 
 *                      system for use by the CSP.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    SPFunctions
 *
 *  \return   NTE_BAD_SIGNATURE 	The digital signature of an auxiliary DLL did 
 *          not verify correctly. Either the DLL or the digital signature has
 *          been tampered with.
 *
 *  \return   NTE_EXISTS 	The dwFlags parameter is CRYPT_NEWKEYSET, but the key container already exists.
 *  
 *  \return   NTE_KEYSET_ENTRY_BAD 	The pszContainer key container was found but is corrupt.
 *  
 *  \return   NTE_KEYSET_NOT_DEF 	The key container specified by pszContainer does not exist.
 *  
 *  \return   NTE_PROVIDER_DLL_FAIL 	An auxiliary DLL file could not be loaded and might not exist.
 *                                      If it exists, the file is not a valid DLL.
 *
 */
BOOL WINAPI
CPAcquireContext(
    OUT HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable);


/** \brief  Releases the handle to the CSP-eleven, closing access to the 
 *          card's key container.
 *          
 *  \param  hProv   Handle to the CSP-evelen.
 *  \param  dwFlags Reserved for Future Use.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *  
 *  \ingroup    SPFunctions
 *
 *  \return   - NTE_BAD_FLAGS 	The value of the dwFlags parameter is invalid.
 *          
 *  \return   - NTE_BAD_UID 	The context specified by hProv is invalid.
 *
 *  \note   After this function has been executed, the hProv handle 
 *          becomes invalid. All session keys and hash objects previously 
 *          created by using the hProv handle can be destroyed at this time.
 *          Ideally, the application already did this using CryptDestroyKey and
 *          CryptDestroyHash, but a CSP cannot depend upon the keys and
 *          hashes being destroyed.
 *  
 */
BOOL WINAPI
CPReleaseContext(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags);


/** \brief Generate cryptographic session keys or keys pairs.
 * 
 *  The function generates both session keys (DES or 3DES keys)
 *  and RSA public/private key pairs for CSP-eleven operations. All keys
 *  are random numbers. The CSP does support both 1024-bit and 2048-bit RSA
 *  keys, and the default key size is 2048 bits.
 *  If the RSA key size is not specified, the CSP will select the largest key strength that is
 *  available on the card at the time.
 * 
 *  \param  hProv   Handle to the CSP-evelen.
 *  \param  Algid   Algorithm identifier. One of these: 
 *                  - AT_KEYEXCHANGE,
 *                  - AT_SIGNATURE,
 *                  - CALG_RC2,
 *                  - CALG_RC4,
 *                  - RC2 block cipher,
 *                  - RC4 stream cipher.
 *                  
 *  \param dwFlags  Flag(s) on the future keys, zero or one or more,
 *                  - Key size set with upper 16 bits representing modulus,
 *                  - CRYPT_CREATE_SALT,
 *                  - CRYPT_EXPORTABLE,
 *                  - CRYPT_NO_SALT,
 *                  - CRYPT_USER_PROTECTED.
 *
 *  \param phKey    Handle to the new key.
 *                  
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *  
 *  \ingroup    KeyGenEx
 *  
 *  \return   NTE_BAD_ALGID 	The Algid parameter specifies an algorithm that this CSP does not support.
 *  
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter contains an invalid value.
 *  
 *  \return   NTE_FAIL 	The function failed in some unexpected way.
 *  
 *  \return   NTE_BAD_UID 	The hProv parameter does not contain a valid context handle.
 *  
 *  \return   NTE_PERM 	An attempt was made to create a key pair when CRYPT_VERIFYCONTEXT was specified.
 *  
 *  \return   NTE_SILENT_CONTEXT 	Provider could not perform the action because the context was acquired as silent.
 *
 *  \return   An application cannot create new key pairs if no key container is currently open. This can happen if CRYPT_VERIFYCONTEXT was set in the CPAcquireContext call. If a key cannot be created, the NTE_PERM error code is returned.
 *
 *  \return   CPGenRandom is generally used to generate the random key material.
 *
 *  \return   Keys generated for symmetric block ciphers must be set up by default in cipher block chaining (CBC) mode with an initialization vector of zero. This cipher mode provides a good default method for bulk-encrypting data.
 *
 *  \sa These parameters are changed using the CPSetKeyParam() function.
 */

BOOL WINAPI
CPGenKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);


/** \brief Generate nonrandom session keys (DES or 3DES) from input data.
 *
 * Indentical input data mean identical session keys produced.
 *
 * The base data could be a password for example.
 *
 *  \param  hProv   Handle to the CSP-evelen.
 *  \param  Algid   Algorithm identifier. One of these: 
 *                  - CALG_RC2,
 *                  - CALG_RC4,
 *                  - RC2 block cipher,
 *                  - RC4 stream cipher.
 *                  
 *  \param hHash    Handle to the hash object using the base data.
 *  
 *  \param dwFlags  Flag(s) on the future keys, zero or one or more,
 *                  - CRYPT_CREATE_SALT,
 *                  - CRYPT_EXPORTABLE,
 *                  - CRYPT_NO_SALT,
 *                  - CRYPT_USER_PROTECTED.
 *
 *  \param phKey    Handle to the new key.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *  
 *  \ingroup    KeyGenEx
 *  
 *  \return   NTE_BAD_ALGID 	The Algid parameter specifies an algorithm that this CSP does not support.
 *  
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter contains an invalid value.
 *  
 *  \return   NTE_FAIL 	The function failed in some unexpected way.
 *  
 *  \return   NTE_BAD_UID 	The hProv parameter does not contain a valid context handle.
 *  
 *  \return   NTE_PERM 	An attempt was made to create a key pair when CRYPT_VERIFYCONTEXT was specified.
 *  
 *  \return   NTE_SILENT_CONTEXT 	Provider could not perform the action because the context was acquired as silent.
 *
 *  \note   
 *          - The CPDeriveKey function completes the hash of the hash object passed in as hBaseData. After CPDeriveKey has been called, no more data can be added to that hash object. Additional calls to CPHashData or CPHashSessionKey with that hash object fail. However, additional calls to CPDeriveKey, CPGetHashParam, CPSignHash, and CPVerifySignature use the completed hash object and succeed.
 *          - If CSP interoperability is important, session keys must be derived in the precise manner specified by the type of the CSP. For information on how the key derivation must be performed, see Deriving Session Keys.
 *          - If interoperability is not a concern, a CSP is free to derive session keys in any manner.
 *
 *  \sa CPCreateHash()
 *
 */

BOOL WINAPI
CPDeriveKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);


/** \brief Release the given key handle.
 *
 *
 * Releases and invalidates the handle referenced by the hKey parameter.
 * 
 *  \param  hProv   Handle to the CSP-evelen.
 *
 *  \param  hKey    Handle to the key to be destroyed.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    KeyGenEx
 *  
 * \return    NTE_BAD_KEY 	The hKey parameter does not contain a valid handle to a key.
 * 
 * \return    NTE_BAD_UID 	The hProv parameter does not contain a valid context handle.
 * 
 * \return    If the handle refers to a session key or to a public key imported into the CSP with CryptImportKey, this function destroys the key and frees the memory that the key occupied. A CSP typically overwrites the memory where the key was held before freeing it.
 * 
 * \return    On the other hand, if the handle refers to a public/private key pair (obtained from CryptGetUserKey), the underlying key pair is not destroyed by this function. Only the handle is destroyed.
 *
 *  \return   The memory where the key was held is scrubbed before the handle is freed.
 */

BOOL WINAPI
CPDestroyKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey);


/** \brief Customize operations of a key.
 *  
 *  The values set by this function are not persistent in memory and
 *  can only be used within a single session.
 *
 *
 *  \param  hProv   Handle to the CSP-eleven.
 *  \param  hKey    Handle to the key.
 *  \param  dwParam Parameter value, one of these:
 *                  - KP_CERTIFICATE
 *                  - KP_PERMISSIONS (defaults to FFFFFFFFh)
 *                  - KP_SALT (defaults to zero)
 *                  - KP_SALT_EX
 *                  In the case of a block cipher session key, use one of
 *                  these values:
 *                  - KP_EFFECTIVE_KEYLEN
 *                  - KP_IV (defaults to zero)
 *                  - KP_MODE (defaults to CRYPT_MODE_CBC)
 *                  - KP_MODE_BITS (defaults to 8)
 *                  - PK_PADDING (defaults to PKCS5_PADDING)
 *                  
 *  \param  pbData  Pointer to parameters data. This buffer will be filled with
 *                  dwParam corresponding data. The length is not set and must be
 *                  deduced from the dwParam parameter value.
 *  \param  dwFlags Flags values, always zero, RFU.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *  
 *  \ingroup    KeyGenEx
 *  
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero, or the pbData buffer contains an invalid value.
 *  \return   NTE_BAD_TYPE 	The dwParam parameter specifies an unknown parameter.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hKey key was created cannot now be found.
 *  \return   NTE_FAIL 	The function failed in some unexpected manner.
 *  \return   Permission flag 	Description
 *  \return   CRYPT_ENCRYPT 	Allows encryption.
 *  \return   CRYPT_DECRYPT 	Allows decryption.
 *  \return   CRYPT_EXPORT 	Allows the key to be exported.
 *  \return   CRYPT_READ 	Allows parameters to be read.
 *  \return   CRYPT_WRITE 	Allows parameters to be set.
 *  \return   CRYPT_MAC 	Allows MACs to be used with the key.
 *  \return   Cipher mode 	Description
 *  \return   CRYPT_MODE_ECB 	Electronic codebook.
 *  \return   CRYPT_MODE_CBC 	Cipher block chaining.
 *  \return   CRYPT_MODE_OFB 	Output feedback mode.
 *  \return   CRYPT_MODE_CFB 	Cipher feedback mode.
 *
 * 
 */
BOOL WINAPI
CPSetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);


/** \brief Get data governing the operations of a key.
 *
 *
 * 
 *  \param  hProv   Handle to the CSP-eleven.
 *  \param  hKey    Handle to the key.
 *  \param  dwParam Parameters value, one of these:
 *                  - KP_ALGID
 *                  - KP_BLOCKLEN
 *                  - KP_KEYLEN
 *                  - KP_SALT
 *                  - KP_PERMISSIONS
 *                  Some additional valid values exist, which depend on the
 *                  key.
 *  \param  pbData  Pointer to data. Can be NULL in order to retrieve the
 *                  buffer length in pdwDataLen. A second call with the good
 *                  data length is expected.
 *  \param   pcbDataLen  Pointer to a DWORD to write or read the byte length of
 *                      the data pointed by pbData. If the pbData is not NULL
 *                      and there is no enough place to store the returned data,
 *                      th ERROR_MORE_DATA error code is set and the correct
 *                      size of the returned data is set. Any other errors set
 *                      this value to 0.
 *  \param  dwFlags Flags values, always zero, RFU.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *  
 *  \ingroup    KeyGenEx
 *  
 *  \return  Pointer to a DWORD to write or read the byte length of
 *                      the data pointed by pbData. If the pbData is not NULL
 *                      and there is no enough place to store the returned data,
 *                      th ERROR_MORE_DATA error code is set and the correct
 *                      size of the returned data is set. Any other errors set
 *                      this value to 0.
 *                      
 *
 *  \return   ERROR_MORE_DATA 	The pbData buffer is not large enough to hold the requested data.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_KEY or NTE_NO_KEY 	The key specified by the hKey parameter is invalid.
 *  \return   NTE_BAD_TYPE 	The dwParam parameter specifies an unknown parameter number.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the key was created cannot now be found.
 *
 *  \return   Microsoft CSPs return a key length of 64 bits for CALG_DES, 128 for CALG_3DES_112, and 192 for CALG_3DES. These lengths are different from the lengths returned when enumerating algorithms with CryptGetProvParam with dwParam set to PP_ENUMALGS. The length returned by CPGetProvParam is the actual size of the key, including parity bits.
 *  \return   Microsoft CSPs that support the ALG_ID of type CALG_CYLINK_MEK return 64 bits for that algorithm. CALG_CYLINK_MEK is a 40-bit key, but it has parity bits and zeroed key bits to make the key length 64 bits.
 *  \return   Permission flag 	Description 	Value
 *  \return   CRYPT_ENCRYPT 	Allows encryption 	0x0001
 *  \return   CRYPT_DECRYPT 	Allows decryption 	0x0002
 *  \return   CRYPT_EXPORT 	Allows key to be exported 	0x0004
 *  \return   CRYPT_READ 	Allows parameters to be read 	0x0008
 *  \return   CRYPT_WRITE 	Allows parameters to be set 	0x0010
 *  \return   CRYPT_MAC 	Allows MACs to be used with key 	0x0020
 *  \return   Cipher mode 	Description 	Value
 *  \return   CRYPT_MODE_ECB 	Electronic codebook 	2
 *  \return   CRYPT_MODE_CBC 	Cipher block chaining 	1
 *  \return   CRYPT_MODE_OFB 	Output feedback mode 	3
 *  \return   CRYPT_MODE_CFB 	Cipher feedback mode 	4
 *                      
 */

BOOL WINAPI
CPGetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);


/** \brief Customize CSP-eleven.
 *
 *
 *  \param  hProv   Handle to the CSP-eleven.
 * 
 *  \param  dwParam Parameter value:
 *                  PP_CLIENT_HWND
 *                  
 *  \param  pbData  Pointer to parameters data. This buffer will be filled with
 *                  dwParam corresponding data. The length is not set and must be
 *                  deduced from the dwParam parameter value.
 *
 *  \param  dwFlags Always zero, no flag applicable to PP_CLIENT_HWND see warning
 *                  for me info.
 *                  
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *  error.
 *  
 *  \ingroup    SPFunctions
 *
 *
 *  \return   NTE_BAD_FLAGS 	The value of the dwFlags parameter is invalid.
 *  \return   NTE_BAD_TYPE 	The dwParam parameter specifies an unknown parameter number.
 *  \return   NTE_BAD_UID 	The context specified by hProv is invalid.
 *  \return   NTE_FAIL 	The function failed in an unexpected way.
 *  \return   Applications can call CryptSetProvParam with the dwParam parameter set to PP_CLIENT_HWND to specify the window handle the CSP is to use when interacting with the user. The call to CryptSetProvParam passes in the window handle as a DWORD value in the pbData buffer.
 *  \return   Applications call CryptSetProvParam before calling CryptAcquireContext; therefore, calls to CPSetProvParam with the PP_CLIENT_HWND parameter are not made. The CSP obtains this window handle using a virtual function pointer obtained from the CPAcquireContext function call.
 *  
 *
 *  \warning    The PP_KEYSET_SEC_DESCR.parameter value does not seems to be
 *              mandatory, so it is perphas not to support.
 */
BOOL WINAPI
CPSetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);


/** \brief  Retrieve operationals parameters of CSP-eleven.
 *
 *  \param  hProv   Handle to the CSP-eleven.
 * 
 *  \param  dwParam Parameter value:
 *                  - PP_CONTAINER
 *                  - PP_ENUMALGS
 *                  - PP_ENUMCONTAINERS
 *                  - PP_ENUMEX_SIGNING_PROT
 *                  - PP_IMPTYPE
 *                  - PP_KEYSPEC
 *                  - PP_NAME
 *                  - PP_VERSION
 *                  
 *  \param  pbData  Pointer to data. Can be NULL in order to retrieve the
 *                  buffer length in pdwDataLen. A second call with the good
 *                  data length is expected.
 *                  
 *  \param   pcbDataLen  Pointer to a DWORD to write or read the byte length of
 *                      the data pointed by pbData. If the pbData is not NULL
 *                      and there is no enough place to store the returned data,
 *                      th ERROR_MORE_DATA error code is set and the correct
 *                      size of the returned data is set. Any other errors set
 *                      this value to 0.
 *
 *  \param  dwFlags Flag values, either one of:
 *                  - CRYPT_FIRST
 *                  - CRYPT_MACHINE_KEYSET
 *                  
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *  error.
 *
 *  \note   The PP_ENUMCONTAINERS has to be call several times in order to
 *  retrieve the full list. The first call is CRYPT_FIRST flagged, the following
 *  are 0 flagged. The end of the enumeration is reached when the call failed
 *  with ERROR_NO_MORE_ITEMS error code.
 *  
 *  \ingroup    SPFunctions
 *
 *  \warning    The PP_KEYSET_SEC_DESCR and SECURITY_INFORMATION parameters.are
 *              not very useful in case of smartCard. So not implemented.
 *
 *  \return   ERROR_MORE_DATA 	The pbData buffer is not large enough to hold the requested data.
 *  \return   ERROR_NO_MORE_ITEMS 	The end of the enumeration list has been reached. No valid data has been placed in the pbData buffer. This error is returned only when dwParam equals PP_ENUMALGS, PP_ENUMALGS_EX, or PP_ENUMCONTAINERS.
 *  \return   NTE_BAD_FLAGS 	The value of the dwFlags parameter is invalid.
 *  \return   NTE_BAD_TYPE 	The dwParam parameter specifies an unknown parameter number.
 *  \return   NTE_BAD_UID 	The context specified by hProv is invalid.
 *  
 */

BOOL WINAPI
CPGetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);


/** \brief  Set operationals data of a hash object.
 *
 *
 *  \param  hProv   Handle to the CSP-eleven.
 * 
 *  \param  hHash   Handle to the hash object.
 *
 *  \param  dwParam Parameter value, one of these:
 *                  - HP_HMAC_INFO
 *                  - HP_HASHVAL
 *
 *  \param  pbData  Pointer to data. Can be NULL in order to retrieve the
 *                  buffer length in pdwDataLen. A second call with the good
 *                  data length is expected.
 *                  
 *  \param  dwFlags Flags values, always zero, RFU.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *  error.
 *  
 *  \ingroup    HashSign
 *  
 *
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero or the pbData buffer contains an invalid value.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_TYPE 	The dwParam parameter specifies an unknown parameter.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hKey key was created cannot now be found.
 *  \return   NTE_FAIL 	The function failed in some unexpected way.
 *  
 */

BOOL WINAPI
CPSetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);


/** \brief  Retrieve operationals data of a hash object.
 *
 * More than only return the operationals data, this function can be used in
 * order to get the actual hash value.
 *
 *  \param  hProv   Handle to the CSP-eleven.
 * 
 *  \param  hHash   Handle to the hash object.
 *
 *  \param  dwParam Parameter value, one of these:
 *                  - HP_ALGID
 *                  - HP_HASHSIZE
 *                  - HP_HASHVAL
 *
 *  \param  pbData  Pointer to data. Can be NULL in order to retrieve the
 *                  buffer length in pdwDataLen. A second call with the good
 *                  data length is expected.
 *                  
 *  \param   pcbDataLen  Pointer to a DWORD to write or read the byte length of
 *                      the data pointed by pbData. If the pbData is not NULL
 *                      and there is no enough place to store the returned data,
 *                      th ERROR_MORE_DATA error code is set and the correct
 *                      size of the returned data is set. Any other errors set
 *                      this value to 0.
 *
 *  \param  dwFlags Flags values, always zero, RFU.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *  error.
 *  
 *  \ingroup    HashSign
 *  
 *
 *  \return   ERROR_MORE_DATA 	The pbData buffer is not large enough to hold the requested data.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_TYPE 	The dwParam parameter specifies an unknown parameter number.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hash was created cannot now be found.
 */

BOOL WINAPI
CPGetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);


/** \brief Export key(s) to a secure key blob.
 *
 * The exported keys can be a session key (DES or 3DES key) or key pair.
 *
 *
 *  \param  hProv   Handle to a particular key container within the CSP-eleven.
 *  
 *  \param  hKey    Handle to the key to export
 *  
 *  \param  hPubKey Handle of a cryptographic key belonging to the destination
 *                  user. This key will be used to crypt the exported key BLOB.
 *                  Usualy it is a public key of the user or session key. If the
 *                  exported BLOB type is a PUBLICKEYBLOB, the specified key is not
 *                  used. In this last case, hPubKey must be zero.
 *  \param  dwBlobType  Type of key blob to be exported, which can be any of
 *                      these values:
 *                      - PUBLICKEYBLOB
 *                      - PRIVATEKEYBLOB
 *                      - SIMPLEBLOB
 *                      - SYMMETRICWRAPKEYBLOB
 *  \param  dwFlags Always zero, RFU. CSP-eleven is not a sChannel CSP.
 *
 *  \param  pbData  Pointer to data. Can be NULL in order to retrieve the
 *                  buffer length in pdwDataLen. A second call with the good
 *                  data length is expected.
 *                  
 *  \param   pcbDataLen  Pointer to a DWORD to write or read the byte length of
 *                      the data pointed by pbData. If the pbData is not NULL
 *                      and there is no enough place to store the returned data,
 *                      th ERROR_MORE_DATA error code is set and the correct
 *                      size of the returned data is set. Any other errors set
 *                      this value to 0.
 *
 *  \warning    CSP-eleven does not use any OPAQUEBLOB, so this blob type is not
 *              supported. Perphas, CSP-eleven will not support exporting
 *              private key.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *  error.
 *  
 *  \ingroup    KeyGenEx
 *  
 *  \return   ERROR_MORE_DATA 	The pbData buffer is not large enough to hold the requested data.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter contains an invalid value.
 *  \return   NTE_BAD_KEY 	One or both of the keys specified by hKey and hPubKey are invalid.
 *  \return   NTE_BAD_KEY_STATE 	The key cannot be exported because the CRYPT_EXPORTABLE flag was not specified when the key was created.
 *  \return   NTE_BAD_PUBLIC_KEY 	If there is any problem with the
 *                                      specified hPubKey.
 *  \return   NTE_BAD_TYPE 	The dwBlobType parameter specifies an unknown BLOB type.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hKey key was created cannot now be found.
 *  \return   NTE_NO_KEY 	A session key is being exported and the hExpKey parameter does not specify a public key.
 */

BOOL WINAPI
CPExportKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen);


/** \brief  Import a session key or key pair from a key blob into the CSP.
 *
 *
 *  \param  hProv   Handle to a particular key container within the CSP-eleven.
 *  
 *  \param  hPubKey The meaning of this parameter differs, depending on the type of key BLOB being imported.
 *                  - The key is used the verify the digital signature of an
 *                    signed key BLOB.
 *                  - The key can be the exchange key used to decrypt a SIMPLEBLOB.
 *                  - This handle must be zero is the BLOB is a PUBLICKEYBLOB.
 *                    (A blob of this type is not encrypted.)
 *
 *  \param  dwFlags - The CSP ignores the CRYPT_EXPORTABLE flag for key pairs.
 *                  - If you import SIMPLEBLOBs with the CRYPT_ONE flag set, a
 *                    header (compliant with PKCS #1, version 2) is inserted 
 *                    and encrypted with the key data, in order to ensure data
 *                    integrity. When the key data is decrypted, only the key
 *                    data is returned.
 *                  - The CRYPT_NO_SALT flag specifies that a no-salt value is
 *                    to be allocated for a 40-bit symmetric key.
 *
 *
 *  \param  pbData  Buffer containing the key BLOB. A BLOB is componed by one
 *                  header and his data.
 *                  
 *  \param  cbDataLen   Length, in bytes, of the key BLOB.
 *  \param  phKey   Pointer to the handle where the function copies a the key
 *                  that was imported. This handle have to be released by 
 *                  calling CPDestroyKey.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *  
 *  \ingroup    KeyGenEx
 *  
 *  \return   Rewrite the dwFlags doc.
 *
 *  \return   NTE_BAD_ALGID 	The simple key BLOB being imported is not encrypted with the expected key exchange algorithm. The most likely cause of this error is incompatible CSPs.
 *  \return   NTE_BAD_DATA 	The algorithm of the public key being imported is not supported by this CSP.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_TYPE 	The key BLOB type is not supported by this CSP and is possibly invalid.
 *  \return   NTE_BAD_UID 	The hProv parameter does not contain a valid context handle.
 *  \return   NTE_BAD_VER 	The version number of the key BLOB indicates a key BLOB version that the CSP does not support.
 *  
 */

BOOL WINAPI
CPImportKey(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);


/** \brief  Encrypt data.
 *
 *
 * If a large amount of data needs to be encrypted,
 * this function can be called multiple times.
 *
 *  \param  hProv   Handle to a particular key container within the CSP-eleven.
 *  \param  hKey    Handle to the key to use. Operational data are stored in the
 *                  handle.
 *  \param  hHash   Optional handle to a hash in order to hash data before 
 *                  encryption. If no hash has to be done, hHash have to be
 *                  zero.
 *  \param  fFinal   If a large amount of data needs to be encrypted and this
 *                  function is called several time of the same data to encrypt,
 *                  every call set Final to FALSE until the last call where it
 *                  is set to TRUE. If there is only one call, of course, this
 *                  is set to TRUE.
 *  \param  dwFlags zero, RFU.
 *  \param  pbData  Buffer that contains the plaintext to be encrypted. After
 *                  encryption the ciphertext overwrites the plaintext in the
 *                  pbData buffer.
 *  \param  pcbDataLen  Pointer to a DWORD specifiyng the bytes length of the
 *                      plaintext data pointed by pbData. If block cipher is
 *                      used and no flag set, this must be a multiple of the
 *                      cipher block length, in that way, this function does not
 *                      need to buffer data internally.
 *                      
 *  \param  pcbDataLen  On exit, this DWORD specifies the length of the
 *                      ciphertext pointed py pbData.
 *                      
 *  \param  pcbDataLen  In cipher block mode, the size of the ciphertext could
 *                      be greater than the source plaintext, but never greater
 *                      than dwBufLen.
 *
 *  \param  cbBufLen   Total size of the data buffer pointed by pbData.
 *                      *pdwDataLen <= dwDataLen.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *          
 *  \ingroup    DataEnc
 *  
 *  \return   Use the Microsoft® Base CSP to do this job.
 *
 *  \return   The encryption uses PKCS #1 Type 2 padding. On decryption, this padding is
 *  verified. Decryption takes place on the smart card. 
 *
 *  \return   A call to CryptEncrypt with an RSA key can encrypt an amount of plain-text
 *  data up to the length of the key modulus minus eleven bytes. The eleven bytes
 *  is the chosen minimum for PKCS #1 padding. The cipher-text is returned in
 *  little-endian format.
 *  
 *  
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
    IN  DWORD cbBufLen);


/** \brief Decrypt Data.
 *
 * If a large amount of data needs to be decrypted,
 * this function can be called multiple times.
 *
 *  \param  hProv   Handle to a particular key container within the CSP-eleven.
 *  \param  hKey    Handle to the key to use. Operational data are stored in the
 *                  handle.
 *  \param  hHash   Optional handle to a hash in order to hash data after 
 *                  decryption. If no hash has to be done, hHash have to be
 *                  zero.
 *  \param  fFinal  If a large amount of data needs to be dncrypted and this
 *                  function is called several time of the same data to decrypt,
 *                  every call set Final to FALSE until the last call where it
 *                  is set to TRUE. If there is only one call, of course, this
 *                  is set to TRUE.
 *  \param  dwFlags zero, RFU.
 *  \param  pbData  Buffer that contains the ciphertext to be decrypted. After
 *                  decryption the plaintext overwrites the ciphertext in the
 *                  pbData buffer.
 *  \param  pcbDataLen  Pointer to a DWORD specifiyng the bytes length of the
 *                      ciphertext data pointed by pbData. If block cipher is
 *                      used and no flag set, this must be a multiple of the
 *                      cipher block length, Any padding is removed.
 *                      in that way, this function does not
 *                      need to buffer data internally.
 *                      
 *  \param  pcbDataLen  On exit, this DWORD specifies the length of the
 *                      lpaintext pointed py pbData.
 *                      
 *  \param  pcbDataLen  In cipher block mode, the size of the plaintext is 
 *                      never greater than the source ciphertext.
 *
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *          
 *  \ingroup    DataEnc
 *  
 *  \return   Use the Microsoft® Base CSP to do this job.
 *
 *  \return   The encryption uses PKCS #1 Type 2 padding. On decryption, this padding is
 *  verified. Decryption takes place on the smart card. 
 *
 *  \return   A call to CryptDecrypt with an RSA key can encrypt an amount of plain-text
 *  data up to the length of the key modulus minus eleven bytes. The eleven bytes
 *  is the chosen minimum for PKCS #1 padding. The cipher-text is returned in
 *  little-endian format.
 *  
 */

BOOL WINAPI
CPDecrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen);


/** \brief Instanciate a hash object and initialise hash on a data stream.
 *
 *
 *
 *  \param  hProv    Handle to the key container.
 *  \param  Algid   Algorithm identifier, one of:
 *                  - CALG_3DES
 *                  - CALG_3DES_112
 *                  - CALG_DES
 *                  - CALG_HMAC
 *                  - CALG_MD2
 *                  - CALG_MD4
 *                  - CALG_MD5
 *                  - CALG_RC2
 *                  - CALG_RC4
 *                  - CALG_SHA
 *                  - CALG_SHA1
 *                  - CALG_SSL3_SHAMD5
 *  \param  hKey    Handle to the key to use with keyed hash algorithm. If the
 *                  specified algorithm does not need a key set it to zero.
 *  \param  dwFlags zero, RFU.
 *  \param  phHash   Pointer to the handle to the new hash object.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  \return   NTE_BAD_ALGID 	The Algid parameter specifies an algorithm that this CSP does not support.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_KEY 	The Algid parameter specifies a keyed hash algorithm, such as CALG_MAC, and the hKey parameter is either zero or an invalid key handle. This error code will also be returned if the key is to a stream cipher or if the cipher mode is one that does not use feedback.
 *  \return   NTE_NO_MEMORY 	The CSP ran out of memory during the operation.
 *  
 *          
 */

BOOL WINAPI
CPCreateHash(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash);


/** \brief  Feed data into a hash object.
 *
 *
 *  \param  hProv   Handle to a key container within CSP-eleven.
 *  \param  hHash   Handle to a hash object.
 *  \param  pbData  Adress of a buffer containgin data to be hashed.
 *  \param  cbDataLen   Buffer length in bytes.
 *  \param  dwFlags Hash flag, zero or CRYPT_USERDATA.
 *  
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  \sa CPCreateHash()
 *
 *  \note   CRYPT_USERDATA asks CSP-eleven to ask directly to the user data (PIN,
 *          password, etc...) in order to produce a direct hash. The provided
 *          data are consumed and destroyed wihtin this function.
 *          
 *  \warning CRYPT_SERDATA support is optional. So do we code it ?
 *
 *  \return   NTE_BAD_ALGID 	The hHash handle specifies an algorithm that this CSP does not support.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter contains an invalid value.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_HASH_STATE 	An attempt was made to add data to a hash object that is already marked as "finished."
 *  \return   NTE_BAD_KEY 	A keyed hash algorithm is being used, but the session key is no longer valid. This error will be generated if the session key is destroyed before the hashing operating is complete.
 *  \return   NTE_BAD_LEN 	The CRYPT_USERDATA flag is set, and the dwDataLen parameter has a nonzero value.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hash object was created cannot now be found.
 *  \return   NTE_FAIL 	The function failed in some unexpected way.
 *  \return   NTE_NO_MEMORY 	The CSP ran out of memory during the operation.
 *  
 */

BOOL WINAPI
CPHashData(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags);


/** \brief  Feed cryptographic key to a hash object.
 *
 *
 *  Using this function, there is no need to access directly to the key material
 *  to hash it. The access is done within CSP-eleven.
 *  
 *  It can be called more than once on the same hash to process multiple keys.
 *
 *  
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  hHash   Handle to hash object.
 *  \param  hKey    Handle to the session key object to be hashed.
 *  \param  dwFlags Flags value, zero or CRYPT_LITTLE_ENDIAN to hash in little
 *                  endian form. The default (zero) is big endian.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  \return   NTE_BAD_ALGID 	The hHash handle specifies a hash algorithm that this function does not support.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_HASH_STATE 	An attempt was made to add data to a hash object that is already marked as "finished."
 *  \return   NTE_BAD_KEY 	A keyed hash algorithm is being used, but the session key is no longer valid. This error is generated when the session key passed to the CPCreateHash function is destroyed before the hashing operation is complete.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hash object was created cannot now be found.
 *  \return   NTE_FAIL 	The function failed in some unexpected way.
 *  \return   The only data this function adds to the hash object is the session key material, itself. If necessary, an application, not the CSP, can hash the salt of the key, the initialization vector, and other hash state material. Depending on the CSP type, the key material might need to be formatted or padded in some specific way before being added to the hash. For more information, see CSP Interoperability.
 *
 *
 *  \sa CPCreateHash()
 *
 */

BOOL WINAPI
CPHashSessionKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags);


/** \brief  Sign difitaly a hash object.
 *
 *  Typicals steps:
 *  1. The hash object needs no more feeding, and the hash value is extracted.
 *  2. The hash value is padded as required by the signature algorithm.
 *  3. The actual signing operation is performed.
 * 
 *  
 *  \param  hProv   Handle to a key container within CSP-eleven.
 *  \param  hHash   Handle to hash object containing hash to sign.
 *  \param  dwKeySpec   Contained key to use to sign the hash,
 *                      - AT_KEYEXCHANGE
 *                      - AT_SIGNATURE.
 *                      The signature algorithm is set at key pair creation. The
 *                      Microsoft® Base Cryptographic Provider only supports RSA
 *                      Public-key signature algorithm.
 *  \param  szDescription    For security reason, always interpreted as NULL.
 *                          Initialy it was a \\0 terminated description string
 *                          of the hash signature.
 *  \param  dwFlags No flags used, OID will always be included in signature
 *                  (PKCS #7).
 *  \param  pbSignature     Pointer to data buffer into which the signature will be
 *                          written. Can be NULL in order to retrieve the
 *                          buffer length in pdwDataLen. A second call with the good
 *                          data length is expected.
 *                  
 *  \param   pcbSigLen  Pointer to a DWORD to write or read the byte length of
 *                      the data pointed by pbSignature.
 *                      When the function is called, this size tell the total
 *                      allocated buffer size at pbSignature.
 *                      When the function returns, this size tell the necessary
 *                      buffer size to store the produced signature.
 *                      If the pbSignature is not NULL
 *                      and there is no enough place to store the returned data,
 *                      th ERROR_MORE_DATA error code is set and the correct
 *                      size of the returned data is set. Any other errors set
 *                      this value to 0.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  \return   ERROR_MORE_DATA 	The pbData buffer is not large enough to hold the requested data.
 *  \return   NTE_BAD_ALGID 	The hHash handle specifies a hash algorithm that this function does not support.
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hash object was created cannot now be found.
 *  \return   NTE_NO_KEY 	The private key specified by dwKeySpec does not exist.
 *  \return   NTE_NO_MEMORY 	The CSP ran out of memory during the operation.
 *  \return   Depending on the key pair to be used, many CSPs ask the user directly before performing the signature operation. When this is the case, the sDescription string, if supported, is displayed to the user so that he or she knows what is being signed.
 *  \return   The CPSignHash function completes the hash. After calling CPSignHash, no more data can be added to the hash. Additional calls to CPHashData or CPHashSessionKey fail. However, additional calls to CPDeriveKey, CPGetHashParam, CPSignHash, and CPVerifySignature succeed and use the finished hash object.
 *
 */

BOOL WINAPI
CPSignHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen);


/** \brief  Destroy a hash object.
 *
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  hHash   Handle to the hash object to be destroyed.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  \sa CPCreateHash()
 *
 *  \return   NTE_BAD_ALGID 	The hHash handle specifies an algorithm that this CSP does not support.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hash object was created cannot now be found.
 *
*/

BOOL WINAPI
CPDestroyHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash);


/** \brief  Verify a digital signature.
 *
 *  Typical steps:
 *  1. The hash object needs no more feeding, and the hash value is extracted.
 *  2. The hash value is padded as required by the signature algorithm.
 *  3. The actual verification operation is performed by using the hPubKey public key.
 *     If the signed hash within the pbSignature buffer and the hash value 
 *     in the hHash hash object do not match, the NTE_BAD_SIGNATURE error code is returned.
 *
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  hHash   Handle to the signed hash object.
 *  \param  pbSignature Pointer to hash object signature data.
 *  \param  cbSigLen    Length in bytes of the signature data.
 *  \param  hPubKey Handle to the public key for verifying
 *                                   the signature
 *  \param  szDescription   For security reason, always set this to NULL.
 *                          Initialy it was a \\0 terminated description string
 *                          of the hash signature.
 *  \param  dwFlags No flags used, OID will always be expected in signature
 *                  (PKCS #7).
 *
 *  \return TRUE if the signature was successfully verified; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  
 *  \sa CPSignHash()
 *
 *  \return   NTE_BAD_FLAGS 	The dwFlags parameter is nonzero.
 *  \return   NTE_BAD_HASH 	The hash object specified by the hHash parameter is invalid.
 *  \return   NTE_BAD_KEY 	The hPubKey parameter does not contain a handle to a valid public key.
 *  \return   NTE_BAD_SIGNATURE 	The signature failed to verify. This could be because the data itself has changed, the description string did not match, or the wrong public key was specified by hPubKey. This error might also be returned if the hashing or signature algorithms do not match the ones used to create the signature.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the hash object was created cannot now be found.
 *  \return   NTE_NO_MEMORY 	The CSP ran out of memory during the operation.
 *  \return   The CPVerifySignature function completes a hash. After CPVerifySignature has been called, no more data can be added to the hash. Additional calls to the CPHashData or CPHashSessionKey function fail. However, additional calls to the CPDeriveKey, CPGetHashParam, CPSignHash, or CPVerifySignature function succeed and use the finished hash object.
 * 
 */
BOOL WINAPI
CPVerifySignature(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags);


/** \brief  Fill a buffer with random bytes.
 *
 *
 *
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  cbLen   Length in bytes of requested random data.
 *  \param  pbBuffer    Address of an allocated buffer where the random
 *                      bytes will be written.
 *
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    KeyGenEx
 *  
 *  \return   NTE_BAD_UID 	The hProv parameter does not contain a valid context handle.
 *  \return   NTE_FAIL 	The function failed in some unexpected manner.
 *
 *  \return   CPGenRandom is one of the more difficult functions to implement correctly, and it must be done correctly to maintain the security of a CSP. CPGenRandom is used internally by the CPGenKey function, as well by applications when generating data items used in cryptographic protocols such as challenge strings. A CSP is not producing message security if values of the cryptographic keys or challenge strings produced by a CSP are predictable.
 *  \return   There are two components to a good random number generator: a method of getting a random seed, and an algorithm that will generate a good pseudo-random stream of data based on that seed.
 *  \return   Generating a random seed can depend on the hardware used by the CSP. If the CSP has access to a hardware random number source, the problem is solved. A completely software-based CSP might use one of the following sources:
 *  \return   - The system time.
 *  \return   - Any high-precision clocks that exist on the system board and peripherals.
 *  \return   - The cursor or mouse pointer location.
 *  \return   - Any accumulated physical state information devices such as in keyboard input buffers, I/O service queues, and video drivers.
 *  \return   - The number of tasks in the OS scheduling queue, their task identifiers, or their code base addresses and sizes.
 *  \return   - Data from the application, passed into the CryptGenRandom function and passed on to CPGenRandom as the input bytes in pbBuffer.
 *  
 *  \return   Some or all of this data can be hashed along with the random seed from the previous session to create a random seed. New seeds should be generated periodically throughout the session, to avoid placing too much reliance on the pseudo-random stream generator.
 *  \return   Once the random seed has been obtained, any number of algorithms can be used to generate a pseudo-random stream of data. Sometimes a stream cipher such as RC4 is used for this purpose, with the seed forming the keying material. The following sources describe other algorithms and techniques:
 *  \return   - Bellare, M., and P. Rogaway. Optimal Asymmetric Encryption. Advances in Cryptology-EUROCRYPT '94, ed. by A. deSantis, Springer-Verlag, 1995, pp. 92-111, Lecture Notes in Computer Science, vol. 950.
 *  \return   - Blum, L. , M. Blum, and M. Shub. A Simple Unpredictable Pseudo-Random Number Generator. SIAM Journal on Computing 15(2)(May 1986); 364-383.
 *  \return   - M. Blum and S. Micali, "How to generate cryptographically strong sequences of pseudo-random bits," SIAM Journal on Computing 13(4)(November 1984); 850-864.
 * 
 */

BOOL WINAPI
CPGenRandom(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer);


/** \brief  Retrieves a handle to a permanent key pair.
 *
 *  This function applies only to exchange and signature key pairs.
 *
 *
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  dwKeySpec   Type of key to retrieve, one of these:
 *                      - AT_KEYEXCHANGE
 *                      - AT_SIGNATURE
 *  \param  phUserKey   Address of retrieved key handle. Must not be NULL.
 *
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    KeyGenEx
 *  
 *
 *  \return   NTE_BAD_KEY 	The key specified by the hKey parameter is invalid.
 *  \return   NTE_BAD_UID 	The CSP context that was specified when the key was created cannot now be found.
 *  \return   NTE_NO_KEY 	The key specified by the dwKeySpec parameter does not exist.
 */
BOOL WINAPI
CPGetUserKey(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey);


/** \brief  Create an exact copy of a hash and of his states.
 *
 *
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  hHash   Handle to duplicate.
 *  \param  pdwReserved NULL, RFU.
 *  \param  dwFlags zero, RFU.
 *  \param  phHash  Address where the handle to a copy of the hash will be written.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    HashSign
 *  
 *  \note   To generate two different hashes, starting with some common hashed
 *          data:
 *          1. Create a single hash object.
 *          2. Hash the common data to that object.
 *          3. Duplicate the object by using the CryptDuplicateHash function.
 *          4. Hash different data to the original hash object and the newly created object.
 *
 *          CPDestroyHash must be called to destroy any hashes created with CryptDuplicateHash. Destroying the original hash does not cause the duplicate hash to be destroyed. Once a duplicate hash is made, it is separate from the original hash. There is no shared state between the two hashes.
 * 
 *  \return Rewrite the Note.
 *
 *  \return   ERROR_CALL_NOT_IMPLEMENTED 	This is a new function and existing CSPs might not implement it. This error is returned if the CSP does not support this function.
 *  \return   ERROR_INVALID_PARAMETER 	One of the parameters contains an invalid value. This is most often an illegal pointer.
 *  \return   NTE_BAD_HASH 	The handle to the original hash is not valid.
 *  \return   CPDuplicateHash makes a copy of a hash including its exact state. 
 *  
 */

BOOL WINAPI
CPDuplicateHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash);


/** \brief  Create a exact copy of a key and his states.
 *
 *
 *  A key can have some special states, like salt value, initialization vectors,
 *
 *  \param  hProv   Handle to a key container in CSP-eleven.
 *  \param  hKey    Handle to the key to duplicate.
 *  \param  pdwReserved NULL, RFU.
 *  \param  dwFlags zero, RFU.
 *  \param  phKey   Address where the handle to a copy of the key will be written.
 *
 *  \return TRUE if the handle is acquired; FALSE if not, more in the last
 *          error.
 *
 *  \ingroup    KeyGenEx
 *  
 *  \return   ERROR_CALL_NOT_IMPLEMENTED 	Because this is a new function, existing CSPs might not implement it. This error is returned if the CSP does not support this function.
 *  \return   ERROR_INVALID_PARAMETER 	One of the parameters contains an invalid value. This is most often an illegal pointer.
 *  \return   NTE_BAD_KEY 	The handle to the original key is not valid.
 *  \return   The CPDuplicateKey function is used to make a copy of a key and the exact state of that key. For example, a caller can encrypt two separate messages with the same key, but with different salt values. A key is generated, a duplicate is made with the CPDuplicateKey function, and then different appropriate salt values are set on each key with the CPSetKeyParam function.
 *  \return   CPDestroyKey must be called to destroy any keys that are created with CPDuplicateKey. Destroying the original key does not destroy the duplicate key. Once a duplicate key is made, it is separate from the original key. There is no shared state between the two keys.
 *  
 */

BOOL WINAPI
CPDuplicateKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);



/** \brief Return the wanted handler index in the given granted handlers list.
 *
 *  \param grantedHandles   Pointer to the beginning of the granted handlers
 *                          tab.
 *  \param  max_len         The maximum lenth of the granted handlers list.
 *  \param wantedHandle    The wanted handler.
 *
 *  \return An integer from 0 to max_len-1 if a granted context is found.
 *          Negative value if not.
 *  \ingroup    SPInternal
 */
int findGrantedHandle(HANDLE *grantedHandles, int max_len, HANDLE wantedHandle);

/** \brief Grants a cryptographic handle.
 *
 *  Used to remember granted handlers.
 *
 *  \param  grantedHandles Pointer to the granted handler list pointer.
 *  \param  lenth   Pointer to the lenth of the list.
 *  \param  lenth Maximum authorized lenth of the list. 0 means unlimited.
 *  \param  handle  The handle to grant.
 *
 *  \return TRUE if everything went OK.
 *  \ingroup    SPInternal
 */
BOOL grantHandle(HANDLE **grantedHandles, int *lenth,
                  HANDLE handle);

/** \brief Revokes a granted cryptographic handle.
 *
 *  Used to forget a granted handle.
 *
 *  \param  handle   Handler to the provided context to forget.
 *  \param  lenth   Lenth of the granted handles list.
 *  \param  grantedHandles  Pointer to the granted handles list.
 *
 *  \return TRUE if everything went OK.
 *  \ingroup    SPInternal
 */
BOOL revokeHandle(HANDLE **grantedHandles, int *lenth, HANDLE handle);

/** \brief Check if a crypto handler was provided.
 *
 *  Check if the given handler is really a valid cryptographic context handler.
 *
 *  \param  lenth   Number of granted handles.
 *  \param  grantedHandles  Pointer to the granted handles list.
 *  \param  handle  Handle to check.
 *
 *  \return TRUE if the handler was granted by CSP-eleven, FALSE if not.
 *  \ingroup    SPInternal
 */
BOOL grantedHandle(HANDLE *grantedHandles, int lenth, HANDLE handle);

/** \brief Return the algId csp11 ALGORITHM.
 *
 *  Browse the algorithms table and get the wanted definition.
 *  
 *  \param  algId   The wanted CAPI algorithm ID.
 *  \param  algorithm The corresponding ALGORITHM structure.
 *
 *  \return TRUE if algorithm found, FALSE if not.
 *
 *  \ingroup SPInternal
 */
BOOL getAlgorithm(ALG_ID algId, ALGORITHM *algorithm);

/** \brief Return size of produced hash value in bytes.
 *  
 *  \warning The size is returned in BYTES.
 *  
 *  \param Algid    Id of wanted algorithm size.
 *
 *  \return >0 integer if the id is supported, -1 if not.
 *
 *  \ingroup SPInternal
 */
int getHashSize(ALG_ID Algid);

/** \brief Initialise a key handler.
 *  
 *  \param pProvCtx Pointer to the used crypto context.
 *  \param pKey Pointer to the handler to fill.
 *  \param algId Key algorithm CAPI ID.
 *  \return TRUE;
 *
 *  \ingroup SPInternal
 */
BOOL initKey(PROV_CTX *pProvCtx, KEY_INFO *pKey, ALG_ID algId);

/** \brief Reverse a byte string.
 * 
 *  \param pBytes       Pointer to the bytes string.
 *  \param stringLen    Length of the bytes string.
 *
 *  \return TRUE if the bytes string was successfully reversed.
 *  \ingroup SPInternal
 *  \note Hey school boys, students or better, take a look !
 *  Gambin gave us a teach: a very good algo to reverse bytes string.
 */
void reverseBytesString(BYTE *pBytes, DWORD stringLen);

/** \brief Set hash algi and alg oid.
 *
 *  Set the hash algid and try to get the corresponding oid.
 *  If no oid found, bad alg id.
 *  \param  algId   The alg Id to set.
 *  \param  pHash    Pointer to the key information structure.
 *  \ingroup SPInternal
 *
 *  \return TRUE if algid and oid are set.
 */
BOOL setHashAlgId(ALG_ID algId, HASH_INFO *pHash);

/** \brief Set key algi and alg oid.
 *
 *  Set the key algid and try to get the corresponding oid.
 *  If no oid found, bad alg id.
 *  \param  algId   The alg Id to set.
 *  \param  pKey    Pointer to the key information structure.
 *
 *  \ingroup SPInternal
 *  \return TRUE if algid and oid are set.
 */
BOOL setKeyAlgId(ALG_ID algId, KEY_INFO *pKey);

#ifdef __cplusplus
}
#endif
#endif // _CSP11_H_

