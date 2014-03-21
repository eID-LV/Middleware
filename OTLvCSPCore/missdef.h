/** \file missdef.h
 * $Id: missdef.h 259 2005-03-17 16:06:25Z rchantereau $ 
 *
 * CSP #11 -- Cryptographic Service Provider PKCS #11.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  This file define missing definitions
 *  Windows CAPI use in CSP #11.
 *  The documentation written here is used by documentation manager.
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


#ifndef _MISSDEF_H_

#define _MISSDEF_H_       /**< misscrypt.h inclusion tag. */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef CRYPT_SIG_RESOURCE_NUMBER
#define CRYPT_SIG_RESOURCE_NUMBER        0x29A  /**< Signature ressource
                                                     number.*/
#endif

#ifndef CRYPT_MAC_RESOURCE_NUMBER
#define CRYPT_MAC_RESOURCE_NUMBER        0x29B  /**< Mac keyed hash.*/
#endif

/* Exponentiation Offload Reg Location
#define EXPO_OFFLOAD_REG_VALUE "ExpoOffload"
#define EXPO_OFFLOAD_FUNC_NAME "OffloadModExpo"*/

/********************** MS CSP DECLARATION ****************************/

#ifndef SCARD_W_WRONG_CHV
#define SCARD_W_WRONG_CHV   ((HRESULT) 0x8010006BL)  /**< The PIN is incorrect.*/
#endif

#ifndef SCARD_W_CHV_BLOCKED
#define SCARD_W_CHV_BLOCKED ((HRESULT) 0x8010006CL)  /**< Too many attempts, PIN blocked.*/
#endif

#ifndef SCARD_W_CANCELLED_BY_USER
#define SCARD_W_CANCELLED_BY_USER ((HRESULT) 0x8010006EL) /**< The user click 
                                                               the cancel button on the 
                                                               PIN UI.*/
#endif

#ifndef NTE_SILENT_CONTEXT
#define NTE_SILENT_CONTEXT  ((HRESULT) 0x80090022L) /**< RC2 key effective key length.*/
#endif

#ifndef KP_KEYLEN
#define KP_KEYLEN   0x00000009 /**< Key length parameter.*/
#endif

#ifndef PP_CLIENT_HWND
#define PP_CLIENT_HWND          1   /**< Missing GNU w32 API declaration.*/
#endif

#ifndef CALG_SSL3_SHAMD5
#define CALG_SSL3_SHAMD5        (ALG_CLASS_HASH | ALG_TYPE_ANY | \
                                 ALG_SID_SSL3SHAMD5) /**< Missing alg defintion
                                 in GNU w32 API.*/
#endif

#ifndef CALG_3DES_112
#define CALG_3DES_112           \
                                 (ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_3DES_112)\
                                  /**< Missing alg definition in GNU w32 API.*/
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256                 12
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef KP_SALT_EX
#define KP_SALT_EX  10 /**< Length of salt in bytes.*/
#endif

#ifndef KP_EFFECTIVE_KEYLEN
#define KP_EFFECTIVE_KEYLEN  19 /**< RC2 key effective key length.*/
#endif


#ifndef CALG_SHA1
#define CALG_SHA1   CALG_SHA    /**< CALG_SHA1 is like CALG_SHA.*/
#endif

#ifndef SCARD_W_WRONG_CHV
#define SCARD_W_WRONG_CHV   0x8010006B  /**< The PIN is incorrect.*/
#endif

#ifndef SCARD_W_CHV_BLOCKED
#define SCARD_W_CHV_BLOCKED 0x8010006C  /**< Too many attempts, PIN blocked.*/
#endif

#define PP_CLIENT_HWND          1   /**< Missing GNU w32 API declaration.*/


#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER_ID       1
#define CERT_SYSTEM_STORE_LOCATION_SHIFT        16
#define CERT_SYSTEM_STORE_CURRENT_USER          \
    (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
#endif

#ifndef CERT_STORE_CERTIFICATE_CONTEXT
#define CERT_STORE_CERTIFICATE_CONTEXT  1
#endif

#ifndef CERT_KEY_PROV_INFO_PROP_ID
#define CERT_KEY_PROV_INFO_PROP_ID          2
#endif

#ifndef CERT_FRIENDLY_NAME_PROP_ID
#define CERT_FRIENDLY_NAME_PROP_ID          11
#endif

#ifndef CERT_STORE_ADD_REPLACE_EXISTING
#define CERT_STORE_ADD_REPLACE_EXISTING                     3
#endif

#ifndef CRYPT_E_EXISTS
#define CRYPT_E_EXISTS                  0x80092005L
#endif

#ifndef CERT_CLOSE_STORE_FORCE_FLAGS
#define CERT_CLOSE_STORE_FORCE_FLAG         0x00000001
#endif

#ifndef WINCRYPT32API
#define WINCRYPT32API DECLSPEC_IMPORT
#endif

#ifndef RSA1
#define RSA1       0x31415352 
#endif

#ifndef RSA2
#define RSA2       0x32415352 
#endif

#ifndef CRYPT_DECRYPT_RSA_NO_PADDING_CHECK
#define CRYPT_DECRYPT_RSA_NO_PADDING_CHECK      0x00000020
#endif
	
#ifdef __cplusplus
}
#endif
#endif // _MISSDEF_H_

