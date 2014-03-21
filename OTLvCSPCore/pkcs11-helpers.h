/** \file pkcs11-helpers.h
 * $Id: pkcs11-helpers.h 259 2005-03-17 16:06:25Z rchantereau $ 
 *
 * CSP #11 -- PKCS11 Cryptographic Helpers.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  This file declares and documents all the necessary functions and types
 *  in order to provide PKCS #11 Cryptographic Helpers Functions.
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

/** \defgroup   SEHelper   External helpers functions.
 *  
 *  These functions are used in order to help the poor developper translating
 *  one API data to another, etc...
 */

#ifndef _PKCS11_HELPERS_H_

#define _PKCS11_HELPERS_H_     /**< pkcs11_helpers.h inclusion tag. */

#ifndef CALG_SHA1
#define CALG_SHA1   CALG_SHA    /**< CALG_SHA1 is like CALG_SHA.*/
#endif

#ifndef NO_SLOT
#define NO_SLOT ((CK_SLOT_ID) -1)   /**< A -1 slot number means no choosen
                                        slot. */
#endif

/** \brief CAPI <==> PKCS#11 key algorithm information.
 */
typedef struct _PKCS11_KEY_TYPE {
    ALG_ID  algId;  /**< The CAPI key algorithm ID.*/
    CK_KEY_TYPE keyType;    /**< The PKCS #11 corresponding key type.*/
} PKCS11_KEY_TYPE;


/** \brief CAPI <==> PKCS#11 hash algorithm information.
 */
typedef struct _PKCS11_MECHANISM {
    ALG_ID  algId;  /**< The CAPI hash algorithm ID.*/
    CK_MECHANISM_TYPE mechType;    /**< The PKCS #11 corresponding mech type.*/
    const char *cIdentifier;    /**< The algorithm identifier.*/
    CK_ULONG    hashLength;     /**< The hash length in bytes.*/
} PKCS11_MECHANISM;

/** \brief Get the CAPI AlgId from PKCS #11 key type.
 *
 *  \param  keyType   The PKCS#11 Key type.
 *  \ingroup   SEHelper
 *
 *  \return CAPI AlgId. Negative value if not found.
 */
ALG_ID getAlgIdFromType(CK_KEY_TYPE keyType);


/** \brief Get the PKCS #11 key type from CAPI AlgId.
 *
 *  \param  algId   The CAPI algorithm ID.
 *  \ingroup   SEHelper
 *
 *  \return the PKCS #11 algorithm ID. Negative value if not found.
 */
CK_KEY_TYPE getTypeFromAlgId(ALG_ID algId);


/** \brief Find the private key of a public key.
 *
 *  \param  hPubKey PKCS #11 Handle to the public key.
 *  \param  phPrivKey   PKCS#11 Handle to the private key.
 *
 *  \ingroup   SEHelper
 *  \return TRUE if founded, false if not.
 *  
 */
BOOL findPrivateKey(CK_SESSION_HANDLE hSession,
                    unsigned char pubKeyId, CK_OBJECT_HANDLE *phPrivKey);

#endif
