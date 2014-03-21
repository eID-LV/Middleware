/** \file csp-debug.h
 * $Id: csp-debug.h 259 2005-03-17 16:06:25Z rchantereau $ 
 *
 * CSP #11 -- Cryptographic Service Provider PKCS #11.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  This file declares and documents all the necessary debug macro
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


#ifndef _CSP_DEBUG_H_

#define _CSP_DEBUG_H_       /**< csp11.h inclusion tag. */
#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG_DIR      TEXT("C:\\eID_csp_log") /**< Path to the debug log file.*/

#define DEBUG_LEVEL      0  /**< Debug level 0 to 5 */

/** \brief Close the debug log file.
 *
 * \return TRUE if the log file was closed. FALSE if not, (not opened of worse).
 */
BOOL closeDebug();

/** \brief Write debug to file
 *
 *  Lock the debug file, open it, write in it, close it, unlock it.
 *  
 *  \param  message C string containgin the message to write.
 *
 *  \return TRUE if ok.
 */
BOOL    fdebug(const char *message);

/** \brief Debug macro
 *
 *
 */
#define DEBUG(LEVEL, MESSAGE) \
    if(LEVEL <= DEBUG_LEVEL) \
    { \
        DWORD __localErrCode = GetLastError(); \
        fdebug(MESSAGE); \
        SetLastError(__localErrCode); \
    }

#ifdef __cplusplus
}
#endif
#endif // _CSP_DEBUG_H_

