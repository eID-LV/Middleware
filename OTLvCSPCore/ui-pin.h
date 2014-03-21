/** \file ui-pin.h
 * $Id: ui-pin.h 259 2005-03-17 16:06:25Z rchantereau $ 
 *
 * CSP #11 -- Cryptographic Service Provider PIN UI resources script file.
 *
 * Copyright © 2004 Entr'ouvert
 * http://csp11.labs.libre-entreprise.org
 * 
 *  Here are all function declaration used by PIN UI.
 * 
 * \author  Romain Chantereau <rchantereau@entrouvert.com>
 * \date    2004
 * \version  0.1 
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

/* Set of macro in order to retrieve 32 bits Windows pointer.*/
#define SETPOINTER(h,lp) SetProp(h,MAKEINTATOM(IDD_PIN),(HANDLE)lp)
#define GETPOINTER(h)    (LPVOID)GetProp(h,MAKEINTATOM(IDD_PIN))
#define KILLPOINTER(h)   RemoveProp(h,MAKEINTATOM(IDD_PIN))

/** \brief Set the instance to use for Windows UI.
 *
 *  \param csphInstance Handle to the CSP DLL instance.
 *
 *  \return TRUE if the instance is set, FALSE if the given parameter is NULL.
 */
BOOL setUIInstance(HINSTANCE csphInstance);


/** \brief Manage the Input PIN dialog box.
 *  
 *  \param  hDlg    Handle to the dialog box window.
 *  \param  msg     Transmitted message number.
 *  \param  wParam  Additional information about msg.
 *  \param  lParam  Additional information about msg.
 *
 *  \return False if something went bad.
 */
INT_PTR WINAPI InputDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam);

/** \brief Create the dialog box.
 *
 *  Display with entered number set to 8.
 *  Only numbers, no others characters.
 *  
 *  \param pHWnd Pointer to the parent Window handle
 *  \param pin Pointer to a char* where pin will be stored.
 *  
 *  \return FALSE if there was a problem.
 */
BOOL ChvGUI(HWND *pHWnd, DWORD keySpec, char* pin, int pinLen);
CK_RV PinPadGUI(HWND *pHWnd, CK_SESSION_HANDLE hSession, DWORD keySpec);

/** \brief Display "PIN locked" dialog box.
 *
 *  \param hWnd Parent Window handle.
 *  \return Always true.
 */
BOOL displayPinLocked(HWND hWnd, DWORD keySpec);

/** \brief Display "PIN incorrect" message box.
 *
 *  \param hWnd Parent Window handle.
 *  \return Always true.
 */
BOOL displayPinIncorrect(HWND hWnd, DWORD keySpec);

/** \brief Display "Bad PIN" message box.
 *
 *  \param hWnd Parent Window handle.
 *  \return Always true.
 */
BOOL displayBadPin(HWND hWnd, DWORD keySpec);

/** \brief Display "card unreadable" dialog.
 *
 *  \param  pHWnd the parent window handle.
 *
 *  \return TRUE is click on retry, false if on cancel.
 */
BOOL unreadableCard(HWND *pHWnd);

