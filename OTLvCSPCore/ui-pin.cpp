/** \file ui-pin.c 
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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include "pkcs11.h"
#include "ui-pin.h"
#include "resource.h"
#include "csp-debug.h"

static HWND cspHWnd = 0; /**< Window handle of the main CSP #11 window.*/
static HINSTANCE csp11hInstance = 0; /**< Instance of the CSP #11 DLL.*/
extern CK_FUNCTION_LIST_PTR p11;

BOOL setUIInstance(HINSTANCE csphInstance)
{
    if(csphInstance != NULL)
    {
        if(csp11hInstance == NULL)
        {
            csp11hInstance = csphInstance;
            return TRUE;
        }
    }
    return FALSE;
}


BOOL CenterWindow(HWND hWnd) throw()
{
	// determine owner window to center against
    HWND hWndCenter = ::GetWindow(hWnd, GW_OWNER);

	// get coordinates of the window relative to its parent
	RECT rcDlg;
	::GetWindowRect(hWnd, &rcDlg);
	RECT rcArea;
	RECT rcCenter;

	// don't center against invisible or minimized windows
	if(hWndCenter != NULL)
	{
		DWORD dwStyleCenter = ::GetWindowLong(hWndCenter, GWL_STYLE);
		if(!(dwStyleCenter & WS_VISIBLE) || (dwStyleCenter & WS_MINIMIZE))
			hWndCenter = NULL;
	}

	// center within screen coordinates
	HMONITOR hMonitor = NULL;
	if(hWndCenter != NULL)
	{
		hMonitor = ::MonitorFromWindow(hWndCenter, MONITOR_DEFAULTTONEAREST);
    if (hMonitor != ::MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST))
    {
        // we must stay on our original monitor
        hWndCenter = NULL;
        hMonitor = ::MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
    }
	}
	else
	{
		hMonitor = ::MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST);
	}
			
	MONITORINFO minfo;
	minfo.cbSize = sizeof(MONITORINFO);
	BOOL bResult = ::GetMonitorInfo(hMonitor, &minfo);
			
	rcArea = minfo.rcWork;

	if(hWndCenter == NULL)
		rcCenter = rcArea;
	else
    {
		::GetWindowRect(hWndCenter, &rcCenter);
    if (  ((rcCenter.right - rcCenter.left) == 0)
        || ((rcCenter.bottom - rcCenter.top) == 0)
        )
    {
        rcCenter = rcArea;
    }
    }

	int DlgWidth = rcDlg.right - rcDlg.left;
	int DlgHeight = rcDlg.bottom - rcDlg.top;

	// find dialog's upper left based on rcCenter
	int xLeft = (rcCenter.left + rcCenter.right) / 2 - DlgWidth / 2;
	int yTop = (rcCenter.top + rcCenter.bottom) / 2 - DlgHeight / 2;

	// if the dialog is outside the screen, move it inside
	if(xLeft + DlgWidth > rcArea.right)
		xLeft = rcArea.right - DlgWidth;
	if(xLeft < rcArea.left)
		xLeft = rcArea.left;

	if(yTop + DlgHeight > rcArea.bottom)
		yTop = rcArea.bottom - DlgHeight;
	if(yTop < rcArea.top)
		yTop = rcArea.top;

	// map screen coordinates to child coordinates
	return ::SetWindowPos(hWnd, NULL, xLeft, yTop, -1, -1,
		SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

INT_PTR WINAPI InputDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{  
    /** - Check the message number, and,*/
   switch(msg)
   {
        /**  - Dialog box initialization:*/
        case WM_INITDIALOG:
        {   
            TCHAR message[200];
            TCHAR title[200];
            TCHAR prompt[200];
            //  Save string pointer passed here
            SETPOINTER( hDlg, lParam );

            bool bIsSignature = (0 == _tcscmp((LPTSTR) lParam, _T("Signature")));

            SetFocus(hDlg);
            SetForegroundWindow(hDlg);
            CenterWindow(hDlg);
            if (bIsSignature)
            {
                LoadString(csp11hInstance, IDS_SIGNATURE_CHV_PROMPT, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_SIGNATURE_CHV_PROMPT, title,
                           sizeof(title)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_SIGNATURE_CHV_PIN, prompt,
                           sizeof(prompt)/sizeof(TCHAR));
            }
            else
            {
                LoadString(csp11hInstance, IDS_CHV_PROMPT, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_CHV_PROMPT, title,
                           sizeof(title)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_CHV_PIN, prompt,
                           sizeof(prompt)/sizeof(TCHAR));
            }
            SetWindowText(GetDlgItem(hDlg, IDC_PIN_MSG), message);
            SetWindowText(hDlg,title);
            SetWindowText(GetDlgItem(hDlg, IDC_PIN_PROMPT),prompt);

            PostMessage(GetDlgItem( hDlg, IDC_PIN_VALUE ), EM_LIMITTEXT, 64, 0);
                    
            return(TRUE);
        }

    case WM_COMMAND:
        if( wParam == IDCANCEL )                //  If Cancel is pressed, quit
        {
            KILLPOINTER( hDlg );

            EndDialog( hDlg, FALSE );  //  Cause DialogBoxParam to return FALSE
            return( TRUE );
        }
        if( wParam == IDOK )
            {
                TCHAR szStr[ 128 ];
                if( ! GetDlgItemText( hDlg, IDC_PIN_VALUE, szStr, 128 ) )   //  If nothing in
                    break;                                //  the edit control, quit
               //  Copy from here to pointer passed to WM_INITDIALOG
               lstrcpy( (TCHAR *)GETPOINTER( hDlg ), szStr );
               KILLPOINTER( hDlg );

               EndDialog( hDlg, TRUE );    //  Cause DialogBoxParam to return TRUE
               return( TRUE );
            }
            break;
   }
   return( FALSE );
}

/*
 * PinPAD support implementation
 */

static UINT g_wmPinPadMessage = ::RegisterWindowMessage(TEXT("LatviaEIDCSPPinPadMessage"));

typedef struct
{
    CK_SESSION_HANDLE hSession;
    HWND hDlg;
} tPinPadThreadParam;

DWORD WINAPI PinPadThread(LPVOID lpThreadParameter)
{
    tPinPadThreadParam* pTh = (tPinPadThreadParam*) lpThreadParameter;
    HWND hDlg = pTh->hDlg;
    CK_SESSION_HANDLE hSession = pTh->hSession;
    CK_RV rv;

    LocalFree(pTh);
    rv = p11->C_Login(hSession, CKU_USER, NULL, 0);
    PostMessage(hDlg, g_wmPinPadMessage, (WPARAM) rv, 0);
    return rv;
}

INT_PTR WINAPI PinpadDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{  
    /** - Check the message number, and,*/
   switch(msg)
   {
        /**  - Dialog box initialization:*/
        case WM_INITDIALOG:
        {   
            TCHAR title[200];
            TCHAR prompt[200];
            DWORD dwID;
            HANDLE hThread;
            DWORD* pParam = (DWORD*) lParam;
            CK_SESSION_HANDLE hSession =  (CK_SESSION_HANDLE) pParam[0];
            bool bIsSignature = (pParam[1] == AT_SIGNATURE);
            tPinPadThreadParam* pTh = (tPinPadThreadParam*) LocalAlloc(0, sizeof(tPinPadThreadParam));

            pTh->hSession = hSession;
            pTh->hDlg = hDlg;

            SetFocus(hDlg);
            SetForegroundWindow(hDlg);
            CenterWindow(hDlg);
            if (bIsSignature)
            {
                LoadString(csp11hInstance, IDS_SIGNATURE_CHV_PINPAD_PROMPT, prompt,
                           sizeof(prompt)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_SIGNATURE_CHV_PROMPT, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            else
            {
                LoadString(csp11hInstance, IDS_CHV_PINPAD_PROMPT, prompt,
                           sizeof(prompt)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_CHV_PROMPT, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            SetWindowText(GetDlgItem(hDlg, IDC_PINPAD_MSG), prompt);
            SetWindowText(hDlg,title);

            hThread = CreateThread(NULL, 0, PinPadThread, (LPVOID) pTh, 0, &dwID);
            SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR) hThread);
                    
            return(TRUE);
        }

    case WM_COMMAND:
        //  If Cancel is pressed, do nothing
        return( TRUE );
        break;
    default:
        if (msg == g_wmPinPadMessage)
        {
            HANDLE hThread = (HANDLE) GetWindowLongPtr(hDlg, GWLP_USERDATA);
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            EndDialog(hDlg, (INT_PTR) wParam);
            return TRUE;
        }
        break;
   }
   return( FALSE );
}

INT_PTR WINAPI BadPinDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    
    /** - Check the message number, and,*/
   switch(msg)
   {
        /**  - Dialog box initialization:*/
        case WM_INITDIALOG:
        {
            TCHAR message[200];
            TCHAR title[100];
            DWORD dwKeySpec = (DWORD) lParam;
            SetFocus(hDlg);
            SetForegroundWindow(hDlg);
            CenterWindow(hDlg);
            if (dwKeySpec == AT_SIGNATURE)
            {
                LoadString(csp11hInstance, IDS_BAD_SIGNATURE_PIN_MSG, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_BAD_SIGNATURE_PIN, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            else
            {
                LoadString(csp11hInstance, IDS_BAD_PIN_MSG, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_BAD_PIN, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            SetWindowText(GetDlgItem(hDlg, IDC_NUMBER_MSG), message);
            SetWindowText(hDlg,title);

             return(TRUE);
        }

    case WM_COMMAND:
        if( wParam == IDOK )                //  If Cancel is pressed, quit
        {
            KILLPOINTER( hDlg );

            EndDialog( hDlg, TRUE );  //  Cause DialogBoxParam to return FALSE
            return( TRUE );
        }
   }
   return( FALSE );
}

INT_PTR WINAPI InvalidPinDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    
    /** - Check the message number, and,*/
   switch(msg)
   {
        /**  - Dialog box initialization:*/
        case WM_INITDIALOG:
        {
            TCHAR message[200];
            TCHAR title[100];
            DWORD dwKeySpec = (DWORD) lParam;
            SetFocus(hDlg);
            SetForegroundWindow(hDlg);
            CenterWindow(hDlg);
            if (dwKeySpec == AT_SIGNATURE)
            {
                LoadString(csp11hInstance, IDS_INVALID_SIGNATURE_PIN_MSG, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_INVALID_SIGNATURE_PIN, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            else
            {
                LoadString(csp11hInstance, IDS_INVALID_PIN_MSG, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_INVALID_PIN, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            SetWindowText(GetDlgItem(hDlg, IDC_INVALID_MSG), message);
            SetWindowText(hDlg,title);
             return(TRUE);
        }

    case WM_COMMAND:
        if( wParam == IDOK )                //  If Cancel is pressed, quit
        {
            KILLPOINTER( hDlg );

            EndDialog( hDlg, TRUE );  //  Cause DialogBoxParam to return FALSE
            return( TRUE );
        }
   }
   return( FALSE );
}
INT_PTR WINAPI PinLockDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    
    /** - Check the message number, and,*/
   switch(msg)
   {
        /**  - Dialog box initialization:*/
        case WM_INITDIALOG:
        {
            TCHAR message[200];
            TCHAR title[100];
            DWORD dwKeySpec = (DWORD) lParam;
            SetFocus(hDlg);
            SetForegroundWindow(hDlg);
            CenterWindow(hDlg);
            if (dwKeySpec == AT_SIGNATURE)
            {
                LoadString(csp11hInstance, IDS_SIGNATURE_PIN_LOCKED_MSG, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_SIGNATURE_PIN_LOCKED, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            else
            {
                LoadString(csp11hInstance, IDS_PIN_LOCKED_MSG, message,
                           sizeof(message)/sizeof(TCHAR));
                LoadString(csp11hInstance, IDS_PIN_LOCKED, title,
                           sizeof(title)/sizeof(TCHAR));
            }
            SetWindowText(GetDlgItem(hDlg, IDC_LOCKED_MSG), message);
            SetWindowText(hDlg,title);
             return(TRUE);
        }

    case WM_COMMAND:
        if( wParam == IDCANCEL )                //  If Cancel is pressed, quit
        {
            KILLPOINTER( hDlg );

            EndDialog( hDlg, FALSE );  //  Cause DialogBoxParam to return FALSE
            return( TRUE );
        }
        if( wParam == ID_MB_UNLOCK )
            {
               EndDialog( hDlg, TRUE );    //  Cause DialogBoxParam to return TRUE
               return( TRUE );
            }
            break;
   }
   return( FALSE );
}

INT_PTR WINAPI unreadableDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    TCHAR message[200];
    TCHAR title[100];
    TCHAR retry[30];
    
    /** - Check the message number, and,*/
   switch(msg)
   {
        /**  - Dialog box initialization:*/
        case WM_INITDIALOG:
        {                                     //  Save string pointer passed here
            SetFocus(hDlg);
            SetForegroundWindow(hDlg);
            CenterWindow(hDlg);
            LoadString(csp11hInstance, IDS_WRONG_CARD_MSG, message,
                       sizeof(message)/sizeof(TCHAR));
            LoadString(csp11hInstance, IDS_WRONG_CARD, title,
                       sizeof(title)/sizeof(TCHAR));
            LoadString(csp11hInstance, IDS_RETRY, retry,
                       sizeof(retry)/sizeof(TCHAR));
            SetWindowText(GetDlgItem(hDlg, IDRETRY), retry);
            SetWindowText(GetDlgItem(hDlg, IDC_UNREADABLE_MSG), message);
            SetWindowText(hDlg,title);
             return(TRUE);
        }

    case WM_COMMAND:
        if( wParam == IDCANCEL )                //  If Cancel is pressed, quit
        {
            KILLPOINTER( hDlg );

            EndDialog( hDlg, FALSE );  //  Cause DialogBoxParam to return FALSE
            return( TRUE );
        }
        if( wParam == IDRETRY )
            {
               EndDialog( hDlg, TRUE );    //  Cause DialogBoxParam to return TRUE
               return( TRUE );
            }
            break;
   }
   return( FALSE );
}

BOOL IsPinValid(LPCTSTR szUnicodePin, char* pin, int pinLen)
{
    int unicodePinLen = lstrlen(szUnicodePin);
    if((unicodePinLen>64) || (unicodePinLen<4))
    {
        return FALSE;
    }
    else
    {
        // convert to ASCII
        pinLen = WideCharToMultiByte(CP_ACP, 0, szUnicodePin, -1, pin, pinLen, NULL, NULL);
        if (!pinLen)
            return FALSE;
        pinLen--; // don't count '\0'
        if((pinLen>64) || (pinLen<4))
        {
            return FALSE;
        }
        for(int i=0; i<pinLen;i++)
        {
            if((pin[i]>'9') || (pin[i]<'0'))
            {
                return FALSE;
            }
        }
    }
    return TRUE;
}

CK_RV PinPadGUI(HWND *pHWnd, CK_SESSION_HANDLE hSession, DWORD keySpec)
{
    DWORD param[2] = {(DWORD) hSession, keySpec};
    HWND hParent = *pHWnd;
    
    if(csp11hInstance == NULL)
    {
        return FALSE;
    }

    if (!IsWindow(hParent))
    {
        hParent = GetForegroundWindow();
        if (hParent == NULL)
            hParent = GetDesktopWindow();
    }

    return DialogBoxParam(csp11hInstance, MAKEINTRESOURCE( IDD_PINPAD ), hParent,
            PinpadDlgProc, (LPARAM) param );
}


BOOL ChvGUI(HWND *pHWnd, DWORD keySpec, char* pin, int pinLen)
{
    TCHAR szText[128] = {0};
    BOOL badPin;
    HWND hParent = *pHWnd;
    
    if(csp11hInstance == NULL)
    {
        return FALSE;
    }

    if (!IsWindow(hParent))
    {
        hParent = GetForegroundWindow();
        if (hParent == NULL)
            hParent = GetDesktopWindow();
    }
    
    while(true)
    {
        badPin = FALSE;
        if (keySpec == AT_SIGNATURE)
            _tcscpy(szText, _T("Signature"));
        else
            _tcscpy(szText, _T("User"));
        if(DialogBoxParam(csp11hInstance, MAKEINTRESOURCE( IDD_PIN ), hParent,
                                InputDlgProc, (LPARAM)(LPTSTR)szText ) )
        {             
            if(!IsPinValid(szText, pin, pinLen))
            {
                displayBadPin(hParent, keySpec);
            }
            else
            {            
                return TRUE;
            }
        }
        else
        {
            return FALSE;
        }
    }

            
    return FALSE;
}

/** \brief Display "PIN locked" message box.*/
BOOL displayPinLocked(HWND hWnd, DWORD keySpec)
{
    if (!IsWindow(hWnd))
    {
        hWnd = GetForegroundWindow();
        if (hWnd == NULL)
            hWnd = GetDesktopWindow();
    }    
    if(DialogBoxParam(csp11hInstance, MAKEINTRESOURCE(IDD_PIN_LOCKED), hWnd,
                 PinLockDlgProc, (LPARAM) keySpec))
    {
        return TRUE;
    }
    return TRUE;
}

/** \brief Display "Invalid PIN" message box.*/
BOOL displayPinIncorrect(HWND hWnd, DWORD keySpec)
{
    if (!IsWindow(hWnd))
    {
        hWnd = GetForegroundWindow();
        if (hWnd == NULL)
            hWnd = GetDesktopWindow();
    }
    DialogBoxParam(csp11hInstance, MAKEINTRESOURCE(IDD_WRONG_CHV), hWnd,
                 InvalidPinDlgProc, (LPARAM) keySpec);
    return TRUE;
}

/** \brief Display "Bad PIN" message box.*/
BOOL displayBadPin(HWND hWnd, DWORD keySpec)
{
    if (!IsWindow(hWnd))
    {
        hWnd = GetForegroundWindow();
        if (hWnd == NULL)
            hWnd = GetDesktopWindow();
    }
    DialogBoxParam(csp11hInstance, MAKEINTRESOURCE(IDD_BAD_PIN), hWnd,
                 BadPinDlgProc, (LPARAM) keySpec);
    return TRUE;
}
    
BOOL unreadableCard(HWND *pHWnd)
{
    HWND hParent = *pHWnd;
    
    if(csp11hInstance == NULL)
    {
        return FALSE;
    }

    if (!IsWindow(hParent))
    {
        hParent = GetForegroundWindow();
        if (hParent == NULL)
            hParent = GetDesktopWindow();
    }
    
    return (BOOL) DialogBox(csp11hInstance, MAKEINTRESOURCE(IDD_UNREADABLE), hParent,
                 unreadableDlgProc);
}
