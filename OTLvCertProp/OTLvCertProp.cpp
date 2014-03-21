/** \file OTLvCertProp.cpp 
 *
 * Author : Mounir IDRASSI
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

#include "stdafx.h"
#include "OTLvCertProp.h"
#include "reader.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);

//////////////////////////////////////////////////////////////////////

class CCardListener : public CReaderListener
{
protected:
	static LPCTSTR g_szProviderName;
	HCERTSTORE m_hCertStore;
    std::list<SCARD_ATRMASK> m_supportedCards;
    CRITICAL_SECTION m_Lock;

    typedef struct {
        LPTSTR szReaderName;
        CCardListener* pThis;
    } tThreadParam;

    typedef std::list<PCCERT_CONTEXT> tCertList;
    typedef std::map<std::wstring, tCertList> tCertMap;
    tCertMap m_loadedCertificates;

public:
	CCardListener() 
	{
        InitializeCriticalSection(&m_Lock);
         m_hCertStore = CertOpenSystemStore(NULL, _T("MY"));
        // retreive the list of cards supported by our CSP
        HKEY hKey;
        LSTATUS lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
            TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards"), 
            0,
            KEY_READ,
            &hKey);
        if (lRet == ERROR_SUCCESS)
        {
            DWORD dwIndex = 0, cchName, cbName;
            TCHAR szCardName[MAX_PATH];
            TCHAR szProviderName[MAX_PATH];
            while (true)
            {
                cchName = MAX_PATH;
                lRet = RegEnumKeyEx(hKey, dwIndex++, szCardName, &cchName, NULL, NULL, NULL, NULL);
                if (ERROR_SUCCESS == lRet)
                {
                    HKEY hCardKey;
                    lRet = RegOpenKeyEx(hKey, szCardName, 0, KEY_READ, &hCardKey);
                    if (lRet == SCARD_S_SUCCESS)
                    {
                        cbName = sizeof(szProviderName);
                        memset(szProviderName, 0, cbName);
                        lRet = RegQueryValueEx(hCardKey, _T("Crypto Provider"), NULL, NULL, (LPBYTE) szProviderName, &cbName);
                        if (    (lRet == ERROR_SUCCESS)
                            &&  (0 == _tcscmp(szProviderName, g_szProviderName))
                            )
                        {
                            // read the atr and its mask
                            SCARD_ATRMASK cardAtr;
                            cardAtr.cbAtr = 36;
                            lRet = RegQueryValueEx(hCardKey, _T("ATR"), NULL, NULL, cardAtr.rgbAtr, &cardAtr.cbAtr);
                            if (lRet == ERROR_SUCCESS)
                            {
                                lRet = RegQueryValueEx(hCardKey, _T("ATRMask"), NULL, NULL, cardAtr.rgbMask, &cardAtr.cbAtr);
                                if (lRet == ERROR_SUCCESS)
                                {
                                    // Add it to our list
                                    m_supportedCards.push_back(cardAtr);
                                }
                            }
                        }
                        RegCloseKey(hCardKey);
                    }
                }
                else
                    break;
            }
            RegCloseKey(hKey);
        }
	}
	~CCardListener()
	{
        // delete all loaded certificates
        EnterCriticalSection(&m_Lock);
        for (tCertMap::iterator It = m_loadedCertificates.begin(); It != m_loadedCertificates.end(); It++)
        {
            for (tCertList::iterator certIt = It->second.begin(); certIt != It->second.end(); certIt++)
            {
                CertDeleteCertificateFromStore(*certIt);
            }
            It->second.clear();

        }
        m_loadedCertificates.clear();
        LeaveCriticalSection(&m_Lock);

		CertCloseStore(m_hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
		m_hCertStore = NULL;
        DeleteCriticalSection(&m_Lock);
	}

    bool IsCardSupported(SCARD_READERSTATE& state)
    {
        bool bStatus = false;
        std::list<SCARD_ATRMASK>::iterator It;
        for (It = m_supportedCards.begin(); It != m_supportedCards.end(); It++)
        {
            if (state.cbAtr == It->cbAtr)
            {
                BYTE maskedAtr[36];
                for (DWORD i=0; i < It->cbAtr; i++)
                    maskedAtr[i] = state.rgbAtr[i] & It->rgbMask[i];

                if (0 == memcmp(maskedAtr, It->rgbAtr, It->cbAtr))
                {
                    bStatus = true;
                    break;
                }
            }
        }
        return bStatus;
    }

	PCCERT_CONTEXT AddCertToStore(LPBYTE pbCertificate, DWORD cbCertificate, 
		LPCTSTR szContainer, DWORD dwKeySpec)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		if (!CertAddEncodedCertificateToStore(m_hCertStore, X509_ASN_ENCODING, 
			pbCertificate, cbCertificate, CERT_STORE_ADD_REPLACE_EXISTING, &pCertContext)) 
		{
			return NULL;
		}

		CRYPT_KEY_PROV_INFO CryptKeyProvInfo;
		CryptKeyProvInfo.pwszContainerName = (LPTSTR) szContainer;
		CryptKeyProvInfo.pwszProvName = (LPTSTR) g_szProviderName;
		CryptKeyProvInfo.dwProvType = PROV_RSA_FULL;
		CryptKeyProvInfo.dwFlags = 0;
		CryptKeyProvInfo.cProvParam = 0;
		CryptKeyProvInfo.rgProvParam = 0;
		CryptKeyProvInfo.dwKeySpec = dwKeySpec;

		if (CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &CryptKeyProvInfo))
            return pCertContext;
        else
        {
            CertFreeCertificateContext(pCertContext);
            return NULL;
        }



	}

	void LoadCertificate(HCRYPTPROV hProv, DWORD dwKeySpec, LPCTSTR szReaderName, LPCTSTR szContainer)
	{
		HCRYPTKEY hKey;
		LPBYTE pbCertificate = NULL;
		DWORD cbCertificate = 0;
		if (CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			if (CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &cbCertificate, 0))
			{	
				pbCertificate = new BYTE[cbCertificate];
				if (CryptGetKeyParam(hKey, KP_CERTIFICATE, pbCertificate, &cbCertificate, 0))
				{
					PCCERT_CONTEXT pCertContext = AddCertToStore(pbCertificate, cbCertificate, szContainer, dwKeySpec);
                    if (pCertContext)
                    {
                        CAutoCriticalSection lock(m_Lock);
                        // Add this certificate to our list
                        m_loadedCertificates[szReaderName].push_back(pCertContext);
                    }
				}
				delete [] pbCertificate;
			}				
			CryptDestroyKey(hKey);
		}
	}

	virtual void NotifyReaderPlug(SCARD_READERSTATE& state)
	{
		if (    (state.dwEventState & SCARD_STATE_PRESENT)
            &&  IsCardSupported(state)
           )
		{
			// reader inserted with card inside
            SCARD_READERSTATE insertedState = {0};
            insertedState.szReader = state.szReader;
            insertedState.dwCurrentState = SCARD_STATE_EMPTY;
            insertedState.dwEventState = SCARD_STATE_PRESENT;
            insertedState.cbAtr = state.cbAtr;
            memcpy(insertedState.rgbAtr, state.rgbAtr, sizeof(state.rgbAtr));
			NotifyReaderChange(insertedState);
		}
	}

    static void _cdecl ThreadCode(void* pArg)
    {
        tThreadParam* param = (tThreadParam*) pArg;
        CCardListener* pThis = param->pThis;

        //card inserted
        TCHAR szContainer[MAX_PATH];
        _sntprintf(szContainer, MAX_PATH, _T("\\\\.\\%s\\"),param->szReaderName);
		HCRYPTPROV hProv;
        DWORD dwFlags = CRYPT_FIRST;
        if (CryptAcquireContext(&hProv, szContainer,g_szProviderName,PROV_RSA_FULL, CRYPT_SILENT))
		{
            char szName[MAX_PATH];
            DWORD cbName = MAX_PATH;
            while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, (BYTE*) szName, &cbName, dwFlags))
            {
                dwFlags = 0;
                cbName = MAX_PATH;

                HCRYPTPROV hLocalProv;
                TCHAR szFullContainerName[MAX_PATH];
                TCHAR szUnicodeName[MAX_PATH];

                _sntprintf(szFullContainerName, MAX_PATH, _T("\\\\.\\%s\\%S"),param->szReaderName, szName);
                _sntprintf(szUnicodeName, MAX_PATH, _T("%S"), szName);

                if (CryptAcquireContext(&hLocalProv, szFullContainerName,g_szProviderName,PROV_RSA_FULL, CRYPT_SILENT))
                {
                    pThis->LoadCertificate(hLocalProv, AT_KEYEXCHANGE	, param->szReaderName, szUnicodeName);
                    pThis->LoadCertificate(hLocalProv, AT_SIGNATURE    , param->szReaderName, szUnicodeName);
				        
                    CryptReleaseContext(hLocalProv, 0);
                }
            }

			CryptReleaseContext(hProv, 0);
		}

        free(param->szReaderName);
    }

	virtual void NotifyReaderChange(SCARD_READERSTATE& state)
	{
        if (    (state.dwEventState & SCARD_STATE_PRESENT)
            &&  IsCardSupported(state)
           )
		{
            tThreadParam* param = new tThreadParam;
            param->pThis = this;
            param->szReaderName = _tcsdup(state.szReader);

            _beginthread(ThreadCode, 0, param);

		}

        else if (!(state.dwEventState & SCARD_STATE_PRESENT))
		{
			
            // workaround for OpenSC bug
            TCHAR szContainer[MAX_PATH];
            _sntprintf(szContainer, MAX_PATH, _T("\\\\.\\%s\\"),state.szReader);
		    HCRYPTPROV hProv;
            CryptAcquireContext(&hProv, szContainer,g_szProviderName,PROV_RSA_FULL, CRYPT_SILENT);

            //card removed
            CAutoCriticalSection lock(m_Lock);
            tCertMap::iterator It = m_loadedCertificates.find(state.szReader);
            if (It != m_loadedCertificates.end())
            {
                // we have loaded certificate from this reader. Remove them
                tCertList::iterator certIt;
                for (certIt = It->second.begin(); certIt != It->second.end(); certIt++)
                {
                    // delete it from MY store
                    CertDeleteCertificateFromStore(*certIt);
                }

                It->second.clear();
                m_loadedCertificates.erase(It);
            }
		}
	}

	virtual void NotifyReaderUnplug(LPCTSTR szReaderName)
	{
        SCARD_READERSTATE insertedState = {0};
        insertedState.szReader = szReaderName;
        insertedState.dwCurrentState = SCARD_STATE_PRESENT;
        insertedState.dwEventState = SCARD_STATE_EMPTY;
		NotifyReaderChange(insertedState);		
	}

	static void DeleteAllCerts()
	{
		//remove all certificates associated with our CSP
		PCCERT_CONTEXT pCert;
		DWORD cbSize;
		CRYPT_KEY_PROV_INFO *pCryptKeyProvInfo;
        HCERTSTORE hCertStore = CertOpenSystemStore(NULL, _T("MY"));
        if (hCertStore)
        {
		    pCert = CertEnumCertificatesInStore(hCertStore, NULL);
		    while (pCert != NULL) {
                cbSize = 0;
			    if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cbSize) && cbSize) {
				    CBuffer pbCryptKeyProvInfo(cbSize);
				    if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pbCryptKeyProvInfo, &cbSize)) {
					    pCryptKeyProvInfo = (CRYPT_KEY_PROV_INFO *)(BYTE *)pbCryptKeyProvInfo;
					    if (pCryptKeyProvInfo->pwszProvName && wcscmp(pCryptKeyProvInfo->pwszProvName, g_szProviderName) == 0) {
							    PCCERT_CONTEXT m_pCert2 = CertDuplicateCertificateContext(pCert);
							    CertDeleteCertificateFromStore(m_pCert2);
					    }
				    }
			    }
			    pCert = CertEnumCertificatesInStore(hCertStore, pCert);
            }
            CertCloseStore(hCertStore, 0);
		}
	}
};

LPCTSTR CCardListener::g_szProviderName = _T("Oberthur LATVIA-EID CSP");

////////////////////////////////////////////////////////////////////////

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);
 	
	MSG msg;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_OTLVCERTPROP, szWindowClass, MAX_LOADSTRING);

    // is there another instance
    HWND hOtherWnd = FindWindow(szWindowClass, szTitle);
    if (hOtherWnd != NULL)
    {
        // quit
        return 0;
    }

	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance))
	{
		return FALSE;
	}

	CCardListener listener;
	//remove all certs remaining from previous session
	CCardListener::DeleteAllCerts();

	CReaderMonitor* monitor = new CReaderMonitor(SCARD_SCOPE_USER,&listener);
	monitor->start();

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	monitor->stop(true);

	delete monitor;

	//remove all certs
	CCardListener::DeleteAllCerts();


	return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_OTLVCERTPROP));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_OTLVCERTPROP);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

#ifdef _DEBUG
   ShowWindow(hWnd, SW_SHOW);
#else
   ShowWindow(hWnd, SW_HIDE);
#endif

   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
    case WM_POWERBROADCAST:
        if (wParam == PBT_APMSUSPEND)
        {
            // PC is suspending. Remove all certs from store
            CCardListener::DeleteAllCerts();
        }
        else
            return DefWindowProc(hWnd, message, wParam, lParam);
        break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}
