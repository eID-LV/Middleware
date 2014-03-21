/******************************************************************
 * CSP Skeleton based on Microsoft Sample in CSPDK
 *
 ******************************************************************/


#include "defs.h"

extern HINSTANCE g_hModule;

const TCHAR l_szProviderName[] = _T("Oberthur LATVIA-EID CSP");
const DWORD l_dwCspType = PROV_RSA_FULL;


/*++

DllUnregisterServer:

    This service removes the registry entries associated with this CSP.

Arguments:

    None

Return Value:

    Status code as an HRESULT.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

STDAPI
DllUnregisterServer(
    void)
{
    LONG nStatus;
    DWORD dwDisp;
    HRESULT hReturnStatus = NO_ERROR;
    HKEY hProviders = NULL;

    //
    // Delete the Registry key for this CSP.
    //

    nStatus = RegCreateKeyEx(
                    HKEY_LOCAL_MACHINE,
                    _T("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"),
                    0,
                    _T(""),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &hProviders,
                    &dwDisp);
    if (ERROR_SUCCESS == nStatus)
    {
        RegDeleteKey(hProviders, l_szProviderName);
        RegCloseKey(hProviders);
        hProviders = NULL;
    }

    //
    // All done!
    //

    return hReturnStatus;
}


/*++

DllRegisterServer:

    This function installs the proper registry entries to enable this CSP.

Arguments:

    None

Return Value:

    Status code as an HRESULT.

Author:

    Doug Barlow (dbarlow) 3/11/1998

--*/

STDAPI
DllRegisterServer(
    void)
{
    TCHAR szModulePath[MAX_PATH];
    LPTSTR szFileName, szFileExt;
    HRSRC hSigResource;
    DWORD dwStatus;
    LONG nStatus;
    DWORD dwDisp;
    HRESULT hReturnStatus = NO_ERROR;
    HKEY hProviders = NULL;
    HKEY hMyCsp = NULL;
    HKEY hCalais = NULL;
    HKEY hVendor = NULL;
    BOOL fSignatureFound = FALSE;
    HANDLE hSigFile = INVALID_HANDLE_VALUE;

    //
    // Figure out the file name and path.
    //

    dwStatus = GetModuleFileName(
                    g_hModule,
                    szModulePath,
                    sizeof(szModulePath) / sizeof(TCHAR));
    if (0 == dwStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(GetLastError());
        goto ErrorExit;
    }

    szFileName = _tcsrchr(szModulePath, _T('\\'));
    if (NULL == szFileName)
        szFileName = szModulePath;
    else
        szFileName += 1;
    szFileExt = _tcsrchr(szFileName, _T('.'));
    if (NULL == szFileExt)
    {
        hReturnStatus = HRESULT_FROM_WIN32(ERROR_INVALID_NAME);
        goto ErrorExit;
    }
    else
        szFileExt += 1;


    //
    // Create the Registry key for this CSP.
    //

    nStatus = RegCreateKeyEx(
                    HKEY_LOCAL_MACHINE,
                    _T("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"),
                    0,
                    _T(""),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &hProviders,
                    &dwDisp);
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }
    nStatus = RegCreateKeyEx(
                    hProviders,
                    l_szProviderName,
                    0,
                    _T(""),
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    NULL,
                    &hMyCsp,
                    &dwDisp);
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }
    nStatus = RegCloseKey(hProviders);
    hProviders = NULL;
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }


    //
    // Install the trivial registry values.
    //

    nStatus = RegSetValueEx(
                    hMyCsp,
                    _T("Image Path"),
                    0,
                    REG_SZ,
                    (LPBYTE)szModulePath,
                    (DWORD) ((_tcslen(szModulePath) + 1) * sizeof(TCHAR)) );
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }

    nStatus = RegSetValueEx(
                    hMyCsp,
                    _T("Type"),
                    0,
                    REG_DWORD,
                    (LPBYTE)&l_dwCspType,
                    sizeof(DWORD));
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }


    //
    // The CSP dll carries its own signature .
    //

    hSigResource = FindResource(
                        g_hModule,
                        MAKEINTRESOURCE(CRYPT_SIG_RESOURCE_NUMBER),
                        RT_RCDATA);
    if (NULL == hSigResource)
    {
		nStatus = GetLastError();
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }

    //
    // Install the file signature from resource
    // Signature in file flag is sufficient.
    //

    dwStatus = 0;
    nStatus = RegSetValueEx(
                    hMyCsp,
                    _T("SigInFile"),
                    0,
                    REG_DWORD,
                    (LPBYTE)&dwStatus,
                    sizeof(DWORD));
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }

    nStatus = RegCloseKey(hMyCsp);
    hMyCsp = NULL;
    if (ERROR_SUCCESS != nStatus)
    {
        hReturnStatus = HRESULT_FROM_WIN32(nStatus);
        goto ErrorExit;
    }


    //
    // All done!
    //

    return hReturnStatus;


    //
    // An error was detected.  Clean up any outstanding resources and
    // return the error.
    //

    ErrorExit:
    if (NULL != hVendor)
        RegCloseKey(hVendor);
    if (INVALID_HANDLE_VALUE != hSigFile)
        CloseHandle(hSigFile);
    if (NULL != hMyCsp)
        RegCloseKey(hMyCsp);
    if (NULL != hProviders)
        RegCloseKey(hProviders);
    DllUnregisterServer();
    return hReturnStatus;
}

