#include "defs.h"

/******************************************
 * Exception class for error code handling
 ******************************************/
class CCSPException  
{
private:	
	DWORD m_dwCode;

public:

	CCSPException(CCSPException &ex)				{ m_dwCode = ex.m_dwCode; }
	CCSPException(DWORD dwCode)						{ m_dwCode = dwCode; }
	DWORD GetCode()									{ return m_dwCode; }
	virtual ~CCSPException()						{ }
	
};

/******************************************
 * Global variable declarations
 ******************************************/
HINSTANCE g_hModule = NULL;
HINSTANCE g_hDllInstance = NULL;
bool g_isInitialized = false;
const TCHAR g_szCspDllName[] = _T("OTLVCspCore.dll");

/******************************************
 * CSP functions pointers
 ******************************************/

typedef BOOL (WINAPI *CPAcquireContextType)(
    HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable);

typedef BOOL (WINAPI *CPReleaseContextType)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPGenKeyType)(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

typedef BOOL (WINAPI *CPDeriveKeyType)(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

typedef BOOL (WINAPI *CPDestroyKeyType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey);

typedef BOOL (WINAPI *CPSetKeyParamType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPGetKeyParamType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPSetProvParamType)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPGetProvParamType)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPSetHashParamType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPGetHashParamType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPExportKeyType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen);

typedef BOOL (WINAPI *CPImportKeyType)(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

typedef BOOL (WINAPI *CPEncryptType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen);

typedef BOOL (WINAPI *CPDecryptType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen);

typedef BOOL (WINAPI *CPCreateHashType)(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash);

typedef BOOL (WINAPI *CPHashDataType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPHashSessionKeyType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPSignHashType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen);

typedef BOOL (WINAPI *CPDestroyHashType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash);

typedef BOOL (WINAPI *CPVerifySignatureType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags);

typedef BOOL (WINAPI *CPGenRandomType)(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer);

typedef BOOL (WINAPI *CPGetUserKeyType)(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey);

typedef BOOL (WINAPI *CPDuplicateHashType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash);

typedef BOOL (WINAPI *CPDuplicateKeyType)(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey);

CPAcquireContextType	acquireContext = NULL;
CPReleaseContextType	releaseContext = NULL;
CPGenKeyType			genKey = NULL;
CPDeriveKeyType			deriveKey = NULL;
CPDestroyKeyType		destroyKey = NULL;
CPSetKeyParamType		setKeyParam = NULL;
CPGetKeyParamType		getKeyParam = NULL;
CPSetProvParamType		setProvParam = NULL;
CPGetProvParamType		getProvParam = NULL;
CPSetHashParamType		setHashParam = NULL;
CPGetHashParamType		getHashParam = NULL;
CPExportKeyType			exportKey = NULL;
CPImportKeyType			importKey = NULL;
CPEncryptType			encrypt = NULL;
CPDecryptType			decrypt = NULL;
CPCreateHashType		createHash = NULL;
CPHashDataType			hashData = NULL;
CPHashSessionKeyType	hashSessionKey = NULL;
CPSignHashType			signHash = NULL;
CPDestroyHashType		destroyHash = NULL;
CPVerifySignatureType	verifySignature = NULL;
CPGenRandomType			genRandom = NULL;
CPGetUserKeyType		getUserKey = NULL;
CPDuplicateHashType		duplicateHash = NULL;
CPDuplicateKeyType		duplicateKey = NULL;

/******************************************
 * Initialization
 ******************************************/
BOOL InitializeLibrary()
{
	if (g_isInitialized)
		return TRUE;

	g_hDllInstance = LoadLibrary(g_szCspDllName);
	if (!g_hDllInstance)
	{
		return FALSE;
	}

	acquireContext = (CPAcquireContextType) GetProcAddress(g_hDllInstance, "CPAcquireContext");
	releaseContext = (CPReleaseContextType) GetProcAddress(g_hDllInstance, "CPReleaseContext");
	genKey = (CPGenKeyType) GetProcAddress(g_hDllInstance, "CPGenKey")			;
	deriveKey = (CPDeriveKeyType) GetProcAddress(g_hDllInstance, "CPDeriveKey")			;
	destroyKey = (CPDestroyKeyType) GetProcAddress(g_hDllInstance, "CPDestroyKey")		;
	setKeyParam = (CPSetKeyParamType) GetProcAddress(g_hDllInstance, "CPSetKeyParam")		;
	getKeyParam = (CPGetKeyParamType) GetProcAddress(g_hDllInstance, "CPGetKeyParam")		;
	setProvParam = (CPSetProvParamType) GetProcAddress(g_hDllInstance, "CPSetProvParam")		;
	getProvParam = (CPGetProvParamType) GetProcAddress(g_hDllInstance, "CPGetProvParam")		;
	setHashParam = (CPSetHashParamType) GetProcAddress(g_hDllInstance, "CPSetHashParam")		;
	getHashParam = (CPGetHashParamType) GetProcAddress(g_hDllInstance, "CPGetHashParam")		;
	exportKey = (CPExportKeyType) GetProcAddress(g_hDllInstance, "CPExportKey")			;
	importKey = (CPImportKeyType) GetProcAddress(g_hDllInstance, "CPImportKey")			;
	encrypt = (CPEncryptType) GetProcAddress(g_hDllInstance, "CPEncrypt")			;
	decrypt = (CPDecryptType) GetProcAddress(g_hDllInstance, "CPDecrypt")			;
	createHash = (CPCreateHashType) GetProcAddress(g_hDllInstance, "CPCreateHash")		;
	hashData = (CPHashDataType) GetProcAddress(g_hDllInstance, "CPHashData")			;
	hashSessionKey = (CPHashSessionKeyType) GetProcAddress(g_hDllInstance, "CPHashSessionKey")	;
	signHash = (CPSignHashType) GetProcAddress(g_hDllInstance, "CPSignHash")			;
	destroyHash = (CPDestroyHashType) GetProcAddress(g_hDllInstance, "CPDestroyHash")		;
	verifySignature = (CPVerifySignatureType) GetProcAddress(g_hDllInstance, "CPVerifySignature")	;
	genRandom = (CPGenRandomType) GetProcAddress(g_hDllInstance, "CPGenRandom")			;
	getUserKey = (CPGetUserKeyType) GetProcAddress(g_hDllInstance, "CPGetUserKey")		;
	duplicateHash = (CPDuplicateHashType) GetProcAddress(g_hDllInstance, "CPDuplicateHash")		;
	duplicateKey = (CPDuplicateKeyType) GetProcAddress(g_hDllInstance, "CPDuplicateKey")		;

	if (!acquireContext || !releaseContext || !genKey || !deriveKey || !destroyKey ||
		!setKeyParam || !getKeyParam || !setHashParam || !getHashParam || !exportKey ||
		!importKey || !encrypt || !decrypt || !createHash ||
		!hashData || !hashSessionKey || !signHash || !destroyHash || !verifySignature ||
		!genRandom || !getUserKey || !setProvParam ||
		!getProvParam )
	{
		FreeLibrary(g_hDllInstance);
		g_hDllInstance = NULL;
		return FALSE;
	}

	g_isInitialized = true;
	return TRUE;
}


/******************************************
 * Main entry point
 ******************************************/

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH) 
    {
        g_hModule = hInstance;
	}
	else if (dwReason == DLL_PROCESS_DETACH) 
    {
		if (g_hDllInstance)
			FreeLibrary(g_hDllInstance);
	}

	return TRUE;
}

/******************************************
 * CSP functions implementation
 ******************************************/

#define CSP_FUNC_PROLOG	{ \
							try

#define CSP_FUNC_EPILOG		catch (CCSPException& ex) { \
								SetLastError(ex.GetCode()); \
								return FALSE; \
							} \
							catch (...) { \
								SetLastError(NTE_FAIL); \
								return FALSE; \
							} \
							return TRUE; \
						}


// CPAcquireContext
BOOL WINAPI CPAcquireContext(
    HCRYPTPROV *phProv,
    LPCSTR szContainer,
    DWORD dwFlags,
    PVTableProvStruc pVTable)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!acquireContext(phProv, szContainer, dwFlags, pVTable))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}	
}
CSP_FUNC_EPILOG

// CPReleaseContext
BOOL WINAPI CPReleaseContext(
    HCRYPTPROV hProv,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!releaseContext(hProv, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPGenKey
BOOL WINAPI CPGenKey(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    DWORD dwFlags,
    HCRYPTKEY *phKey)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!genKey(hProv, Algid, dwFlags, phKey))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPDeriveKey
BOOL WINAPI CPDeriveKey(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTHASH hHash,
    DWORD dwFlags,
    HCRYPTKEY *phKey)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!deriveKey(hProv, Algid, hHash, dwFlags, phKey))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPDestroyKey
BOOL WINAPI CPDestroyKey(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!destroyKey(hProv, hKey))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPSetKeyParam
BOOL WINAPI CPSetKeyParam(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    DWORD dwParam,
    CONST BYTE *pbData,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!setKeyParam(hProv, hKey, dwParam, pbData, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

//CPGetKeyParam
BOOL WINAPI CPGetKeyParam(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    DWORD dwParam,
    LPBYTE pbData,
    LPDWORD pcbDataLen,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!getKeyParam(hProv, hKey, dwParam, pbData, pcbDataLen, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPSetProvParam
BOOL WINAPI CPSetProvParam(
    HCRYPTPROV hProv,
    DWORD dwParam,
    CONST BYTE *pbData,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!setProvParam(hProv, dwParam, pbData, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPGetProvParam
BOOL WINAPI CPGetProvParam(
    HCRYPTPROV hProv,
    DWORD dwParam,
    LPBYTE pbData,
    LPDWORD pcbDataLen,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

    if (!getProvParam(hProv, dwParam, pbData, pcbDataLen, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPSetHashParam
BOOL WINAPI CPSetHashParam(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    DWORD dwParam,
    CONST BYTE *pbData,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!setHashParam(hProv, hHash, dwParam, pbData, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPGetHashParam
BOOL WINAPI CPGetHashParam(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    DWORD dwParam,
    LPBYTE pbData,
    LPDWORD pcbDataLen,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!getHashParam(hProv, hHash, dwParam, pbData, pcbDataLen, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPExportKey
BOOL WINAPI CPExportKey(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    HCRYPTKEY hPubKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    LPBYTE pbData,
    LPDWORD pcbDataLen)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!exportKey(hProv, hKey, hPubKey, dwBlobType, dwFlags, pbData, pcbDataLen))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPImportKey
BOOL WINAPI CPImportKey(
    HCRYPTPROV hProv,
    CONST BYTE *pbData,
    DWORD cbDataLen,
    HCRYPTKEY hPubKey,
    DWORD dwFlags,
    HCRYPTKEY *phKey)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!importKey(hProv, pbData, cbDataLen, hPubKey, dwFlags, phKey))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPEncrypt
BOOL WINAPI CPEncrypt(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL fFinal,
    DWORD dwFlags,
    LPBYTE pbData,
    LPDWORD pcbDataLen,
    DWORD cbBufLen)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!encrypt(hProv, hKey, hHash, fFinal, dwFlags, pbData, pcbDataLen, cbBufLen))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPDecrypt
BOOL WINAPI CPDecrypt(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL fFinal,
    DWORD dwFlags,
    LPBYTE pbData,
    LPDWORD pcbDataLen)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!decrypt(hProv, hKey, hHash, fFinal, dwFlags, pbData, pcbDataLen))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPCreateHash
BOOL WINAPI CPCreateHash(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTKEY hKey,
    DWORD dwFlags,
    HCRYPTHASH *phHash)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!createHash(hProv, Algid, hKey, dwFlags, phHash))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPHashData
BOOL WINAPI CPHashData(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    CONST BYTE *pbData,
    DWORD cbDataLen,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!hashData(hProv, hHash, pbData, cbDataLen, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPHashSessionKey
BOOL WINAPI CPHashSessionKey(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    HCRYPTKEY hKey,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!hashSessionKey(hProv, hHash, hKey, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPSignHash
BOOL WINAPI CPSignHash(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    DWORD dwKeySpec,
    LPCWSTR szDescription,
    DWORD dwFlags,
    LPBYTE pbSignature,
    LPDWORD pcbSigLen)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!signHash(hProv, hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pcbSigLen))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPDestroyHash
BOOL WINAPI CPDestroyHash(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!destroyHash(hProv, hHash))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPVerifySignature
BOOL WINAPI CPVerifySignature(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    CONST BYTE *pbSignature,
    DWORD cbSigLen,
    HCRYPTKEY hPubKey,
    LPCWSTR szDescription,
    DWORD dwFlags)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!verifySignature(hProv, hHash, pbSignature, cbSigLen, hPubKey, szDescription, dwFlags))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPGenRandom
BOOL WINAPI CPGenRandom(
    HCRYPTPROV hProv,
    DWORD cbLen,
    LPBYTE pbBuffer)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!genRandom(hProv, cbLen, pbBuffer))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPGetUserKey
BOOL WINAPI CPGetUserKey(
    HCRYPTPROV hProv,
    DWORD dwKeySpec,
    HCRYPTKEY *phUserKey)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!getUserKey(hProv, dwKeySpec, phUserKey))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPDuplicateHash
BOOL WINAPI CPDuplicateHash(
    HCRYPTPROV hProv,
    HCRYPTHASH hHash,
    LPDWORD pdwReserved,
    DWORD dwFlags,
    HCRYPTHASH *phHash)
CSP_FUNC_PROLOG
{
	if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!duplicateHash)
		throw CCSPException(ERROR_CALL_NOT_IMPLEMENTED);

	if (!duplicateHash(hProv, hHash, pdwReserved, dwFlags, phHash))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG

// CPDuplicateKey
BOOL WINAPI CPDuplicateKey(
    HCRYPTPROV hProv,
    HCRYPTKEY hKey,
    LPDWORD pdwReserved,
    DWORD dwFlags,
    HCRYPTKEY *phKey)
CSP_FUNC_PROLOG
{
    if (!InitializeLibrary())
		throw CCSPException(NTE_FAIL);

	if (!duplicateKey)
		throw CCSPException(ERROR_CALL_NOT_IMPLEMENTED);

	if (!duplicateKey(hProv, hKey, pdwReserved, dwFlags, phKey))
	{
		DWORD dwErr = GetLastError();
		throw CCSPException(dwErr);
	}
}
CSP_FUNC_EPILOG
