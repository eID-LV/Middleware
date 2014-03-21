#ifndef PTCRYPTOKI_H
#define PTCRYPTOKI_H

#include <wx/wx.h>
#include <wx/dynlib.h>

#ifndef _WIN32
#include <wchar.h>
#include <unistd.h>
typedef unsigned long DWORD;
typedef unsigned char BOOL;
typedef unsigned char BYTE;
#define PBYTE unsigned char*
#define LPBYTE unsigned char*
typedef wxChar TCHAR;
#define LPCTSTR	const wxChar*
#define __declspec(a)
#define _cdecl
#ifdef _UNICODE
#define	_tcslen	wcslen
#define _tcscat	wcscat
#define _tchdir	wchdir
#else
#define	_tcslen	strlen
#define _tcscat	strcat
#define _tchdir chdir
#endif
#endif

extern "C" {

//	PKCS#11 V2 header files
#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name)			returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION(returnType, name)			returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)	returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name)			returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11/2.20/pkcs11.h"
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif
}

CK_RV _cdecl MyCreateMutex(CK_VOID_PTR_PTR ppMutex);
CK_RV _cdecl MyDestroyMutex(CK_VOID_PTR pMutex);
CK_RV _cdecl MyLockMutex(CK_VOID_PTR pMutex);
CK_RV _cdecl MyUnlockMutex(CK_VOID_PTR pMutex);

// return a string description of the error status
const wxChar* CK_RVtoName(CK_RV status) ;

class CCryptoki
{
protected:
	CK_FUNCTION_LIST_PTR	m_cryptoki;
public:
	CCryptoki() : m_cryptoki(NULL)
	{

	}

	~CCryptoki()
	{ 
    }

	void Set(CK_FUNCTION_LIST_PTR	cryptoki) { m_cryptoki = cryptoki;}

	CK_RV C_Initialize(CK_VOID_PTR   pInitArgs)
	{
		CK_RV rv = m_cryptoki->C_Initialize(pInitArgs);
		return rv;
	}

	CK_RV C_GetInfo(CK_INFO_PTR   pInfo)
	{
		CK_RV rv = m_cryptoki->C_GetInfo(pInfo);
		return rv;
	}

	CK_RV C_Finalize(CK_VOID_PTR   pReserved)
	{
		CK_RV rv = m_cryptoki->C_Finalize(pReserved);
		return rv;
	}

	CK_RV C_WaitForSlotEvent(
		  CK_FLAGS flags,   
		  CK_SLOT_ID_PTR pSlot,
		  CK_VOID_PTR pRserved)
	{
		return m_cryptoki->C_WaitForSlotEvent(flags,pSlot,pRserved);
	}

	CK_RV C_GetSlotList(
		  CK_BBOOL       tokenPresent,
		  CK_SLOT_ID_PTR pSlotList,
		  CK_ULONG_PTR   pulCount)
	{
		CK_RV rv = m_cryptoki->C_GetSlotList(tokenPresent,pSlotList,pulCount);
		return rv;
	}

	CK_RV C_GetSlotInfo(
		  CK_SLOT_ID       slotID,
		  CK_SLOT_INFO_PTR pInfo)
	{
		CK_RV rv = m_cryptoki->C_GetSlotInfo(slotID,pInfo);
		return rv;
	}

	CK_RV C_GetTokenInfo(
		  CK_SLOT_ID        slotID,  
		  CK_TOKEN_INFO_PTR pInfo)
	{
		CK_RV rv = m_cryptoki->C_GetTokenInfo(slotID,pInfo);
		return rv;

	}

	CK_RV C_OpenSession(
		  CK_SLOT_ID            slotID,        /* the slot's ID */
		  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
		  CK_VOID_PTR           pApplication,  /* passed to callback */
		  CK_NOTIFY             Notify,        /* callback function */
		  CK_SESSION_HANDLE_PTR phSession)
	{
		CK_RV rv = m_cryptoki->C_OpenSession(slotID,flags,pApplication,Notify,phSession);
		return rv;
	}

	CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
	{
		CK_RV rv = m_cryptoki->C_CloseSession(hSession);
		return rv;
	}

	CK_RV C_CloseAllSessions(CK_SLOT_ID     slotID)
	{
		CK_RV rv = m_cryptoki->C_CloseAllSessions(slotID);
		return rv;
	}

	CK_RV C_GetSessionInfo(
		  CK_SESSION_HANDLE   hSession,  /* the session's handle */
		  CK_SESSION_INFO_PTR pInfo      /* receives session info */
		)
	{
		CK_RV rv = m_cryptoki->C_GetSessionInfo(hSession,pInfo);
		return rv;
	}

	CK_RV C_Login(
		  CK_SESSION_HANDLE hSession,  /* the session's handle */
		  CK_USER_TYPE      userType,  /* the user type */
		  CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
		  CK_ULONG          ulPinLen)
	{
		CK_RV rv = m_cryptoki->C_Login(hSession,userType,pPin,ulPinLen);
		return rv;
	}

	CK_RV C_Logout(
		CK_SESSION_HANDLE hSession
		)
	{
		CK_RV rv = m_cryptoki->C_Logout(hSession);
		return rv;
	}

	CK_RV C_GetAttributeValue(
		  CK_SESSION_HANDLE hSession,   /* the session's handle */
		  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
		  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
		  CK_ULONG          ulCount     /* attributes in template */
		)
	{
		CK_RV rv = m_cryptoki->C_GetAttributeValue(hSession,hObject,pTemplate,ulCount);
		return rv;
	}

	CK_RV C_FindObjectsInit(
	  CK_SESSION_HANDLE hSession,
	  CK_ATTRIBUTE_PTR  pTemplate,
	  CK_ULONG          ulCount)
	{
		CK_RV rv = m_cryptoki->C_FindObjectsInit(hSession,pTemplate,ulCount);
		return rv;
	}

	CK_RV C_FindObjects(
		 CK_SESSION_HANDLE    hSession,          /* session's handle */
		 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
		 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
		 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
		)
	{
		CK_RV rv = m_cryptoki->C_FindObjects(hSession,phObject,ulMaxObjectCount,pulObjectCount);
		return rv;
	}


	CK_RV C_FindObjectsFinal(
		  CK_SESSION_HANDLE hSession 
		)
	{
		CK_RV rv = m_cryptoki->C_FindObjectsFinal(hSession);
		return rv;
	}

	CK_RV C_SetPIN(
	  CK_SESSION_HANDLE hSession,  /* the session's handle */
	  CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
	  CK_ULONG          ulOldLen,  /* length of the old PIN */
	  CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
	  CK_ULONG          ulNewLen   /* length of the new PIN */
	)
	{
		CK_RV rv = m_cryptoki->C_SetPIN(hSession,pOldPin,ulOldLen,pNewPin,ulNewLen);
		return rv;
	}

	CK_RV C_InitPIN(
	  CK_SESSION_HANDLE hSession,  /* the session's handle */
	  CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
	  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
	)
	{
		CK_RV rv = m_cryptoki->C_InitPIN(hSession,pPin,ulPinLen);
		return rv;
	}

};








#endif
