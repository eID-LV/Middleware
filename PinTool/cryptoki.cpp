
#include "cryptoki.h"
#include <wx/thread.h>


CK_RV _cdecl MyCreateMutex(CK_VOID_PTR_PTR ppMutex)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	if(ppMutex)
	{
		*ppMutex = new wxMutex();
		rv = CKR_OK;
	}

	return rv;
}

CK_RV _cdecl MyDestroyMutex(CK_VOID_PTR pMutex)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	if(pMutex)
	{
		wxMutex* m = (wxMutex*) pMutex;
		delete m;
		rv = CKR_OK;
	}
	return rv;
}

CK_RV _cdecl MyLockMutex(CK_VOID_PTR pMutex)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	if(pMutex)
	{
		wxMutex* m  =(wxMutex*) pMutex;
		rv = m->Lock();
		if(rv != wxMUTEX_NO_ERROR)
			rv = CKR_CANT_LOCK;
	}
	return rv;
}

CK_RV _cdecl MyUnlockMutex(CK_VOID_PTR pMutex)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	if(pMutex)
	{
		wxMutex* m  =(wxMutex*) pMutex;
		rv = m->Unlock();
		if(rv != wxMUTEX_NO_ERROR)
			rv = CKR_MUTEX_NOT_LOCKED;
	}
	return rv;
}


//////////////////////////////////////////////////////////
wxChar staticBuffer[256];

static CK_RV CKlist[]={

CKR_OK ,
CKR_CANCEL                            ,
CKR_HOST_MEMORY                       ,
CKR_SLOT_ID_INVALID                   ,
/* CKR_FLAGS_INVALID was removed for v2.0 */
/* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
CKR_GENERAL_ERROR                     ,
CKR_FUNCTION_FAILED                   ,
/* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
 * and CKR_CANT_LOCK are new for v2.01 */
CKR_ARGUMENTS_BAD                     ,
CKR_NO_EVENT                          ,
CKR_NEED_TO_CREATE_THREADS            ,
CKR_CANT_LOCK                         ,
CKR_ATTRIBUTE_READ_ONLY               ,
CKR_ATTRIBUTE_SENSITIVE               ,
CKR_ATTRIBUTE_TYPE_INVALID            ,
CKR_ATTRIBUTE_VALUE_INVALID           ,
CKR_DATA_INVALID                      ,
CKR_DATA_LEN_RANGE                    ,
CKR_DEVICE_ERROR                      ,
CKR_DEVICE_MEMORY                     ,
CKR_DEVICE_REMOVED                    ,
CKR_ENCRYPTED_DATA_INVALID            ,
CKR_ENCRYPTED_DATA_LEN_RANGE          ,
CKR_FUNCTION_CANCELED                 ,
CKR_FUNCTION_NOT_PARALLEL             ,
/* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
CKR_FUNCTION_NOT_SUPPORTED            ,
CKR_KEY_HANDLE_INVALID                ,
/* CKR_KEY_SENSITIVE was removed for v2.0 */
CKR_KEY_SIZE_RANGE                    ,
CKR_KEY_TYPE_INCONSISTENT             ,
/* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
 * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
 * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
 * v2.0 */
CKR_KEY_NOT_NEEDED                    ,
CKR_KEY_CHANGED                       ,
CKR_KEY_NEEDED                        ,
CKR_KEY_INDIGESTIBLE                  ,
CKR_KEY_FUNCTION_NOT_PERMITTED        ,
CKR_KEY_NOT_WRAPPABLE                 ,
CKR_KEY_UNEXTRACTABLE                 ,
CKR_MECHANISM_INVALID                 ,
CKR_MECHANISM_PARAM_INVALID           ,
/* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
 * were removed for v2.0 */
CKR_OBJECT_HANDLE_INVALID             ,
CKR_OPERATION_ACTIVE                  ,
CKR_OPERATION_NOT_INITIALIZED         ,
CKR_PIN_INCORRECT                     ,
CKR_PIN_INVALID                       ,
CKR_PIN_LEN_RANGE                     ,
/* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
CKR_PIN_EXPIRED                       ,
CKR_PIN_LOCKED                        ,
CKR_SESSION_CLOSED                    ,
CKR_SESSION_COUNT                     ,
CKR_SESSION_HANDLE_INVALID            ,
CKR_SESSION_PARALLEL_NOT_SUPPORTED    ,
CKR_SESSION_READ_ONLY                 ,
CKR_SESSION_EXISTS                    ,
/* CKR_SESSION_READ_ONLY_EXISTS and
 * CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
CKR_SESSION_READ_ONLY_EXISTS          ,
CKR_SESSION_READ_WRITE_SO_EXISTS      ,
CKR_SIGNATURE_INVALID                 ,
CKR_SIGNATURE_LEN_RANGE               ,
CKR_TEMPLATE_INCOMPLETE               ,
CKR_TEMPLATE_INCONSISTENT             ,
CKR_TOKEN_NOT_PRESENT                 ,
CKR_TOKEN_NOT_RECOGNIZED              ,
CKR_TOKEN_WRITE_PROTECTED             ,
CKR_UNWRAPPING_KEY_HANDLE_INVALID     ,
CKR_UNWRAPPING_KEY_SIZE_RANGE         ,
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  ,
CKR_USER_ALREADY_LOGGED_IN            ,
CKR_USER_NOT_LOGGED_IN                ,
CKR_USER_PIN_NOT_INITIALIZED          ,
CKR_USER_TYPE_INVALID                 ,
/* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
 * are new to v2.01 */
CKR_USER_ANOTHER_ALREADY_LOGGED_IN    ,
CKR_USER_TOO_MANY_TYPES               ,
CKR_WRAPPED_KEY_INVALID               ,
CKR_WRAPPED_KEY_LEN_RANGE             ,
CKR_WRAPPING_KEY_HANDLE_INVALID       ,
CKR_WRAPPING_KEY_SIZE_RANGE           ,
CKR_WRAPPING_KEY_TYPE_INCONSISTENT    ,
CKR_RANDOM_SEED_NOT_SUPPORTED         ,
/* These are new to v2.0 */
CKR_RANDOM_NO_RNG                     ,
/* These are new to v2.11 */
CKR_DOMAIN_PARAMS_INVALID             ,
/* These are new to v2.0 */
CKR_BUFFER_TOO_SMALL                  ,
CKR_SAVED_STATE_INVALID               ,
CKR_INFORMATION_SENSITIVE             ,
CKR_STATE_UNSAVEABLE                  ,
/* These are new to v2.01 */
CKR_CRYPTOKI_NOT_INITIALIZED          ,
CKR_CRYPTOKI_ALREADY_INITIALIZED      ,
CKR_MUTEX_BAD                         ,
CKR_MUTEX_NOT_LOCKED                  ,
/* This is new to v2.20 */
CKR_FUNCTION_REJECTED                 
};
				

const wxChar* CKnames[]={
wxT("CKR_OK"),
wxT("CKR_CANCEL"),
wxT("CKR_HOST_MEMORY"),
wxT("CKR_SLOT_ID_INVALID"),
/* wxT("CKR_FLAGS_INVALID was removed for v2.0 */
/* wxT("CKR_GENERAL_ERROR and wxT("CKR_FUNCTION_FAILED are new for v2.0 */
wxT("CKR_GENERAL_ERROR"),
wxT("CKR_FUNCTION_FAILED"),
/* wxT("CKR_ARGUMENTS_BAD, wxT("CKR_NO_EVENT, wxT("CKR_NEED_TO_CREATE_THREADS,
 * and wxT("CKR_CANT_LOCK are new for v2.01 */
wxT("CKR_ARGUMENTS_BAD"),
wxT("CKR_NO_EVENT"),
wxT("CKR_NEED_TO_CREATE_THREADS"),
wxT("CKR_CANT_LOCK"),
wxT("CKR_ATTRIBUTE_READ_ONLY"),
wxT("CKR_ATTRIBUTE_SENSITIVE"),
wxT("CKR_ATTRIBUTE_TYPE_INVALID"),
wxT("CKR_ATTRIBUTE_VALUE_INVALID"),
wxT("CKR_DATA_INVALID"),
wxT("CKR_DATA_LEN_RANGE"),
wxT("CKR_DEVICE_ERROR"),
wxT("CKR_DEVICE_MEMORY"),
wxT("CKR_DEVICE_REMOVED"),
wxT("CKR_ENCRYPTED_DATA_INVALID"),
wxT("CKR_ENCRYPTED_DATA_LEN_RANGE"),
wxT("CKR_FUNCTION_CANCELED"),
wxT("CKR_FUNCTION_NOT_PARALLEL"),
/* wxT("CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
wxT("CKR_FUNCTION_NOT_SUPPORTED"),
wxT("CKR_KEY_HANDLE_INVALID"),
/* wxT("CKR_KEY_SENSITIVE was removed for v2.0 */
wxT("CKR_KEY_SIZE_RANGE"),
wxT("CKR_KEY_TYPE_INCONSISTENT"),
/* wxT("CKR_KEY_NOT_NEEDED, wxT("CKR_KEY_CHANGED, wxT("CKR_KEY_NEEDED,
 * wxT("CKR_KEY_INDIGESTIBLE, wxT("CKR_KEY_FUNCTION_NOT_PERMITTED,
 * wxT("CKR_KEY_NOT_WRAPPABLE, and wxT("CKR_KEY_UNEXTRACTABLE are new for
 * v2.0 */
wxT("CKR_KEY_NOT_NEEDED"),
wxT("CKR_KEY_CHANGED"),
wxT("CKR_KEY_NEEDED"),
wxT("CKR_KEY_INDIGESTIBLE"),
wxT("CKR_KEY_FUNCTION_NOT_PERMITTED"),
wxT("CKR_KEY_NOT_WRAPPABLE"),
wxT("CKR_KEY_UNEXTRACTABLE"),
wxT("CKR_MECHANISM_INVALID"),
wxT("CKR_MECHANISM_PARAM_INVALID"),
/* wxT("CKR_OBJECT_CLASS_INCONSISTENT and wxT("CKR_OBJECT_CLASS_INVALID
 * were removed for v2.0 */
wxT("CKR_OBJECT_HANDLE_INVALID"),
wxT("CKR_OPERATION_ACTIVE"),
wxT("CKR_OPERATION_NOT_INITIALIZED"),
wxT("CKR_PIN_INCORRECT"),
wxT("CKR_PIN_INVALID"),
wxT("CKR_PIN_LEN_RANGE"),
/* wxT("CKR_PIN_EXPIRED and wxT("CKR_PIN_LOCKED are new for v2.0 */
wxT("CKR_PIN_EXPIRED"),
wxT("CKR_PIN_LOCKED"),
wxT("CKR_SESSION_CLOSED"),
wxT("CKR_SESSION_COUNT"),
wxT("CKR_SESSION_HANDLE_INVALID"),
wxT("CKR_SESSION_PARALLEL_NOT_SUPPORTED"),
wxT("CKR_SESSION_READ_ONLY"),
wxT("CKR_SESSION_EXISTS"),
/* wxT("CKR_SESSION_READ_ONLY_EXISTS and
 * wxT("CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
wxT("CKR_SESSION_READ_ONLY_EXISTS"),
wxT("CKR_SESSION_READ_WRITE_SO_EXISTS"),
wxT("CKR_SIGNATURE_INVALID"),
wxT("CKR_SIGNATURE_LEN_RANGE"),
wxT("CKR_TEMPLATE_INCOMPLETE"),
wxT("CKR_TEMPLATE_INCONSISTENT"),
wxT("CKR_TOKEN_NOT_PRESENT"),
wxT("CKR_TOKEN_NOT_RECOGNIZED"),
wxT("CKR_TOKEN_WRITE_PROTECTED"),
wxT("CKR_UNWRAPPING_KEY_HANDLE_INVALID"),
wxT("CKR_UNWRAPPING_KEY_SIZE_RANGE"),
wxT("CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"),
wxT("CKR_USER_ALREADY_LOGGED_IN"),
wxT("CKR_USER_NOT_LOGGED_IN"),
wxT("CKR_USER_PIN_NOT_INITIALIZED"),
wxT("CKR_USER_TYPE_INVALID"),
/* wxT("CKR_USER_ANOTHER_ALREADY_LOGGED_IN and wxT("CKR_USER_TOO_MANY_TYPES
 * are new to v2.01 */
wxT("CKR_USER_ANOTHER_ALREADY_LOGGED_IN"),
wxT("CKR_USER_TOO_MANY_TYPES"),
wxT("CKR_WRAPPED_KEY_INVALID"),
wxT("CKR_WRAPPED_KEY_LEN_RANGE"),
wxT("CKR_WRAPPING_KEY_HANDLE_INVALID"),
wxT("CKR_WRAPPING_KEY_SIZE_RANGE"),
wxT("CKR_WRAPPING_KEY_TYPE_INCONSISTENT"),
wxT("CKR_RANDOM_SEED_NOT_SUPPORTED"),
/* These are new to v2.0 */
wxT("CKR_RANDOM_NO_RNG"),
/* These are new to v2.11 */
wxT("CKR_DOMAIN_PARAMS_INVALID"),
/* These are new to v2.0 */
wxT("CKR_BUFFER_TOO_SMALL"),
wxT("CKR_SAVED_STATE_INVALID"),
wxT("CKR_INFORMATION_SENSITIVE"),
wxT("CKR_STATE_UNSAVEABLE"),
/* These are new to v2.01 */
wxT("CKR_CRYPTOKI_NOT_INITIALIZED"),
wxT("CKR_CRYPTOKI_ALREADY_INITIALIZED"),
wxT("CKR_MUTEX_BAD"),
wxT("CKR_MUTEX_NOT_LOCKED"),
/* This is new to v2.20 */
wxT("CKR_FUNCTION_REJECTED")                
};     
             
const wxChar* CK_RVtoName(CK_RV status){

	if (status == CKR_OK) return _("No error");
	int CKlistLength =sizeof(CKlist)/sizeof(CK_RV);
	for (int j = 0; j < CKlistLength; j++) {
        if (CKlist[j] == status)
            return CKnames[j];
	}


	wxSnprintf(staticBuffer,256,wxT("0x%.8X"), status);
	return staticBuffer;
}

