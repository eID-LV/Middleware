/** \file Reader.cpp 
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
#include "Reader.h"
#include <process.h>


// -----------------------------------------------------------
LONG volatile CReaderMonitor::g_fExit = 0;
LPTSTR CReaderMonitor::g_mszReaderNames = NULL;
DWORD CReaderMonitor::g_cReaderStates = 0;
SCARD_READERSTATE *CReaderMonitor::g_pReaderStates = NULL;
SCARDCONTEXT CReaderMonitor::g_hContext = NULL;
CReaderListener *CReaderMonitor::g_pListener = NULL;
DWORD CReaderMonitor::g_dwScope = 0;
HANDLE CReaderMonitor::g_readersCheckedEvent = NULL;
bool volatile CReaderMonitor::g_bReadersListInitialized = false;

void CReaderMonitor::ResetGlobals()
{
	if(g_mszReaderNames)
		delete [] g_mszReaderNames, g_mszReaderNames = NULL;
	g_cReaderStates = 0;
	if(g_pReaderStates)
		delete [] g_pReaderStates, g_pReaderStates = NULL;
	if (g_hContext)
		SCardReleaseContext(g_hContext),g_hContext=NULL;
    g_bReadersListInitialized = false;
}

CReaderMonitor::CReaderMonitor(DWORD dwScope, CReaderListener *pListener)
{
	g_pListener = pListener;
	g_dwScope = dwScope;
	m_hMonitorThread = NULL;

	ResetGlobals();

	g_readersCheckedEvent = CreateEvent(NULL,FALSE,FALSE, NULL);
}

CReaderMonitor::~CReaderMonitor()
{
	stop(true);
	CloseHandle(g_readersCheckedEvent);
    g_readersCheckedEvent = NULL;
}

void CReaderMonitor::start()
{
	if(!m_hMonitorThread)
	{
		DWORD dwThreadId;
		m_hMonitorThread = CreateThread(NULL, 0, ReaderMonitorProc, (void *)this, 0, &dwThreadId);
		WaitForSingleObject(g_readersCheckedEvent,10000);
		for (int i=0; i < 10; i++)
		{
			if (!g_bReadersListInitialized)
				Sleep(1000);
			else
				break;
		}
	}
}

void CReaderMonitor::stop(bool mustWait)
{
	if (m_hMonitorThread) {
		g_pListener = NULL;
		InterlockedIncrement(&g_fExit);
        if (SCARD_S_SUCCESS == SCardIsValidContext(g_hContext))
            SCardCancel(g_hContext);
		if(mustWait)
		{
			if (WaitForSingleObject(m_hMonitorThread, POLL_PERIOD * 4) == WAIT_TIMEOUT)
				TerminateThread(m_hMonitorThread, 0);
			InterlockedDecrement(&g_fExit);
			CloseHandle(m_hMonitorThread);
		}
		else
		{
			TerminateThread(m_hMonitorThread, 0);
			InterlockedDecrement(&g_fExit);
			CloseHandle(m_hMonitorThread);
		}
		
		m_hMonitorThread = NULL;
	}
}

DWORD WINAPI CReaderMonitor::ReaderMonitorProc(void* param)
{
	HRESULT hRes;
	LPTSTR mszNewReaderNames = NULL;

	while (!InterlockedCompareExchange(&g_fExit,0,0)) {

		if (g_hContext == 0) {
			// trying to establish context
			hRes = SCardEstablishContext(g_dwScope, NULL, NULL, &g_hContext);
			if (hRes != SCARD_S_SUCCESS) {
				Sleep(POLL_PERIOD);
				if(InterlockedCompareExchange(&g_fExit,1,1))
					break;
				g_hContext = 0;
			}
		}

		if (g_hContext) {

            if (SCARD_S_SUCCESS == SCardIsValidContext(g_hContext))
            {
			    // rescan reader list...
			    mszNewReaderNames = NULL;
			    DWORD cchReaderNames = 0;
			    do {
				    hRes = SCardListReaders(g_hContext, NULL, NULL, &cchReaderNames);
                if ((hRes == SCARD_S_SUCCESS) && cchReaderNames) {
					    mszNewReaderNames = new TCHAR[cchReaderNames];
					    hRes = SCardListReaders(g_hContext, NULL, mszNewReaderNames, &cchReaderNames);
					    if (hRes != SCARD_S_SUCCESS) {
						    delete[] mszNewReaderNames;
						    mszNewReaderNames = NULL;
					    }
				    }
			    }
			    while (hRes == SCARD_E_INSUFFICIENT_BUFFER);
            }
            else
                hRes = SCARD_E_NO_SERVICE;

			if(InterlockedCompareExchange(&g_fExit,1,1))
				break;

			// check reader listing status
			DWORD cNewReaderStates = 0;
			SCARD_READERSTATE *pNewReaderStates = NULL;
			switch (hRes) {
            case ERROR_INVALID_HANDLE:
			case SCARD_E_INVALID_HANDLE:
			case SCARD_E_NO_SERVICE:
			case SCARD_E_SERVICE_STOPPED:
				SCardReleaseContext(g_hContext);
				g_hContext = 0;
				hRes = SCARD_S_SUCCESS;
				break;
			case SCARD_E_NO_READERS_AVAILABLE:
				hRes = SCARD_S_SUCCESS;
				break;
			case SCARD_S_SUCCESS:
				for (LPCTSTR pReader = mszNewReaderNames; *pReader != 0; pReader += _tcslen(pReader) + 1)
					cNewReaderStates++;
				if (cNewReaderStates)
				{
					pNewReaderStates = new SCARD_READERSTATE[cNewReaderStates];
					memset(pNewReaderStates,0,cNewReaderStates* sizeof(SCARD_READERSTATE));
				}
			default:
				break;
			}

			if(InterlockedCompareExchange(&g_fExit,1,1))
				break;
			
			if (hRes == SCARD_S_SUCCESS) {
				// compare readers
				DWORD j;
				for (j = 0; j < g_cReaderStates; j++)
					g_pReaderStates[j].pvUserData = (LPVOID)1;
				LPCTSTR pReader = mszNewReaderNames;
				DWORD i = 0;
				if (pReader) {
					while (*pReader != 0) {
						pNewReaderStates[i].pvUserData = (LPVOID)1;
						pNewReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
						for (j = 0; j < g_cReaderStates; j++) {
							if (_tcscmp(pReader, g_pReaderStates[j].szReader) == 0) {
								g_pReaderStates[j].pvUserData = NULL;
								pNewReaderStates[i] = g_pReaderStates[j];
								break;
							}
						}

						pNewReaderStates[i].szReader = pReader;
						pReader += _tcslen(pReader) + 1;
						i++;
					}
				}

				// check removed readers
				for (j = 0; j < g_cReaderStates; j++) {
					if (g_pReaderStates[j].pvUserData != NULL) {
						NotifyReaderUnplug(g_pReaderStates[j].szReader);
						if(InterlockedCompareExchange(&g_fExit,1,1))
							goto end_label;
					}
				}

				// update current list
				if (g_pReaderStates)
					delete[] g_pReaderStates;
				if (g_mszReaderNames)
					delete[] g_mszReaderNames;
				g_mszReaderNames = mszNewReaderNames;
				g_pReaderStates = pNewReaderStates;
				g_cReaderStates = cNewReaderStates;
				mszNewReaderNames = NULL;
			}

			// check reader states
			if (g_cReaderStates == 0) {
                if (!g_bReadersListInitialized)
                {
                   SetEvent(g_readersCheckedEvent);
                   g_bReadersListInitialized = true;
                }
				Sleep(POLL_PERIOD);
				if(InterlockedCompareExchange(&g_fExit,1,1))
					break;
			}
			else {
				hRes = SCardGetStatusChange(g_hContext, POLL_PERIOD, g_pReaderStates, g_cReaderStates);
				if(InterlockedCompareExchange(&g_fExit,1,1))
					break;
				if (hRes == SCARD_S_SUCCESS) {
					// check changed readers...
					for (DWORD i = 0; i < g_cReaderStates && !InterlockedCompareExchange(&g_fExit,0,0); i++) {
						if (g_pReaderStates[i].pvUserData != NULL) {
							// new reader
							g_pReaderStates[i].pvUserData = NULL;
							g_pReaderStates[i].dwEventState &= ~SCARD_STATE_CHANGED;
                            g_pReaderStates[i].dwCurrentState = g_pReaderStates[i].dwEventState;
                            if ((g_pReaderStates[i].dwEventState & (SCARD_STATE_IGNORE | SCARD_STATE_MUTE)) == 0)
							    NotifyReaderPlug(g_pReaderStates[i]);
							if(InterlockedCompareExchange(&g_fExit,1,1))
								goto end_label;
							
						}
						else if (g_pReaderStates[i].dwEventState & SCARD_STATE_CHANGED) {
							// existing reader
							g_pReaderStates[i].dwEventState &= ~SCARD_STATE_CHANGED;
							if (    ((g_pReaderStates[i].dwEventState & (SCARD_STATE_IGNORE | SCARD_STATE_MUTE)) == 0)
                                &&  ((g_pReaderStates[i].dwCurrentState & SCARD_STATE_MUTE) == 0)
                                &&  (   ((g_pReaderStates[i].dwCurrentState & SCARD_STATE_PRESENT) && (!(g_pReaderStates[i].dwEventState & SCARD_STATE_PRESENT)))
                                      ||((!(g_pReaderStates[i].dwCurrentState & SCARD_STATE_PRESENT)) && (g_pReaderStates[i].dwEventState & SCARD_STATE_PRESENT))
                                    )
                               )
                            {
								NotifyReaderChange(g_pReaderStates[i]);
                            }
                            g_pReaderStates[i].dwCurrentState = g_pReaderStates[i].dwEventState & (~(SCARD_STATE_CHANGED | SCARD_STATE_IGNORE));
							if(InterlockedCompareExchange(&g_fExit,1,1))
								goto end_label; 
						}
					}
                }
                else if (hRes != SCARD_E_TIMEOUT)
                {
                    if(InterlockedCompareExchange(&g_fExit,1,1))
                        goto end_label; 

                    // something strange happened. Act as if all readers where disconnected
                    for (DWORD i = 0; i < g_cReaderStates; i++)
                    {
                        NotifyReaderUnplug(g_pReaderStates[i].szReader);
						if(InterlockedCompareExchange(&g_fExit,1,1))
							goto end_label;
                    }

				    if (g_pReaderStates)
					    delete[] g_pReaderStates;
				    if (g_mszReaderNames)
					    delete[] g_mszReaderNames;
				    g_mszReaderNames = NULL;
				    g_pReaderStates = NULL;
				    g_cReaderStates = 0;
				    SCardReleaseContext(g_hContext);
				    g_hContext = 0;
                }
                if (!g_bReadersListInitialized)
                {
                   SetEvent(g_readersCheckedEvent);
                   g_bReadersListInitialized = true;
                }				
			}
		}
	}
end_label:

	ResetGlobals();
	if(mszNewReaderNames)
		delete [] mszNewReaderNames;

	return 0;
}

void CReaderMonitor::NotifyReaderPlug(SCARD_READERSTATE& state)
{
	if (g_pListener && !InterlockedCompareExchange(&g_fExit,0,0))
		g_pListener->NotifyReaderPlug(state);
}

void CReaderMonitor::NotifyReaderChange(SCARD_READERSTATE& state)
{
	if (g_pListener && !InterlockedCompareExchange(&g_fExit,0,0))
		g_pListener->NotifyReaderChange(state);
}

void CReaderMonitor::NotifyReaderUnplug(LPCTSTR szReaderName)
{
	if (g_pListener && !InterlockedCompareExchange(&g_fExit,0,0))
		g_pListener->NotifyReaderUnplug(szReaderName);
}


