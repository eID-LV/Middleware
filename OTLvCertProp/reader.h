// ---------------------------------
//
#pragma once

class CAutoCriticalSection
{
protected:
	CRITICAL_SECTION& mLock;
public:
	CAutoCriticalSection(CRITICAL_SECTION& section) : mLock(section)
	{
		EnterCriticalSection(&mLock);
	}

	~CAutoCriticalSection()
	{
		LeaveCriticalSection(&mLock);
	}
};

class CBuffer {
private:
	BYTE *m_pbData;
	DWORD m_dwDataLength;
public:
	CBuffer()				{ m_pbData = NULL; m_dwDataLength = 0; }
	CBuffer(DWORD c)		{ if (c) m_pbData = new BYTE[c]; else m_pbData = NULL; m_dwDataLength = c;}
	CBuffer(const CBuffer& buf);
	CBuffer(LPCBYTE pData, DWORD dwDataLength);
	~CBuffer()				{ Reset();}
	operator BYTE *()		{ return m_pbData; }
	DWORD GetLength()		{ return m_dwDataLength; }
	void Reset()			{ if (m_pbData) { memset(m_pbData,0,m_dwDataLength); delete[] m_pbData; } 
							  m_pbData = NULL; m_dwDataLength = 0;									}
	void Alloc(DWORD c)		{ Reset(); m_pbData = new BYTE[c]; m_dwDataLength = c;}
};

// ---------------------------------

#define POLL_PERIOD 500

class CReaderListener
{
public:
	virtual void NotifyReaderPlug(SCARD_READERSTATE& state) = 0;
	virtual void NotifyReaderChange(SCARD_READERSTATE& state) = 0;
	virtual void NotifyReaderUnplug(LPCTSTR szReaderName) = 0;
};

class CReaderMonitor
{

private:

	static DWORD g_dwScope;

	static SCARDCONTEXT g_hContext;
	static CReaderListener *g_pListener;

	HANDLE m_hMonitorThread;
	static LPTSTR g_mszReaderNames;
	static DWORD g_cReaderStates;
	static SCARD_READERSTATE *g_pReaderStates;
	static LONG volatile g_fExit;
	static HANDLE g_readersCheckedEvent;
    static bool volatile g_bReadersListInitialized;

	static DWORD WINAPI ReaderMonitorProc(void *pParam);
	static void ResetGlobals();

	static void NotifyReaderPlug(SCARD_READERSTATE& state);
	static void NotifyReaderChange(SCARD_READERSTATE& state);
	static void NotifyReaderUnplug(LPCTSTR szReaderName);

public:

	CReaderMonitor(DWORD dwScope, CReaderListener *pListener);
	~CReaderMonitor();

	void start();
	void stop(bool mustWait);

};

