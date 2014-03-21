#include <wx/wx.h>
#include <wx/image.h>
#include <wx/utils.h>
#include <wx/buffer.h>
#include <wx/aboutdlg.h>
#include <wx/filedlg.h>
#include <wx/wfstream.h>
#include <wx/base64.h>
#include <wx/config.h>
#include <wx/filefn.h>
#include <wx/datetime.h>
#include <wx/log.h>
#include <wx/stdpaths.h>
#include <wx/snglinst.h>
#include <vector>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/buffer.h>
#include "PinTool.h"
#include "cryptoki.h"
#include "res/arrow.png.h"
#include "res/ok.png.h"
#include "res/cancel.png.h"
#include "res/welcome_lv.PNG.h"
#include "res/oberthur.png.h"

#ifndef _WIN32
#include <sys/time.h>
#include "res/pintoolicon.xpm"
#endif

/*********************************************************************
 * OpenSSL Helpers                                                   *
 *                                                                   *
 *********************************************************************/
struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result);
/* Take a tm structure and add an offset to it. This avoids any OS issues
 * with restricted date types and overflows which cause the year 2038
 * problem.
 */

#define SECS_PER_DAY (24 * 60 * 60)

static long date_to_julian(int y, int m, int d);
static void julian_to_date(long jd, int *y, int *m, int *d);

int OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec)
	{
	int offset_hms, offset_day;
	long time_jd;
	int time_year, time_month, time_day;
	/* split offset into days and day seconds */
	offset_day = offset_sec / SECS_PER_DAY;
	/* Avoid sign issues with % operator */
	offset_hms  = offset_sec - (offset_day * SECS_PER_DAY);
	offset_day += off_day;
	/* Add current time seconds to offset */
	offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
	/* Adjust day seconds if overflow */
	if (offset_hms >= SECS_PER_DAY)
		{
		offset_day++;
		offset_hms -= SECS_PER_DAY;
		}
	else if (offset_hms < 0)
		{
		offset_day--;
		offset_hms += SECS_PER_DAY;
		}

	/* Convert date of time structure into a Julian day number.
	 */

	time_year = tm->tm_year + 1900;
	time_month = tm->tm_mon + 1;
	time_day = tm->tm_mday;

	time_jd = date_to_julian(time_year, time_month, time_day);

	/* Work out Julian day of new date */
	time_jd += offset_day;

	if (time_jd < 0)
		return 0;

	/* Convert Julian day back to date */

	julian_to_date(time_jd, &time_year, &time_month, &time_day);

	if (time_year < 1900 || time_year > 9999)
		return 0;

	/* Update tm structure */

	tm->tm_year = time_year - 1900;
	tm->tm_mon = time_month - 1;
	tm->tm_mday = time_day;

	tm->tm_hour = offset_hms / 3600;
	tm->tm_min = (offset_hms / 60) % 60;
	tm->tm_sec = offset_hms % 60;

	return 1;
		
}

/* Convert date to and from julian day
 * Uses Fliegel & Van Flandern algorithm
 */
static long date_to_julian(int y, int m, int d)
{
	return (1461 * (y + 4800 + (m - 14) / 12)) / 4 +
		(367 * (m - 2 - 12 * ((m - 14) / 12))) / 12 -
		(3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4 +
		d - 32075;
}

static void julian_to_date(long jd, int *y, int *m, int *d)
{
	long  L = jd + 68569;
	long  n = (4 * L) / 146097;
	long  i, j;

	L = L - (146097 * n + 3) / 4;
	i = (4000 * (L + 1)) / 1461001;
	L = L - (1461 * i) / 4 + 31;
	j = (80 * L) / 2447;
	*d = L - (2447 * j) / 80;
	L = j / 11;
	*m = j + 2 - (12 * L);
	*y = 100 * (n - 49) + i + L;
}


long GetTimeOffset()
{
#ifdef _WIN32
	TIME_ZONE_INFORMATION zone;
	GetTimeZoneInformation(&zone);
	return zone.Bias;
#else
	struct timeval tv;
	struct timezone tz;

	if (0 == gettimeofday(&tv, &tz))
		return tz.tz_minuteswest;
	return 0;
#endif
}

int asn1_time_to_tm(struct tm *tm, ASN1_TIME *s)
{
	const unsigned char *p;

	if (!ASN1_TIME_check(s))
		return 0;

	memset(tm, 0 ,sizeof tm);
	p = s->data;

#define g2(p) (((p)[0] - '0') * 10 + ((p)[1] - '0'))
	if (s->type == V_ASN1_GENERALIZEDTIME)
		{
		int yr = g2(p) * 100 + g2(p + 2);
		if (yr < 1900)
			return 0;
		tm->tm_year = yr - 1900;
		p += 4;
		}
	else
		{
		tm->tm_year=g2(p);
		if(tm->tm_year < 50)
			tm->tm_year+=100;
		p += 2;
		}
	tm->tm_mon=g2(p)-1;
	tm->tm_mday=g2(p + 2);
	tm->tm_hour=g2(p + 4);
	tm->tm_min=g2(p + 6);
	p += 8;
	/* Seconds optional in UTCTime */
	if (s->type == V_ASN1_GENERALIZEDTIME || (*p >= '0' && *p <= '9'))
		{
		tm->tm_sec=g2(p);
		p += 2;
		}
	else
		tm->tm_sec = 0;
	if (s->type == V_ASN1_GENERALIZEDTIME)
		{
		/* Skip any fractional seconds */
		if (*p == '.')
			{
			p++;
			while (*p >= '0' && *p <= '9')
				p++;
			}
		}
	/* Timezone */
	if(*p != 'Z')
		{
		int off_sec = g2(p + 1) * 3600 + g2(p + 3) * 60;
		if(*p == '-')
			off_sec = -off_sec;
		OPENSSL_gmtime_adj(tm, 0, off_sec);
		}
	return 1;
}

#ifndef _WIN32
time_t _mkgmtime(struct tm *tm)
{
	time_t ret;
	char *tz;

	tz = getenv("TZ");
	setenv("TZ", "", 1);
	tzset();
	ret = mktime(tm);
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();
	return ret;
}
#endif

// used for checking certificate type
#define ku_reject(x, usage) \
      (((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))
#define xku_reject(x, usage) \
      (((x)->ex_flags & EXFLAG_XKUSAGE) && !((x)->ex_xkusage & (usage)))

typedef enum
{
    eAuthCert = 0,
    eCipherCert,
    eSignCert
} tCertType;

#ifdef _WIN32
bool IsWindowsThemesActive()
{
    bool bReturn = false;
    HMODULE hDll = ::LoadLibrary(L"UxTheme.dll");
    if( hDll )
    {
        typedef BOOL(*THEMEACTIVE)(VOID);
 
        THEMEACTIVE pIsAppThemed = (THEMEACTIVE)GetProcAddress(hDll, "IsAppThemed");
        if( pIsAppThemed ) bReturn = (pIsAppThemed() == TRUE);
        ::FreeLibrary( hDll );
    }
    return bReturn;
}
#endif

unsigned char *fromBase64(const char* szInput, int* pLen, bool bHasNoLF = false)
{
  BIO *b64, *bmem;
  size_t length = strlen(szInput);
  // The length of BASE64 representation is always bigger
  // than the actual data length, so the size given to
  // the malloc below is sufficient to hold all the
  // decoded data
  unsigned char *buffer = (unsigned char *)malloc(length);
  b64 = BIO_new(BIO_f_base64());

  if (bHasNoLF)
  {
      // No LF on the input string
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new_mem_buf((void*)szInput, length);
  bmem = BIO_push(b64, bmem);
  *pLen = BIO_read(bmem, buffer, length);
  BIO_free_all(bmem);
  return buffer;
} 

wxString toBase64(const unsigned char* pbData, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, pbData, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  wxString base64((const char*) bptr->data, bptr->length);

  BIO_free_all(b64);

  return base64;
}

wxString toBase64(const wxMemoryBuffer& buffer)
{
    return toBase64((const unsigned char*) buffer.GetData(), buffer.GetDataLen());
}


///////////////////////////////////////////////
class MyApp: public wxApp {
public:
    bool OnInit();
	int OnExit();
	int InitLanguages();
	void CreateGUI(const wxPoint& position = wxDefaultPosition);
	wxConfig*				m_config;
	wxLocale*				m_locale; // locale we'll be using
	wxString				m_szLogFile;
	wxFFile 				m_logFile;
    wxDynamicLibrary	    m_pkcs11Dll;
    CCryptoki*              m_cryptokiObject;
	wxSingleInstanceChecker* m_checker;

};

IMPLEMENT_APP(MyApp)


class MyPinToolAboutDlg : public PinToolAboutDlg
{
protected:

    virtual void HandleLinkClick( wxHyperlinkEvent& event )
    { 
		wxString szUrl = m_hyperlink1->GetLabel();
        bool bStatus = wxLaunchDefaultBrowser( szUrl, wxBROWSER_NEW_WINDOW);
#ifdef __WXGTK__
		if (!bStatus)
		{
			wxString szCommand = wxT("firefox ");
			szCommand += szUrl;
			wxExecute(szCommand);
		}
#endif            
    }

    virtual void handleChangeLog( wxHyperlinkEvent& event )
    {
		wxString szChanges = wxPathOnly(wxStandardPaths::Get().GetExecutablePath()) + wxFileName::GetPathSeparator();
#ifndef __APPLE__
		szChanges += wxT("CHANGES.txt");
#else
		szChanges += wxT("../Resources/CHANGES.txt");
#endif	
		
		bool bStatus = wxLaunchDefaultApplication(szChanges);
#ifdef __WXGTK__
		if (!bStatus)
		{
			wxString szCommand = wxT("gedit ");
			szCommand += szChanges;
			wxExecute(szCommand);
		}
#endif        
    }
		
	
public:
		
    MyPinToolAboutDlg( wxWindow* parent) : PinToolAboutDlg(parent) 
	{

	}
};

//--------------------------------------------------------------

DECLARE_LOCAL_EVENT_TYPE(wxEVT_PINPAD_RETURNED_EVENT, -1)

class MyChangePinPadDlg;

class PinPadThread : public wxThread
{
protected:
	wxDialog*	m_pDlg;
    bool        m_bForUnblock;
    CK_SESSION_HANDLE m_hSession;
public:
	PinPadThread(CK_SESSION_HANDLE hSession, bool bForUnblock = false);
	virtual wxThreadError Create(wxDialog* pDlg, unsigned int stackSize = 0);
	virtual ExitCode Entry();
};

class MyChangePinPadDlg : public ChangePinPadDlg
{
	protected:
		
    virtual void handleOnClose( wxCloseEvent& myEvent ) { }
    virtual void handleThreadMessage( wxCommandEvent& myEvent )
    { 
        CK_RV rv = (CK_RV) myEvent.GetId();
        EndModal(rv);
    }

public:
    MyChangePinPadDlg(wxWindow* parent, int triesLeft, CK_SESSION_HANDLE hSession, bool bIsPin2 = false) : 
      ChangePinPadDlg(parent)
    {
        if (bIsPin2)
        {
            SetTitle(_("Change PIN2"));
            
            m_description->SetLabel(_("Please type the current PIN2 and the new PIN2 twice using the pinpad"));
        }

        m_triesLeftLabel->SetLabel(wxString::Format(m_triesLeftLabel->GetLabel(), (bIsPin2)? _("PIN2") : _("PIN1"), triesLeft));

        this->Connect( wxEVT_PINPAD_RETURNED_EVENT, wxCommandEventHandler( MyChangePinPadDlg::handleThreadMessage ) );

		m_thread = new PinPadThread(hSession);
		m_thread->Create(this,400000);
		m_thread->Run();
    }

    ~MyChangePinPadDlg()
    {
	    // Disconnect Events
	    this->Disconnect( wxEVT_PINPAD_RETURNED_EVENT, wxCommandEventHandler( MyChangePinPadDlg::handleThreadMessage ) );
		if(m_thread)
		{
			m_thread->Delete();
			delete m_thread;
			m_thread = NULL;
		}	
    }
    
    PinPadThread* m_thread;
};

DEFINE_EVENT_TYPE(wxEVT_PINPAD_RETURNED_EVENT)


PinPadThread::PinPadThread(CK_SESSION_HANDLE hSession, bool bForUnblock) : 
wxThread(wxTHREAD_JOINABLE), m_bForUnblock(bForUnblock), m_hSession(hSession) {}

wxThreadError PinPadThread::Create(wxDialog* pDlg, unsigned int stackSize) 
{
	m_pDlg = pDlg;
	return  wxThread::Create(stackSize);
}

wxThread::ExitCode PinPadThread::Entry()
{
	ExitCode status = NULL;
    CCryptoki* cryptokiObject = wxGetApp().m_cryptokiObject;
	if(cryptokiObject)
	{
        CK_RV rv;
        
        if (m_bForUnblock)
        {
            rv = cryptokiObject->C_Login(m_hSession, CKU_SO, NULL, 0);
            if (rv == CKR_OK)
            {
                rv = cryptokiObject->C_InitPIN(m_hSession, NULL, 0);
            }
        }
        else
        {
            rv = cryptokiObject->C_SetPIN(m_hSession, NULL, 0, NULL, 0);
        }
		wxCommandEvent returnedEvent( wxEVT_PINPAD_RETURNED_EVENT,rv);
        wxPostEvent(m_pDlg,returnedEvent);
	}
    return status;
}

// 
class MyChangePinDlg : public ChangePinDlg 
{
protected:
    virtual void HandleTextChange( wxCommandEvent& event )
    { 
        size_t minPinLength = (m_bIsPIN2)? 6 : 4; // for signature PIN, minimum length is 6
        wxString szPin = m_currentPin->GetValue();
        wxString szNewPin1 = m_newPin->GetValue();
        wxString szNewPin2 = m_confirmNewPin->GetValue();

        if ((szPin.Length() >= minPinLength) && 
            (szNewPin1.Length() >= minPinLength) &&
            (szNewPin1 == szNewPin2)
            )
        {
            m_buttonsSizerOK->Enable(true);
        }
        else
        {
            m_buttonsSizerOK->Enable(false);
        }
    }

    virtual void HandleOkButton( wxCommandEvent& event )
    {
        m_szOldPin = m_currentPin->GetValue();
        m_szNewPin = m_newPin->GetValue();
        event.Skip();
    }
public:
    MyChangePinDlg(wxWindow* parent, int triesLeft, bool bIsPin2 = false) : ChangePinDlg(parent), m_bIsPIN2(bIsPin2)
    {
        if (bIsPin2)
        {
            SetTitle(_("Change PIN2"));
            
            m_currentPinlabel->SetLabel(_("Current PIN2 : "));
            m_newPinLabel->SetLabel(_("New PIN2 : "));
            m_confirmNewPinLabel->SetLabel(_("Confirm New PIN2 : "));            
        }

        m_triesLeftLabel->SetLabel(wxString::Format(m_triesLeftLabel->GetLabel(), (bIsPin2)? _("PIN2") : _("PIN1"), triesLeft));

        m_buttonsSizerOK->Enable(false);

        m_buttonsSizerOK->SetDefault();
		m_buttonsSizerOK->SetBitmap(ok_png_to_wx_bitmap());
		m_buttonsSizerCancel->SetBitmap(cancel_png_to_wx_bitmap());

        // Allow only ASCII digits
        m_currentPin->SetValidator(wxTextValidator(wxFILTER_DIGITS));
        m_newPin->SetValidator(wxTextValidator(wxFILTER_DIGITS));
        m_confirmNewPin->SetValidator(wxTextValidator(wxFILTER_DIGITS));

		m_currentPin->SetFocus();
    }

    void Warning(const wxString& szMsg)
    {
	    wxMessageBox(szMsg,_("Warning"),wxOK|wxICON_EXCLAMATION,this);
    }
    
    bool m_bIsPIN2;
    wxString m_szOldPin, m_szNewPin;
};

//---------------------------------------------

class MyUnblockPinPadDlg : public UnblockPinPadDlg
{
	protected:
		
    virtual void handleOnClose( wxCloseEvent& myEvent ) { }
    virtual void handleThreadMessage( wxCommandEvent& myEvent )
    { 
        CK_RV rv = (CK_RV) myEvent.GetId();
        EndModal(rv);
    }

public:
    MyUnblockPinPadDlg(wxWindow* parent, int triesLeft, CK_SESSION_HANDLE hSession, bool bIsPin2 = false) : 
      UnblockPinPadDlg(parent)
    {
        if (bIsPin2)
        {
            SetTitle(_("Unblock PIN2"));
            m_description->SetLabel(_("Please type the PUK and the new PIN2 twice using the pinpad"));
        }

        m_triesLeftLabel->SetLabel(wxString::Format(m_triesLeftLabel->GetLabel(), triesLeft));

        this->Connect( wxEVT_PINPAD_RETURNED_EVENT, wxCommandEventHandler( MyUnblockPinPadDlg::handleThreadMessage ) );

	    m_thread = new PinPadThread(hSession, true);
		m_thread->Create(this,400000);
		m_thread->Run();
    }

    ~MyUnblockPinPadDlg()
    {
	    // Disconnect Events
	    this->Disconnect( wxEVT_PINPAD_RETURNED_EVENT, wxCommandEventHandler( MyUnblockPinPadDlg::handleThreadMessage ) );
		if(m_thread)
		{
			m_thread->Delete();
			delete m_thread;
			m_thread = NULL;
		}	
    }

    PinPadThread* m_thread;
};

class MyUnblockPinDlg : public UnblockPinDlg 
{
protected:
    virtual void HandleTextChange( wxCommandEvent& event )
    { 
        size_t minPinLength = (m_bIsPIN2)? 6 : 4; // for signature PIN, minimum length is 6
        wxString szPuk = m_puk->GetValue();
        wxString szNewPin1 = m_newPin->GetValue();
        wxString szNewPin2 = m_confirmNewPin->GetValue();

        if ((szPuk.Length() >= 8) && 
            (szNewPin1.Length() >= minPinLength) &&
            (szNewPin1 == szNewPin2)
            )
        {
            m_buttonsSizerOK->Enable(true);
        }
        else
        {
            m_buttonsSizerOK->Enable(false);
        }
    }

    virtual void HandleOkButton( wxCommandEvent& event )
    {
        m_szPuk = m_puk->GetValue();
        m_szNewPin = m_newPin->GetValue();
        event.Skip();
    }
public:
    MyUnblockPinDlg(wxWindow* parent, int triesLeft, bool bIsPin2 = false) : UnblockPinDlg(parent), m_bIsPIN2(bIsPin2)
    {
        if (bIsPin2)
        {
            SetTitle(_("Unblock PIN2"));

            m_newPinLabel->SetLabel(_("New PIN2 : "));
            m_confirmNewPinLabel->SetLabel(_("Confirm New PIN2 : "));
        }

        m_triesLeftLabel->SetLabel(wxString::Format(m_triesLeftLabel->GetLabel(), triesLeft));

        m_buttonsSizerOK->Enable(false);
        m_buttonsSizerOK->SetDefault();
		m_buttonsSizerOK->SetBitmap(ok_png_to_wx_bitmap());
		m_buttonsSizerCancel->SetBitmap(cancel_png_to_wx_bitmap());

        // Allow only ASCII digits
        m_puk->SetValidator(wxTextValidator(wxFILTER_DIGITS));
        m_newPin->SetValidator(wxTextValidator(wxFILTER_DIGITS));
        m_confirmNewPin->SetValidator(wxTextValidator(wxFILTER_DIGITS));

		m_puk->SetFocus();
    }

    void Warning(const wxString& szMsg)
    {
	    wxMessageBox(szMsg,_("Warning"),wxOK|wxICON_EXCLAMATION,this);
    }
    
    bool m_bIsPIN2;
    wxString m_szPuk, m_szNewPin;
};

// Inherit from PinToolFrame to add specifics
class MyReaderSelectionDlg : public ReaderSelectionDlg
{
protected:
    virtual void HandleOkButton( wxCommandEvent& event )
    {
        if (m_readersList->GetSelection() != 0)
            m_szSelectedReader = m_readersList->GetValue();
        event.Skip();
    }

public:
    MyReaderSelectionDlg(wxWindow* parent, wxString& initialReader, std::vector<wxString>& readers) : ReaderSelectionDlg(parent)
    {
        int selectionIndex = 0, counter = 0;
        m_readersList->Append(_("{No Prefered Reader}"));
        for (std::vector<wxString>::iterator It = readers.begin(); It != readers.end(); It++)
        {
            counter++;
            m_readersList->Append(*It);
            if (*It == initialReader)
                selectionIndex = counter;
        }

        m_readersList->SetSelection(selectionIndex);
		m_buttonsSizerOK->SetBitmap(ok_png_to_wx_bitmap());
		m_buttonsSizerCancel->SetBitmap(cancel_png_to_wx_bitmap());
#ifdef __WXGTK__ 	
		SetSizeHints( wxSize( 450,120 ), wxSize( 450,120 ) );
		Layout();		
#endif		
    }

    wxString m_szSelectedReader;

};

// Inherit from PinToolFrame to add specifics
class MyPinToolFrame : public PinToolFrame 
{
protected:

	void SelectLanguage(int langId)
	{
		int lng;
		if(!m_config->Read(wxT("Languages/Selected"),&lng))
		{
			lng = wxLANGUAGE_ENGLISH_US;
		}

		if (langId != lng)
		{
			wxLogMessage(wxT("New GUI language = %s"), wxLocale::GetLanguageName(langId));
			wxPoint position = GetPosition();
			m_config->Write(wxT("Languages/Selected"),langId);
			wxGetApp().InitLanguages();
			wxGetApp().CreateGUI(position);
		}
	}
	virtual void HandleMenuSelectEnglish( wxCommandEvent& event )
	{ 		
		SelectLanguage(wxLANGUAGE_ENGLISH_US); 
	}

	virtual void HandleMenuSelectLatvia( wxCommandEvent& event )
	{ 
		SelectLanguage(wxLANGUAGE_LATVIAN);
	}

    virtual void HandleMenuCardReader( wxCommandEvent& event )
    {        
        bool bShowDialog = false;
        std::vector<wxString> readers;

        if (InitializePkcs11Module())
        {       
            wxBusyCursor wait;
            UpdateState();

            // List all readers available
            CK_ULONG ulCount = 0;
            CK_RV rv = m_cryptokiObject->C_GetSlotList(FALSE, NULL, &ulCount);
            if ((rv == CKR_OK) && (ulCount))
            {
                std::vector<CK_SLOT_ID> pSlots;
                pSlots.resize(ulCount);
                rv = m_cryptokiObject->C_GetSlotList(FALSE, &pSlots[0], &ulCount);
                if (rv == CKR_OK)
                {
                    CK_SLOT_INFO slotInfo;
                    for (CK_ULONG i = 0; i < ulCount; i++)
                    {
                        rv = m_cryptokiObject->C_GetSlotInfo(pSlots[i], &slotInfo);
                        if (rv == CKR_OK)
                        {
                            wxString slotDesc = MyPinToolFrame::GetCryptokiString(slotInfo.slotDescription, 64, true);
                            if (slotDesc != wxT("Virtual hotplug slot"))
                            {
                                if (readers.empty() || readers.back() != slotDesc)
                                    readers.push_back(slotDesc);
                            }
                        }
                    }
                }
            }

            bShowDialog = true;
        }

        if (bShowDialog)
        {
            MyReaderSelectionDlg dlg(this, m_szSelectedReader, readers);
            dlg.SetIcon(GetIcon());
            if (dlg.ShowModal() == wxID_OK)
            {
                m_szSelectedReader = dlg.m_szSelectedReader;
                if (m_szSelectedReader.IsEmpty())
				{
					wxLogMessage(wxT("No prefered reader selected"));
				}
                else
				{
					wxLogMessage(wxT("New prefered reader = \"%s\""), m_szSelectedReader.c_str());
				}

				m_config->Write(wxT("PreferedReader"), m_szSelectedReader);
            }
        }
    }

    virtual void HandleMouseEvent( wxMouseEvent& event ) 
    { 
#ifndef __WXGTK__
        if (event.Entering())
        {
            SetCursor(wxCursor(wxCURSOR_HAND ));
        }
        else if (event.Leaving())
        {
            SetCursor(wxCursor(wxCURSOR_ARROW));
        }
        else
#endif
            event.Skip();
    }

    virtual void HandlePageChanging( wxNotebookEvent& noteBookEvent )
    { 
        if (noteBookEvent.GetOldSelection() == 0)
        {
            ProcessCardReading();

            if (m_currentSlotID == 0)
            {
                // An error occured. abort action
                noteBookEvent.Skip(false);
                noteBookEvent.Veto();
                return;
            }
        }
        
        noteBookEvent.Skip(); 
    }

    virtual void HandleConnectToCardReader( wxCommandEvent& event )
    {
        ProcessCardReading();
        if (m_currentSlotID != 0)
        {
            m_mainTabs->SetSelection(1);
        }
    }

	virtual void HandleMenuLogs( wxCommandEvent& event )
	{ 
		bool bStatus = wxLaunchDefaultApplication(wxGetApp().m_szLogFile);
#ifdef __WXGTK__
		if (!bStatus)
		{
			wxString szCommand = wxT("gedit ");
			szCommand += wxGetApp().m_szLogFile;
			wxExecute(szCommand);
		}
#endif
	}
    
    virtual void HandleHelp( wxCommandEvent& event )
    {
        wxString szHelpFile, szRelativePath;

        // adapt the help to the current language
        int lng;
        if(!m_config->Read(wxT("Languages/Selected"),&lng))
        {
	        lng = wxLANGUAGE_ENGLISH_US;
        }

        if (lng == wxLANGUAGE_LATVIAN)
        {
#ifndef __APPLE__
            szRelativePath = wxT("/help/lv/help.htm");
#else
            szRelativePath = wxT("/../Resources/help/lv/help.htm");
#endif
        }
        else
        {
#ifndef __APPLE__
            szRelativePath = wxT("/help/en/help.htm");
#else
            szRelativePath = wxT("/../Resources/help/en/help.htm");
#endif
        }

        szHelpFile = wxPathOnly(wxStandardPaths::Get().GetExecutablePath()) + szRelativePath;

        bool bStatus = wxLaunchDefaultBrowser( szHelpFile, wxBROWSER_NEW_WINDOW);
#ifdef __WXGTK__
		if (!bStatus)
		{
			wxString szCommand = wxT("firefox ");
			szCommand += szHelpFile;
			wxExecute(szCommand);
		}
#endif        
    }

    void ProcessCardReading()
    {
        if (InitializePkcs11Module())
        {
            wxBusyCursor wait;
            UpdateState();

            if (m_currentSlotID != 0)
            {
                // we already have read the card
                // check that the user didn't select another reader
                if (m_szSelectedReader.IsEmpty())
                    return;
                else
                {
                    CK_SLOT_INFO slotInfo;
                    CK_RV rv = m_cryptokiObject->C_GetSlotInfo(m_currentSlotID, &slotInfo);
                    if ((rv == CKR_OK) && (m_szSelectedReader == MyPinToolFrame::GetCryptokiString(slotInfo.slotDescription, 64, true)))
                        return;
                    else
                    {
                        m_currentSlotID = 0;
                        ClearInformation();
                    }
                }
            }

			wxLogMessage(wxT("Reading the content of a smart card"));

            CK_ULONG ulCount = 0;
            CK_RV rv = m_cryptokiObject->C_GetSlotList(TRUE, NULL, &ulCount);
            if (rv != CKR_OK)
            {
				wxSnprintf(m_buffer,2048,_("Error \"%s\" occured while looking for inserted smart cards."),CK_RVtoName(rv));
				Error(m_buffer);
				wxLogMessage(wxString::Format(wxT("Error \"%s\" occured while looking for inserted smart cards."), CK_RVtoName(rv)));
            }
            else if (ulCount == 0)
            {
                Warning(_("No smart card detected on your machine"));
				wxLogMessage(wxT("No smart card detected on your machine"));
            }
            else
            {
                CK_SLOT_INFO slotInfo;
                std::vector<CK_SLOT_ID> pSlots;
                pSlots.resize(ulCount);
                rv = m_cryptokiObject->C_GetSlotList(TRUE, &pSlots[0], &ulCount);
                if (rv != CKR_OK)
                {
				    wxSnprintf(m_buffer,2048,_("Error \"%s\" occured while looking for inserted smart cards."),CK_RVtoName(rv));
				    Error(m_buffer);
					wxLogMessage(wxString::Format(wxT("Error \"%s\" occured while looking for inserted smart cards."),CK_RVtoName(rv)));
                    return;
                }

                CK_SLOT_ID selectedSlotID = 0;
                if (m_szSelectedReader.IsEmpty())
                {
                    if (ulCount >= 4)
                    {
                        Warning(_("There are several cards inserted.\nEither leave only one card or choose the reader to use from the \"Settings\" menu"));
						wxLogMessage(wxT("Too many cards found on the system. Stopping the reading process"));
                        return;
                    }
                    selectedSlotID = pSlots[0];
                }
                else
                {
                    for (CK_ULONG i = 0; i < ulCount; i++)
                    {
                        rv = m_cryptokiObject->C_GetSlotInfo(pSlots[i], &slotInfo);
                        if ((rv == CKR_OK) && ((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT))
                        {
                            wxString szReaderName = GetCryptokiString(slotInfo.slotDescription,64, true);
                            if (m_szSelectedReader == szReaderName)
                            {
                                selectedSlotID = pSlots[i];
                                break;
                            }
                        }
                    }

                    if (selectedSlotID == 0)
                    {
                        Warning(wxString::Format(_("No card has been found on the selected reader \"%s\".\nPlease insert a card or change your favorite reader in the \"Setting\" menu."), m_szSelectedReader.c_str()));
						wxLogMessage((wxString::Format(wxT("No card has been found on the prefered reader \"%s\""), m_szSelectedReader.c_str())));
                        return;
                    }
                }   

                ParseCardContent(selectedSlotID);

                if (m_currentSlotID != 0)
                {
                    rv = m_cryptokiObject->C_GetSlotInfo(m_currentSlotID, &slotInfo);
                    if (rv == CKR_OK)
                    {
                        wxString szSlotDesc = GetCryptokiString(slotInfo.slotDescription, 64, true);
                        m_statusBar->SetStatusText(wxString::Format(_("Connected to \"%s\""), szSlotDesc.c_str()));
                    }
                }
            }
        }
    }

    void ParseCardContent(CK_SLOT_ID slotID)
    {
        //This slot contains the user PIN and the next one contains the signature PIN
        CK_SLOT_ID authSlotID = slotID;
        CK_SLOT_ID signSlotID = slotID + 1;
        CK_RV rv;
        CK_SESSION_HANDLE hSession;
        std::vector<CK_OBJECT_HANDLE> pHandles;
	    CK_OBJECT_CLASS classe = CKO_CERTIFICATE;
	    CK_BBOOL		bToken = TRUE;
	    CK_ATTRIBUTE find_template[] = {
		    {CKA_CLASS, &classe, sizeof(classe)},
		    {CKA_TOKEN, &bToken, sizeof(CK_BBOOL)}
	    };
	    CK_ULONG ulCount = 0,totalCount = 0;
        CK_TOKEN_INFO tokenInfo;
		CK_SLOT_INFO slotInfo;

		rv = m_cryptokiObject->C_GetSlotInfo(slotID, &slotInfo);
		if (rv != CKR_OK)
		{
			wxSnprintf(m_buffer,2048,_("Error %s occured while reading card information"),CK_RVtoName(rv));
			Error(m_buffer);
			wxLogMessage(wxString::Format(wxT("Error %s occured while reading slot %d information"),CK_RVtoName(rv), slotID));
            return;
		}

		wxString szReaderName = GetCryptokiString(slotInfo.slotDescription,64, true);
		wxLogMessage(wxString::Format(wxT("Reading content of the card on reader \"%s\""), szReaderName.c_str()));

        // check the ID of authentication slot and signature slot are correct
        rv = m_cryptokiObject->C_GetTokenInfo(slotID, &tokenInfo);
        if (rv != CKR_OK)
        {
			wxSnprintf(m_buffer,2048,_("Error %s occured while reading card information"),CK_RVtoName(rv));
			Error(m_buffer);
			wxLogMessage(wxString::Format(wxT("Error %s occured while reading token information on slot %d"),CK_RVtoName(rv), slotID));
            return;
        }

        wxString szTokenLabel = GetCryptokiString(tokenInfo.label, 32, true);
		wxLogMessage(wxString::Format(wxT("Token Label = %s"), szTokenLabel.c_str()));

        if (szTokenLabel.EndsWith(wxT("(Signature PIN)")))
        {
            authSlotID = slotID + 1;
            signSlotID = slotID;
        }


		wxLogMessage(wxT("Looking for Authentication/Ciphering certificate(s)"));
        rv = m_cryptokiObject->C_OpenSession(authSlotID, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        if (rv != CKR_OK)
        {
			wxSnprintf(m_buffer,2048,_("Error %s occured while opening a session on the smart card"),CK_RVtoName(rv));
			Error(m_buffer);
            return;
        }

	    rv = m_cryptokiObject->C_FindObjectsInit(hSession,find_template,2);
	    if(rv == CKR_OK)
	    {
		    do
		    {
                CK_OBJECT_HANDLE hCert;
			    rv = m_cryptokiObject->C_FindObjects(hSession,&hCert,1,&ulCount);
			    if((rv == CKR_OK) && ulCount)
			    {
                    pHandles.push_back(hCert);
                }
		    } while(ulCount);

		    m_cryptokiObject->C_FindObjectsFinal(hSession);
        }

        if (pHandles.size())
        {
			wxLogMessage(wxString::Format(wxT("Parsing %d certificates found on authentication/ciphering slot."), (int) pHandles.size()));
            if (ParseCertificates(hSession, pHandles))
                m_currentSlotID = slotID;
        }
        else
        {
            Warning(_("No Authentication or Ciphering certificate found on the card"));
			wxLogMessage(wxT("No Authentication or Ciphering certificate found on the card"));
        }

        m_cryptokiObject->C_CloseSession(hSession);

        // Look for the signature certificate
        pHandles.clear();

		wxLogMessage(wxT("Looking for Signature certificate"));
        rv = m_cryptokiObject->C_GetTokenInfo(signSlotID, &tokenInfo);
        if (rv == CKR_OK)
        {
			wxString szTokenLabel = GetCryptokiString(tokenInfo.label, 32, true);
			wxLogMessage(wxString::Format(wxT("Token Label = %s"), szTokenLabel.c_str()));
		}

        rv = m_cryptokiObject->C_OpenSession(signSlotID, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
        if (rv != CKR_OK)
        {
			wxSnprintf(m_buffer,2048,_("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv));
			Error(m_buffer);
			wxLogMessage(wxString::Format(wxT("Error \"%s\" occured while opening a session on signature slot"),CK_RVtoName(rv)));
            return;
        }

	    rv = m_cryptokiObject->C_FindObjectsInit(hSession,find_template,2);
	    if(rv == CKR_OK)
	    {
		    do
		    {
                CK_OBJECT_HANDLE hCert;
			    rv = m_cryptokiObject->C_FindObjects(hSession,&hCert,1,&ulCount);
			    if((rv == CKR_OK) && ulCount)
			    {
                    pHandles.push_back(hCert);
                }
		    } while(ulCount);

		    m_cryptokiObject->C_FindObjectsFinal(hSession);
        }

        if (pHandles.size())
        {
			wxLogMessage(wxString::Format(wxT("Parsing %d certificates found on signature slot."), (int) pHandles.size()));
            if (ParseCertificates(hSession, pHandles))
                m_currentSlotID = slotID;
        }
        else
        {
            Warning(_("No Signature certificate found on the card"));
			wxLogMessage(wxT("No Signature certificate found on the card"));
        }

        m_cryptokiObject->C_CloseSession(hSession);

    }

    static wxString GetCertDetail(X509* x, int NID, bool bForIssuer = false)
    {
        wxString szResult;
        X509_NAME* pName = (bForIssuer)? X509_get_issuer_name(x) : X509_get_subject_name(x);
        int lastpos = -1;
        lastpos = X509_NAME_get_index_by_NID(pName, NID, lastpos);
        if (lastpos != -1)
        {
            X509_NAME_ENTRY *e = X509_NAME_get_entry(pName, lastpos);
            ASN1_STRING* pEntryStr = X509_NAME_ENTRY_get_data(e);

            BIO* b = BIO_new(BIO_s_mem());
            int status = ASN1_STRING_print_ex(b,pEntryStr,ASN1_STRFLGS_UTF8_CONVERT);
            if (status)
            {
                char szLine[1024];      
                while(BIO_gets(b, szLine, 1024))
                {
                    szResult += wxString(szLine, wxConvUTF8);
                }       
            }

            BIO_free(b);            
        }

        return szResult;
    }

    void GetCertValidity(X509* x, wxString& szFrom, wxString& szTo)
    {
        ASN1_TIME* pFrom = x->cert_info->validity->notBefore;
        ASN1_TIME* pTo = x->cert_info->validity->notAfter;

		struct tm before;
		struct tm after;

		asn1_time_to_tm(&before, pFrom);	

		wxDateTime d1(before);
		d1.MakeFromTimezone(wxDateTime::GMT0, true);
		szFrom = d1.Format(wxT("%A,  %B  %d,  %Y %I:%M:%S %p"));


		asn1_time_to_tm(&after, pTo);
		
		wxDateTime d2(after);
		d2.MakeFromTimezone(wxDateTime::GMT0, true);
		szTo = d2.Format(wxT("%A,  %B  %d,  %Y %I:%M:%S %p"));
    }

    bool ParseCertificates(CK_SESSION_HANDLE hSession, std::vector<CK_OBJECT_HANDLE>& pHandles)
    {
        bool bResult = false;
        CK_ATTRIBUTE value_template[] = {
            {CKA_VALUE, NULL, 0}
        };

        for (size_t i = 0; i < pHandles.size(); i++)
        {
            value_template[0].pValue = NULL;
            value_template[0].ulValueLen = 0;
            CK_RV rv = m_cryptokiObject->C_GetAttributeValue(hSession, pHandles[i], value_template, 1);
            if ((rv != CKR_OK) || (value_template[0].ulValueLen == 0) || (value_template[0].ulValueLen == CK_UNAVAILABLE_INFORMATION))
            {
                Error(_("Failed to read certificate from the card"));
                continue;
            }

            wxMemoryBuffer certValue;
            certValue.SetBufSize(value_template[0].ulValueLen);
            value_template[0].pValue = certValue.GetData();
            rv = m_cryptokiObject->C_GetAttributeValue(hSession, pHandles[i], value_template, 1);
            if ((rv != CKR_OK) || (value_template[0].ulValueLen == 0) || (value_template[0].ulValueLen == CK_UNAVAILABLE_INFORMATION))
            {
                Error(_("Failed to read certificate from the card"));
                continue;
            }

            certValue.SetDataLen(value_template[0].ulValueLen);
            unsigned char* pbCert = (unsigned char*) certValue.GetData();

            X509* x = d2i_X509(NULL, (const unsigned char **) &pbCert, value_template[0].ulValueLen);

			if (!x)
            {
                Error(_("Invalid certificate found on the card"));
                continue;
            }
        
            if (!X509_check_ca(x)) // Skip CA certificates if any
            {
                tCertType type;
                if (X509_check_purpose(x, X509_PURPOSE_SMIME_SIGN, 0))
				{
                    type = eSignCert;
					wxLogMessage(wxT("\tSigning certificate found"));
				}
                else if (X509_check_purpose(x, X509_PURPOSE_SMIME_ENCRYPT, 0))
				{
                    type = eCipherCert;
					wxLogMessage(wxT("\tCiphering certificate found"));
				}
                else if (X509_check_purpose(x, X509_PURPOSE_SSL_CLIENT, 0))
				{
                    type = eAuthCert;
					wxLogMessage(wxT("\tAuthentication certificate found"));
				}
                else
                    continue;

                wxString szFirsName = GetCertDetail(x, NID_givenName);
                wxString szLastName = GetCertDetail(x, NID_surname);
				if (szFirsName.IsEmpty() && szLastName.IsEmpty())
				{
					// If no given name or suname found, reader the common name
					// and suppose that it is composed of given name, followed by space and
					// then surname
					wxString szCN = GetCertDetail(x, NID_commonName);
					szFirsName = szCN.BeforeFirst(wxT(' '));
					szLastName = szCN.AfterFirst(wxT(' '));
				}
                wxString szPersonalNumber = GetCertDetail(x, NID_serialNumber);
                wxString szAuthorityName = GetCertDetail(x, NID_commonName, true);
                wxString szFrom, szTo;
                GetCertValidity(x, szFrom, szTo);        

                m_InformationPanel->Enable();
                m_certTabs->Enable();

				wxLogMessage(wxString::Format(wxT("\t\tSubject = %s %s"), szFirsName.c_str(), szLastName.c_str()));
				wxLogMessage(wxString::Format(wxT("\t\tPersonal Number = %s"), szPersonalNumber.c_str()));
				wxLogMessage(wxString::Format(wxT("\t\tAuthority Name = %s"), szAuthorityName.c_str()));

                UpdateUserPinTab(type, szFirsName, szLastName, szPersonalNumber, szAuthorityName, szFrom, szTo, certValue);

                bResult = true;
            }
			else
			{
				wxLogMessage(wxT("\tSkipping CA certificate"));
			}
            X509_free(x);
        }

		if (bResult)
			wxLogMessage(wxT("Parsing OK"));
		else
		{
			wxLogMessage(wxT("Parsing Error : No user certificate found on this token"));
		}
        return bResult;
    }

    void UpdateUserPinTab(tCertType type, wxString& szFirsName,wxString& szLastName,
            wxString& szPersonalNumber,wxString& szAuthorityName,wxString& szFrom,wxString& szTo,
            wxMemoryBuffer& certValue)
    {
        if (type == eAuthCert)
        {
            m_authFirstName->SetValue(szFirsName);
            m_authLastName->SetValue(szLastName);
            m_authPersonalNumber->SetValue(szPersonalNumber);
            m_authAuthorityName->SetValue(szAuthorityName);
            m_authFrom->SetValue(szFrom);
            m_authTo->SetValue(szTo);

            m_authExportCert->Enable();
            m_authChangePin1->Enable();
            m_authUnblockPin1->Enable();
            m_authCertTab->Enable();

            m_authCertValue = certValue;
        }
        else if (type == eSignCert)
        {
            m_signFirstName->SetValue(szFirsName);
            m_signLastName->SetValue(szLastName);
            m_signPersonalNumber->SetValue(szPersonalNumber);
            m_signAuthorityName->SetValue(szAuthorityName);
            m_signFrom->SetValue(szFrom);
            m_signTo->SetValue(szTo);

            m_signExportCert->Enable();
            m_signChangePin2->Enable();
            m_signUnblockPin2->Enable();
            m_signCertTab->Enable();

            m_signCertValue = certValue;
        }
        else if (type == eCipherCert)
        {
            m_cipherFirstName->SetValue(szFirsName);
            m_cipherLastName->SetValue(szLastName);
            m_cipherPersonalNumber->SetValue(szPersonalNumber);
            m_cipherAuthorityName->SetValue(szAuthorityName);
            m_cipherFrom->SetValue(szFrom);
            m_cipherTo->SetValue(szTo);

            m_cipherExportCert->Enable();
            m_cipherChangePin1->Enable();
            m_cipherUnblockPin1->Enable();
            m_cipherCertTab->Enable();

            m_cipherCertValue = certValue;
        }


    }

    void UpdateState()
    {
        if (m_cryptokiObject)
        {
            // List all slots to update internal P11 state
            CK_SLOT_ID pSlots[64];
            CK_ULONG ulCount = 64;
            CK_RV rv;
            m_cryptokiObject->C_GetSlotList(FALSE, pSlots, &ulCount);

            do
            {
                rv = m_cryptokiObject->C_WaitForSlotEvent(CKF_DONT_BLOCK, pSlots, NULL);
                if ((rv == CKR_OK) && (m_currentSlotID == pSlots[0]))
                {
                    m_currentSlotID = 0;
                    ClearInformation();
                }
            } while(rv == CKR_OK);

            if (m_currentSlotID != 0)
            {
                // check if the user have choosen another reader
                CK_SLOT_INFO slotInfo;
                rv = m_cryptokiObject->C_GetSlotInfo(m_currentSlotID, &slotInfo);
                if ((rv != CKR_OK) || ((slotInfo.flags & CKF_TOKEN_PRESENT) == 0))
                {
                    m_currentSlotID = 0;
                    ClearInformation();
                }
                else
                {
                    wxString szReaderName = GetCryptokiString(slotInfo.slotDescription,64, true);
                    if (!m_szSelectedReader.IsEmpty() && (m_szSelectedReader != szReaderName))
                    {
                        m_currentSlotID = 0;
                        ClearInformation();                    
                    }
                }
            }
        }
    }

    // Clear all information from all tabs
    void ClearInformation()
    {
        m_statusBar->SetStatusText(_("Not connected"));

        m_authCertValue.SetDataLen(0);
        m_signCertValue.SetDataLen(0);
        m_cipherCertValue.SetDataLen(0);

        m_InformationPanel->Enable(false);
        m_certTabs->Enable(false);

        m_authFirstName->SetValue(wxT(""));
        m_authLastName->SetValue(wxT(""));
		m_authPersonalNumber->SetValue(wxT(""));
		m_authAuthorityName->SetValue(wxT(""));
		m_authFrom->SetValue(wxT(""));
		m_authTo->SetValue(wxT(""));
        m_authExportCert->Enable(false);
        m_authChangePin1->Enable(false);
        m_authUnblockPin1->Enable(false);
        m_authCertTab->Enable(false);

        m_signFirstName->SetValue(wxT(""));
        m_signLastName->SetValue(wxT(""));
		m_signPersonalNumber->SetValue(wxT(""));
		m_signAuthorityName->SetValue(wxT(""));
		m_signFrom->SetValue(wxT(""));
		m_signTo->SetValue(wxT(""));
        m_signExportCert->Enable(false);
        m_signChangePin2->Enable(false);
        m_signUnblockPin2->Enable(false);
        m_signCertTab->Enable(false);

        m_cipherFirstName->SetValue(wxT(""));
        m_cipherLastName->SetValue(wxT(""));
		m_cipherPersonalNumber->SetValue(wxT(""));
		m_cipherAuthorityName->SetValue(wxT(""));
		m_cipherFrom->SetValue(wxT(""));
		m_cipherTo->SetValue(wxT(""));
        m_cipherExportCert->Enable(false);
        m_cipherChangePin1->Enable(false);
        m_cipherUnblockPin1->Enable(false);
        m_cipherCertTab->Enable(false);

        m_mainTabs->SetSelection(0);
    }

    static wxString GetCryptokiString(CK_UTF8CHAR_PTR pString, int length, bool bRemovePadding)
    {
        if (bRemovePadding)
        {
            while ((length > 0) && (pString[length-1] == (CK_UTF8CHAR) ' '))
            {
                length--;
            }
        }

        return wxString((const char*) pString, wxConvUTF8, length);
    }

    int GetPinTriesLeft(CK_SLOT_ID slotID, bool& bIsPinPAD)
    {
		wxBusyCursor waitCursor;
        int triesLeft = 3;
        CK_TOKEN_INFO tokenInfo;
        CK_RV ret;

		bIsPinPAD = false;			
		ret = m_cryptokiObject->C_GetTokenInfo(slotID, &tokenInfo);
        if (ret == CKR_OK)
        {
            if (tokenInfo.flags & CKF_USER_PIN_FINAL_TRY)
                triesLeft = 1;
            else if (tokenInfo.flags & CKF_USER_PIN_COUNT_LOW)
                triesLeft = 2;
            else if (tokenInfo.flags & CKF_USER_PIN_LOCKED)
                triesLeft = 0;

			if (tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
				bIsPinPAD = true;
        }
        return triesLeft;
    }

    int GetPukTriesLeft(CK_SLOT_ID slotID, bool& bIsPinPAD)
    {
		wxBusyCursor waitCursor;
        int triesLeft = 3;
        CK_TOKEN_INFO tokenInfo;
        CK_RV ret;
		
		bIsPinPAD = false;
		ret = m_cryptokiObject->C_GetTokenInfo(slotID, &tokenInfo);
        if (ret == CKR_OK)
        {
            if (tokenInfo.flags & CKF_SO_PIN_FINAL_TRY)
                triesLeft = 1;
            else if (tokenInfo.flags & CKF_SO_PIN_COUNT_LOW)
                triesLeft = 2;
            else if (tokenInfo.flags & CKF_SO_PIN_LOCKED)
                triesLeft = 0;

			if (tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
				bIsPinPAD = true;
        }
        return triesLeft;
    }

    virtual void handleMenuExit( wxCommandEvent& event ) 
    {
        Close(true);
    }

	virtual void HandleMenuHelp( wxCommandEvent& event ) 
	{ 
		HandleHelp(event);
	}

    virtual void HandleMenuAbout( wxCommandEvent& event )
    {
        //wxAboutDialogInfo aboutInfo;
        //aboutInfo.SetName(_("PinTool"));
        //aboutInfo.SetVersion(_("1.0.11"));
        //aboutInfo.SetDescription(_("PinTool for Latvia eID Middleware"));
        //aboutInfo.SetCopyright("(C) 2012");
        //aboutInfo.SetWebSite(_("http://www.pmlp.gov.lv/en/"));
        //aboutInfo.AddDeveloper("Oberthur Technologies");

        //wxAboutBox(aboutInfo, this);
        MyPinToolAboutDlg aboutInfo(this);
        aboutInfo.ShowModal();
    }

    void ExportCert(const wxMemoryBuffer& certValue, const wxString& certDesc)
    {
        if (certValue.GetDataLen() == 0) // should never happen
            return;

        wxString szFileName = wxFileSelector(wxString::Format(_("Please choose where to save the %s certificate"), certDesc.c_str()),
                                             wxEmptyString,
                                             wxEmptyString,
                                             wxEmptyString,
                                             _("DER binary certificate (*.cer)|*.cer|BASE-64 certificate (*.crt;*.pem)|*.crt;*.pem"),
                                             wxFD_SAVE | wxFD_OVERWRITE_PROMPT,
                                             this);
        if (!szFileName.IsEmpty())
        {
            if (szFileName.EndsWith(wxT(".cer")))
            {
				wxLogMessage(wxString::Format(wxT("Exporting %s certificate in DER binary encoding to file \"%s\""), 
					certDesc, szFileName));
                wxFFileOutputStream stream(szFileName);
                if (stream.IsOk())
                {
                    stream.Write(certValue.GetData(), certValue.GetDataLen());
					wxLogMessage(wxT("Certificate exported successfully"));
                }
                else
                {
					wxLogMessage(wxT("I/O error while writing certificate"));
                    Error(wxString::Format(_("Failed to write the %s certificate to the selected file.\nPlease check disk permissions"), certDesc.c_str()));
                }
            }
            else
            {
				wxLogMessage(wxString::Format(wxT("Exporting %s certificate in BASE64 encoding to file \"%s\""), 
					certDesc, szFileName));
                wxFFileOutputStream stream(szFileName, wxT("wt"));
                if (stream.IsOk())
                {
                    // Transform to BASE64
                    wxString szBase64 = wxT("-----BEGIN CERTIFICATE-----\n") + toBase64(certValue) + wxT("-----END CERTIFICATE-----\n");
                    wxWritableCharBuffer buffer = szBase64.char_str();
                    stream.Write(buffer.data(), buffer.length());
					wxLogMessage(wxT("Certificate exported successfully"));
                }
                else
                {
					wxLogMessage(wxT("I/O error while writing certificate"));
                    Error(wxString::Format(_("Failed to write the %s certificate to the selected file.\nPlease check disk permissions"), certDesc.c_str()));
                }

            }
        }
    }

	virtual void HandleExportAuthCert( wxCommandEvent& event )
    { 
        ExportCert(m_authCertValue, _("authentication"));
    }
	virtual void HandleExportSignCert( wxCommandEvent& event )
    {
        ExportCert(m_signCertValue, _("signature"));
    }
	virtual void HandleExportCipherCert( wxCommandEvent& event )
    {
        ExportCert(m_cipherCertValue, _("ciphering"));
    }

    void HandleChangePin(bool bIsPIN2 = false)
    {
        CK_SLOT_ID slotID = (bIsPIN2)? m_currentSlotID + 1 : m_currentSlotID; // PIN2 is in the second slot
		bool bIsPinPAD = false;

		wxLogMessage(wxString::Format(wxT("Change of %s requested"),  (bIsPIN2)? _("PIN2"):_("PIN1")));

        while (true)
        {
			int triesLeft = GetPinTriesLeft(slotID, bIsPinPAD);
            if (triesLeft == 0)
            {
                Error(wxString::Format(_("%s of the card is blocked"),  (bIsPIN2)? _("PIN2"):_("PIN1")));
				wxLogMessage(wxString::Format(wxT("%s of the card is blocked"),  (bIsPIN2)? _("PIN2"):_("PIN1")));
                break;
            }

            if (bIsPinPAD)
            {
                CK_SESSION_HANDLE hSession;
                CK_RV rv = m_cryptokiObject->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
                if (rv != CKR_OK)
				{
                    Error(wxString::Format(_("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
					wxLogMessage(wxString::Format(wxT("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
                    break;
				}
                else
                {
                    MyChangePinPadDlg dlg(this, triesLeft, hSession, bIsPIN2);
                    dlg.SetIcon(GetIcon());
                    rv = dlg.ShowModal();
                    m_cryptokiObject->C_CloseSession(hSession);

                    if (rv == CKR_PIN_INCORRECT)
                    {
                        // check if we have only one try left
						wxLogMessage(wxString::Format(wxT("The current %s entered is incorrect."), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        int choice = Error(wxString::Format(_("The current %s your entered is incorrect.\nDo you want to retry?"), (bIsPIN2)? _("PIN2"):_("PIN1")), true);
                        if (wxYES == choice)
                        {
							wxLogMessage(wxT("Retrying..."));
                            continue;
                        }
						else
						{
							wxLogMessage(wxT("Change PIN stopped"));
                            break;
						}
                    }
                    else if (rv == CKR_PIN_LOCKED)
                    {
                        Error(wxString::Format(_("The %s of the card is locked."), (bIsPIN2)? _("PIN2"):_("PIN1")));
						wxLogMessage(wxString::Format(wxT("The %s of the card is locked."), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        break;
                    }
                    else if (rv == CKR_FUNCTION_CANCELED)
			        {
				        wxLogMessage(wxT("Request canceled by user"));
                        break;
			        }
                    else if (rv != CKR_OK && rv != CKR_FUNCTION_NOT_SUPPORTED)
                    {
                        Error(wxString::Format(_("Error \"%s\" while changing %s of the card"),CK_RVtoName(rv), (bIsPIN2)? _("PIN2"):_("PIN1")));
						wxLogMessage(wxString::Format(wxT("Error \"%s\" while changing %s of the card"),CK_RVtoName(rv), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        break;
                    }
                    else if (rv == CKR_OK)
                    {
                        break;
                    }
                }
            }

            MyChangePinDlg dlg(this, triesLeft, bIsPIN2);
            dlg.SetIcon(GetIcon());
            if (dlg.ShowModal() == wxID_OK)
            {
                wxBusyCursor waitCursor;
                // convert PIN values to UTF8
                wxScopedCharBuffer oldPin = dlg.m_szOldPin.utf8_str();
                wxScopedCharBuffer newPin = dlg.m_szNewPin.utf8_str();
                CK_SESSION_HANDLE hSession;
                CK_RV rv = m_cryptokiObject->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
                if (rv != CKR_OK)
				{
                    Error(wxString::Format(_("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
					wxLogMessage(wxString::Format(wxT("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
				}
                else
                {
                    rv = m_cryptokiObject->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR) oldPin.data(), oldPin.length());
                    if (rv == CKR_PIN_INCORRECT)
                    {
                        // check if we have only one try left
						wxLogMessage(wxString::Format(wxT("The current %s entered is incorrect."), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        int choice = Error(wxString::Format(_("The current %s your entered is incorrect.\nDo you want to retry?"), (bIsPIN2)? _("PIN2"):_("PIN1")), true);
                        if (wxYES == choice)
                        {
							wxLogMessage(wxT("Retrying..."));
                            m_cryptokiObject->C_CloseSession(hSession);
                            continue;
                        }
						else
						{
							wxLogMessage(wxT("Change PIN stopped"));
						}
                    }
                    else if (rv == CKR_PIN_LOCKED)
                    {
                        Error(wxString::Format(_("The %s of the card is locked."), (bIsPIN2)? _("PIN2"):_("PIN1")));
						wxLogMessage(wxString::Format(wxT("The %s of the card is locked."), (bIsPIN2)? _("PIN2"):_("PIN1")));
                    }
                    else if (rv != CKR_OK)
                    {
                        Error(wxString::Format(_("Error \"%s\" while authenticating to the card"),CK_RVtoName(rv)));
						wxLogMessage(wxString::Format(wxT("Error \"%s\" while authenticating to the card"),CK_RVtoName(rv)));
                    }

                    if (rv == CKR_OK)
                    {
                        rv = m_cryptokiObject->C_SetPIN(hSession, (CK_UTF8CHAR_PTR) oldPin.data(), oldPin.length(), 
                                                (CK_UTF8CHAR_PTR) newPin.data(), newPin.length());
                        if (rv == CKR_OK)
						{
                            Info(wxString::Format(_("%s has been changed successfully"), (bIsPIN2)? _("PIN2"): _("PIN1")));
							wxLogMessage(wxString::Format(wxT("%s has been changed successfully"), (bIsPIN2)? _("PIN2"): _("PIN1")));
						}
                        else
                        {
                            Error(wxString::Format(_("Error \"%s\" while changing %s of the card"),CK_RVtoName(rv), (bIsPIN2)? _("PIN2"):_("PIN1")));
							wxLogMessage(wxString::Format(wxT("Error \"%s\" while changing %s of the card"),CK_RVtoName(rv), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        }
                        m_cryptokiObject->C_Logout(hSession);
                    }

                    m_cryptokiObject->C_CloseSession(hSession);
                }
                break;
            }
            else
			{
				wxLogMessage(wxT("Request canceled by user"));
                break;
			}
        }
    }

    void HandleUnblockPin(bool bIsPIN2 = false)
    {
        CK_SLOT_ID slotID = (bIsPIN2)? m_currentSlotID + 1 : m_currentSlotID; // PIN2 is in the second slot
		bool bIsPinPAD = false;

        while (true)
        {
            int triesLeft = GetPukTriesLeft(slotID, bIsPinPAD);
            if (triesLeft == 0)
            {
                Error(_("PUK of the card is blocked"));
                break;
            }
			
            if (bIsPinPAD)
			{
                CK_SESSION_HANDLE hSession;
                CK_RV rv = m_cryptokiObject->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
                if (rv != CKR_OK)
				{
                    Error(wxString::Format(_("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
					wxLogMessage(wxString::Format(wxT("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
                    break;
				}
                else
                {
                    MyUnblockPinPadDlg dlg(this, triesLeft, hSession, bIsPIN2);
                    dlg.SetIcon(GetIcon());
                    rv = dlg.ShowModal();
                    m_cryptokiObject->C_CloseSession(hSession);

                    if (rv == CKR_PIN_INCORRECT)
                    {
                        if (wxYES == Error(wxString::Format(_("The PUK your entered is incorrect.\nDo you want to retry?")), true))
                        {
                            m_cryptokiObject->C_CloseSession(hSession);
                            continue;
                        }
                    }
                    else if (rv == CKR_PIN_LOCKED)
                    {
                        Error(wxString::Format(_("The PUK of the card is locked.")));
                        break;
                    }
                    else if (rv == CKR_FUNCTION_CANCELED)
			        {
				        wxLogMessage(wxT("Request canceled by user"));
                        break;
			        }
                    else if(rv != CKR_OK && rv != CKR_FUNCTION_NOT_SUPPORTED)
                    {
                        Error(wxString::Format(_("Error \"%s\" while unblocking %s of the card"),CK_RVtoName(rv), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        break;
                    }
                    else if (rv == CKR_OK)
                    {
                        Info(wxString::Format(_("%s has been unblocked successfully"), (bIsPIN2)? _("PIN2"): _("PIN1")));
                        break;
                    }
                    
                    Warning(wxString::Format(_("Your PinPAD doesn't support PIN modification")));
                }
			}

            MyUnblockPinDlg dlg(this, triesLeft, bIsPIN2);
            dlg.SetIcon(GetIcon());
            if (dlg.ShowModal() == wxID_OK)
            {
                wxBusyCursor waitCursor;
                // convert PIN values to UTF8
                wxScopedCharBuffer puk = dlg.m_szPuk.utf8_str();
                wxScopedCharBuffer newPin = dlg.m_szNewPin.utf8_str();
                CK_SESSION_HANDLE hSession;
                CK_SLOT_ID slotID = (bIsPIN2)? m_currentSlotID + 1 : m_currentSlotID; // PIN2 is in the second slot
                CK_RV rv = m_cryptokiObject->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
                if (rv != CKR_OK)
                    Error(wxString::Format(_("Error \"%s\" occured while opening a session on the smart card"),CK_RVtoName(rv)));
                else
                {
                    rv = m_cryptokiObject->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR) puk.data(), puk.length());
                    if (rv == CKR_PIN_INCORRECT)
                    {
                        if (wxYES == Error(wxString::Format(_("The PUK your entered is incorrect.\nDo you want to retry?")), true))
                        {
                            m_cryptokiObject->C_CloseSession(hSession);
                            continue;
                        }
                    }
                    else if (rv == CKR_PIN_LOCKED)
                    {
                        Error(wxString::Format(_("The PUK of the card is locked.")));
                    }
                    else if (rv != CKR_OK)
                    {
                        Error(wxString::Format(_("Error \"%s\" while verifying the PUK of the card"),CK_RVtoName(rv)));
                    }

                    if (rv == CKR_OK)
                    {
                        rv = m_cryptokiObject->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) newPin.data(), newPin.length());
                        if (rv == CKR_OK)
                            Info(wxString::Format(_("%s has been unblocked successfully"), (bIsPIN2)? _("PIN2"): _("PIN1")));
                        else
                        {
                            Error(wxString::Format(_("Error \"%s\" while unblocking %s of the card"),CK_RVtoName(rv), (bIsPIN2)? _("PIN2"):_("PIN1")));
                        }

                        m_cryptokiObject->C_Logout(hSession);
                    }

                    m_cryptokiObject->C_CloseSession(hSession);
                }
                break;
            }
            else
                break;
        }
    }

	virtual void HandleChangePin1( wxCommandEvent& event )
    { 
        HandleChangePin();
    }

	virtual void HandleUnblockPin1( wxCommandEvent& event )
    { 
        HandleUnblockPin();
    }

	virtual void HandleChangePin2( wxCommandEvent& event )
    {
        HandleChangePin(true);
    }

	virtual void HandleUnblockPin2( wxCommandEvent& event )
    {
        HandleUnblockPin(true);
    }



public:
	wxConfigBase*			m_config;
    wxChar				    m_buffer[2048];
    wxDynamicLibrary	    &m_pkcs11Dll;
    CCryptoki*              &m_cryptokiObject;
    wxString                m_szSelectedReader;
    CK_SLOT_ID              m_currentSlotID;
    wxMemoryBuffer          m_authCertValue;
    wxMemoryBuffer          m_signCertValue;
    wxMemoryBuffer          m_cipherCertValue;

    MyPinToolFrame(wxDynamicLibrary& pkcs11Dll, CCryptoki* &cryptokiObject)
		: PinToolFrame(NULL),
		m_cryptokiObject(cryptokiObject),
		m_pkcs11Dll(pkcs11Dll),
		m_currentSlotID(0),
		m_config(wxConfigBase::Get(false))
    {
        m_statusBar->SetStatusText(_("Not connected"));

		// Read prefered reader from configuration
		m_szSelectedReader = m_config->Read(wxT("PreferedReader"));

		// adapt the welcome logo
		int lng;
		if(!m_config->Read(wxT("Languages/Selected"),&lng))
		{
			lng = wxLANGUAGE_ENGLISH_US;
		}

		if (lng == wxLANGUAGE_LATVIAN)
		{
			m_welcomeLogo->SetBitmap(welcome_lv_PNG_to_wx_bitmap());
			m_WelcomePanel->Layout();
			m_WelcomePanel->GetSizer()->Fit( m_WelcomePanel );

			Layout();
		}
    }
		
    ~MyPinToolFrame()
    {

    }

    /* Helpers for usefull dialogs */
    void Warning(const wxString& szMsg)
    {
	    wxMessageBox(szMsg,_("Warning"),wxOK|wxICON_EXCLAMATION,this);
    }

    int Error(const wxString& szMsg, bool bShowYesNo = false)
    {
        int style = wxICON_ERROR;
        if (bShowYesNo)
            style |= wxYES_NO;
        else
            style |= wxOK;
	    return wxMessageBox(szMsg,_("Error"),style,this);
    }

    void Info(const wxString& szMsg)
    {
	    wxMessageBox(szMsg,_("Information"),wxOK|wxICON_INFORMATION,this);
    }

    int Question(const wxString& szMsg,const wxString& szTitle,int style )
    {
	    return wxMessageBox(szMsg,szTitle,wxYES_NO|style,this);
    }

    /* Loading the PKCS#11 library */
    bool LoadPkcs11Module()
    {
        if (m_pkcs11Dll.IsLoaded())
            return true;

	    wxBusyCursor wait;   
#ifdef _WIN32	        
        wxString szDllName = wxT("otlvp11.dll");
#else
        wxString szDllName = wxT(LATVIAEID_PREFIX "/lib/otlv-pkcs11.so");
#endif        

	    if(!m_pkcs11Dll.Load(szDllName, wxDL_LAZY))
	    {		
		    DWORD dwError = ::wxSysErrorCode();	
		    const wxChar * szMsg = ::wxSysErrorMsg(dwError);
		    if(!szMsg)
			{
				wxLogMessage(wxString::Format(wxT("Failed to load %s. Error 0x%.8X"), szDllName,  dwError));
                wxSnprintf(m_buffer,2048,_("The PKCS#11 module couldn't be loaded. Please check your installation.\nError 0x%.8X"),dwError);
			}
		    else
		    {
				wxLogMessage(wxString::Format(wxT("Failed to load %s. Error \"%s\""), szDllName,  szMsg));
			    wxSnprintf(m_buffer,2048,_("The PKCS#11 module couldn't be loaded. Please check your installation.\nError %s"),szMsg);
		    }				
		    Error(m_buffer);
            return false;
	    }
	    else
	    {
			wxLogMessage(szDllName + wxT(" loaded OK"));
		    CK_C_GetFunctionList fn = (CK_C_GetFunctionList) m_pkcs11Dll.GetSymbol(wxT("C_GetFunctionList"));
		    if(!fn)
		    {
				wxLogMessage(wxT("Unexpected fatal error : Entry point \"C_GetFunctionList\" not found on ") + szDllName);
                Error(_("\"C_GetFunctionList\" Entry point missing from the PKCS#11 dll. Please check your installation."));
			    m_pkcs11Dll.Unload();
                return false;
		    }
		    else
		    {
			    CK_FUNCTION_LIST_PTR cryptoki;
			    CK_RV rv = fn(&cryptoki); 
			    if(rv != CKR_OK)
			    {
					wxLogMessage(wxString::Format(wxT("Unexpected fatal error : \"C_GetFunctionList\" failed with error %s."), CK_RVtoName(rv)));
				    wxSnprintf(m_buffer,2048,_("C_GetFunctionList failed with error %s. Please check your installation."),CK_RVtoName(rv));
				    Error(m_buffer);
				    m_pkcs11Dll.Unload();
                    return false;
			    }
			    else
			    {
					wxLogMessage(wxT("CCryptoki object created successfully"));
                    m_cryptokiObject = new CCryptoki();
				    m_cryptokiObject->Set(cryptoki);
                    return true;
			    }
		    }
	    }
    }

    bool InitializePkcs11Module()
    {
	    if(!m_cryptokiObject)
	    {
            if (!LoadPkcs11Module())
                return false;
	    }

	    wxBusyCursor wait;
	    CK_RV rv=m_cryptokiObject->C_Initialize(NULL);
        if(rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
	    {
			wxLogMessage(wxString::Format(wxT("Error %s occured while initilizing the PKCS#11 module."),CK_RVtoName(rv)));
		    wxSnprintf(m_buffer,2048,_("Error %s occured while initilizing the PKCS#11 module."),CK_RVtoName(rv));
		    Error(m_buffer);
            return false;
	    }		
	    else
	    {
			if (rv == CKR_OK) wxLogMessage(wxT("PKCS#11 initialization OK"));
            // Call C_GetSlotList to initialize PKCS#11 internal state
            CK_ULONG ulCount = 0;
            m_cryptokiObject->C_GetSlotList(FALSE, NULL, &ulCount);
            return true;
	    }
    }

#ifdef __WXGTK__
	void CustomInit()
	{
		m_ConnectReaderButton->SetLabel(_("Connect to a card reader") );
		m_HelpButton->SetLabel( _("Help                                 ") );
		m_ConnectReaderButton->SetCursor(wxCursor(wxCURSOR_HAND));
		m_HelpButton->SetCursor(wxCursor(wxCURSOR_HAND));
	}
#endif
};

////////////////////////////////
int MyApp::OnExit()
{
    if (m_cryptokiObject)
    {
        m_cryptokiObject->C_Finalize(NULL);
        delete m_cryptokiObject;
    }
    if (m_pkcs11Dll.IsLoaded())
        m_pkcs11Dll.Unload();

	wxLogMessage(wxT("PinTool exited"));
	wxLog::SetTimestamp(wxT(""));
	wxLogMessage(wxT("********************************************************************************************\n"));

	int status = wxApp::OnExit();
	wxLog* logger = wxLog::SetActiveTarget(NULL);
	if (logger) delete logger;
	if (m_locale) delete m_locale;

	delete m_checker;

	return status;
}

void MyApp::CreateGUI(const wxPoint& position)
{
	wxWindow * topwindow = GetTopWindow();
	if(topwindow)
	{
		SetTopWindow(NULL);
		topwindow->Destroy();
	}

    MyPinToolFrame* frame_1 = new MyPinToolFrame(m_pkcs11Dll, m_cryptokiObject);
	frame_1->SetPosition(position);

	wxIcon _icon;
    _icon.CopyFromBitmap(wxBitmap(wxICON(pintoolicon)));
	frame_1->SetIcon(_icon);

#ifdef _WIN32
    if (IsWindowsThemesActive() == false)
    {		
        frame_1->m_ConnectReaderButton->SetBackgroundColour(frame_1->m_WelcomePanel->GetBackgroundColour());
        frame_1->m_HelpButton->SetBackgroundColour(frame_1->m_WelcomePanel->GetBackgroundColour());
    }
	else
	{
		frame_1->m_WelcomePanel->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
		frame_1->m_InformationPanel->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
	}
#endif
	
#ifdef __APPLE__
	
#endif	

    frame_1->m_ConnectReaderButton->SetBitmap(arrow_png_to_wx_bitmap());
    frame_1->m_HelpButton->SetBitmap(arrow_png_to_wx_bitmap());
#ifdef __WXGTK__    
	frame_1->CustomInit();  
    frame_1->SetSizeHints( wxSize( 600,600 ), wxSize( 600,600 ) );   
	frame_1->Layout();	
	frame_1->Centre( wxBOTH );   
#endif
	
#ifdef __APPLE__
	frame_1->m_WelcomePanel->SetFocus();
#endif
    SetTopWindow(frame_1);
    frame_1->Show();
}

int MyApp::InitLanguages()
{
	if (m_locale) delete m_locale;
	m_locale = new wxLocale;

	int lng = wxLANGUAGE_ENGLISH_US;

	if(!m_config->Read(wxT("Languages/Selected"),&lng))
	{
		lng = wxLocale::GetSystemLanguage();
		if (lng >= wxLANGUAGE_ENGLISH && lng <= wxLANGUAGE_ENGLISH_ZIMBABWE)
			lng = wxLANGUAGE_ENGLISH_US;
		if (lng != wxLANGUAGE_ENGLISH_US && lng != wxLANGUAGE_LATVIAN)
			lng = wxLANGUAGE_ENGLISH_US;
		m_config->Write(wxT("Languages/Selected"),lng);
	}
	
	if ( !m_locale->Init(lng, 0) )
	{		
		if(m_locale->Init(wxLANGUAGE_ENGLISH_US, 0) )
		{
			lng = wxLANGUAGE_ENGLISH_US;
			m_config->Write(wxT("Languages/Selected"),lng);
		}
	}

#ifndef __APPLE__   
    wxLocale::AddCatalogLookupPathPrefix(wxPathOnly(wxStandardPaths::Get().GetExecutablePath()) + wxFileName::GetPathSeparator() +  wxT("Languages"));
#else    
    wxLocale::AddCatalogLookupPathPrefix(wxPathOnly(wxStandardPaths::Get().GetExecutablePath()) + wxFileName::GetPathSeparator() +  wxT("../Resources/Languages"));
#endif   
	m_locale->AddCatalog(wxT("wx"));
    m_locale->AddCatalog(wxT("pintool"));

	return lng;
}

bool MyApp::OnInit()
{
#if defined( __WXGTK__ )
	// force GTK to show icons on menus and buttons
	wxExecute(wxT("gconftool-2 --type boolean --set /desktop/gnome/interface/menus_have_icons true"));
	wxExecute(wxT("gconftool-2 --type boolean --set /desktop/gnome/interface/buttons_have_icons true"));
#endif	
	SetAppName(_("PinTool"));
	
	wxLog::EnableLogging(false);
	wxLog::SetComponentLevel(wxT("wx"), wxLOG_FatalError );

	//configuration object
	m_config = new wxConfig(wxT("PinTool"),wxT("Latvia eID"),wxEmptyString,wxEmptyString,wxCONFIG_USE_LOCAL_FILE);
	wxConfigBase::Set(m_config);

	m_locale = NULL;
	int lng = InitLanguages();

    m_checker = new wxSingleInstanceChecker;
    if ( m_checker->IsAnotherRunning() )
    {
		wxMessageBox(_("PinTool is already running"), _("Warning"), wxOK | wxICON_EXCLAMATION);
        delete m_checker;
        m_checker = NULL;
		delete m_locale;
		m_locale = NULL;
		delete m_config;
		m_config = NULL;
        return false;
    }

    wxInitAllImageHandlers();          
#if defined( __WXGTK__ )
    wxString szUserAppDir = wxStandardPaths::Get().GetUserDataDir() + wxT("-data");
#else
	wxString szUserAppDir = wxStandardPaths::Get().GetUserDataDir();
#endif
	m_szLogFile = szUserAppDir + wxFileName::GetPathSeparator() + wxT("PinToolLogs.txt");

	if(!wxDirExists(szUserAppDir))
		wxMkdir(szUserAppDir);

	m_logFile.Open(m_szLogFile, wxT("at"));
	if (m_logFile.IsOpened())
	{
		wxLog::SetActiveTarget(new wxLogStderr(m_logFile.fp()));
		wxLog::EnableLogging(true);
		wxLog::SetComponentLevel(wxT("wx"), wxLOG_Error);

		wxLog::SetTimestamp(wxT(""));
		wxLogMessage(wxT("********************************************************************************************"));

		wxLog::SetTimestamp(wxT("%d-%m-%Y %H:%M:%S"));
	}
	else
	{
		wxLog::EnableLogging(false);
		wxLog::SetComponentLevel(wxT("wx"), wxLOG_Error);
	}

	wxLogMessage(wxT("PinTool started"));

	wxLogMessage(wxT("Initial GUI language = ") + wxLocale::GetLanguageName(lng));
	// Read prefered reader from configuration
	wxString szSelectedReader = m_config->Read(wxT("PreferedReader"));
	if (szSelectedReader.IsEmpty())
	{
		wxLogMessage(wxT("No Prefered Reader"));
	}
    else
	{
		wxLogMessage(wxT("Prefered reader = \"%s\""), szSelectedReader.c_str());
	}

	m_cryptokiObject = NULL;

	CreateGUI();

    return true;
}
