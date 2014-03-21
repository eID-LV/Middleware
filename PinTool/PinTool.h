///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Apr 10 2012)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#ifndef __PINTOOL_H__
#define __PINTOOL_H__

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/statbmp.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/button.h>
#include <wx/sizer.h>
#include <wx/panel.h>
#include <wx/stattext.h>
#include <wx/textctrl.h>
#include <wx/notebook.h>
#include <wx/menu.h>
#include <wx/statusbr.h>
#include <wx/frame.h>
#include <wx/combobox.h>
#include <wx/dialog.h>
#include <wx/hyperlink.h>
#include <wx/collpane.h>
extern wxBitmap& oberthur_png_to_wx_bitmap();

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class PinToolFrame
///////////////////////////////////////////////////////////////////////////////
class PinToolFrame : public wxFrame 
{
	private:
	
	protected:
		enum
		{
			ID_CARD_READER = 1000,
			ID_LANGUAGE_ENGLISH,
			ID_LANGUAGE_LATVIAN,
			ID_HELP_CONTENTS,
			ID_LOGS
		};
		
		wxPanel* m_panel3;
		wxNotebook* m_mainTabs;
		wxStaticBitmap* m_welcomeLogo;
		wxPanel* m_panel10;
		wxNotebook* m_certTabs;
		wxPanel* m_authCertTab;
		wxStaticText* m_staticText1;
		wxStaticText* m_staticText2;
		wxStaticText* m_staticText4;
		wxTextCtrl* m_authFirstName;
		wxStaticText* m_staticText5;
		wxTextCtrl* m_authLastName;
		wxStaticText* m_staticText6;
		wxTextCtrl* m_authPersonalNumber;
		wxStaticText* m_staticText7;
		wxStaticText* m_staticText8;
		wxTextCtrl* m_authAuthorityName;
		wxStaticText* m_staticText9;
		wxStaticText* m_staticText10;
		wxTextCtrl* m_authFrom;
		wxStaticText* m_staticText11;
		wxTextCtrl* m_authTo;
		wxButton* m_authExportCert;
		wxButton* m_authChangePin1;
		wxButton* m_authUnblockPin1;
		wxPanel* m_signCertTab;
		wxStaticText* m_staticText13;
		wxStaticText* m_staticText21;
		wxStaticText* m_staticText41;
		wxTextCtrl* m_signFirstName;
		wxStaticText* m_staticText51;
		wxTextCtrl* m_signLastName;
		wxStaticText* m_staticText61;
		wxTextCtrl* m_signPersonalNumber;
		wxStaticText* m_staticText71;
		wxStaticText* m_staticText81;
		wxTextCtrl* m_signAuthorityName;
		wxStaticText* m_staticText91;
		wxStaticText* m_staticText101;
		wxTextCtrl* m_signFrom;
		wxStaticText* m_staticText111;
		wxTextCtrl* m_signTo;
		wxButton* m_signExportCert;
		wxButton* m_signChangePin2;
		wxButton* m_signUnblockPin2;
		wxPanel* m_cipherCertTab;
		wxStaticText* m_staticText14;
		wxStaticText* m_staticText22;
		wxStaticText* m_staticText42;
		wxTextCtrl* m_cipherFirstName;
		wxStaticText* m_staticText52;
		wxTextCtrl* m_cipherLastName;
		wxStaticText* m_staticText62;
		wxTextCtrl* m_cipherPersonalNumber;
		wxStaticText* m_staticText72;
		wxStaticText* m_staticText82;
		wxTextCtrl* m_cipherAuthorityName;
		wxStaticText* m_staticText92;
		wxStaticText* m_staticText102;
		wxTextCtrl* m_cipherFrom;
		wxStaticText* m_staticText112;
		wxTextCtrl* m_cipherTo;
		wxButton* m_cipherExportCert;
		wxButton* m_cipherChangePin1;
		wxButton* m_cipherUnblockPin1;
		wxMenuBar* m_menubar1;
		wxMenu* settings;
		wxMenu* language;
		wxMenu* help;
		wxStatusBar* m_statusBar;
		
		// Virtual event handlers, overide them in your derived class
		virtual void HandlePageChanging( wxNotebookEvent& event ) { event.Skip(); }
		virtual void HandleConnectToCardReader( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMouseEvent( wxMouseEvent& event ) { event.Skip(); }
		virtual void HandleHelp( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleExportAuthCert( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleChangePin1( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleUnblockPin1( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleExportSignCert( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleChangePin2( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleUnblockPin2( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleExportCipherCert( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMenuCardReader( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMenuSelectEnglish( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMenuSelectLatvia( wxCommandEvent& event ) { event.Skip(); }
		virtual void handleMenuExit( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMenuHelp( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMenuLogs( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleMenuAbout( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		wxPanel* m_WelcomePanel;
		wxButton* m_ConnectReaderButton;
		wxButton* m_HelpButton;
		wxPanel* m_InformationPanel;
		
		PinToolFrame( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Latvia eID Pintool"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 600,520 ), long style = wxCAPTION|wxCLOSE_BOX|wxMINIMIZE_BOX|wxSYSTEM_MENU|wxCLIP_CHILDREN|wxTAB_TRAVERSAL );
		
		~PinToolFrame();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class ReaderSelectionDlg
///////////////////////////////////////////////////////////////////////////////
class ReaderSelectionDlg : public wxDialog 
{
	private:
	
	protected:
		wxStaticText* m_staticText31;
		wxComboBox* m_readersList;
		wxStdDialogButtonSizer* m_buttonsSizer;
		wxButton* m_buttonsSizerOK;
		wxButton* m_buttonsSizerCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void HandleOkButton( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		ReaderSelectionDlg( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Please choose your prefered reader to use"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 450,120 ), long style = wxDEFAULT_DIALOG_STYLE ); 
		~ReaderSelectionDlg();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class ChangePinDlg
///////////////////////////////////////////////////////////////////////////////
class ChangePinDlg : public wxDialog 
{
	private:
	
	protected:
		wxStaticText* m_currentPinlabel;
		wxTextCtrl* m_currentPin;
		wxStaticText* m_newPinLabel;
		wxTextCtrl* m_newPin;
		wxStaticText* m_confirmNewPinLabel;
		wxTextCtrl* m_confirmNewPin;
		wxStaticText* m_triesLeftLabel;
		wxPanel* m_panel8;
		wxStdDialogButtonSizer* m_buttonsSizer;
		wxButton* m_buttonsSizerOK;
		wxButton* m_buttonsSizerCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void HandleTextChange( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleOkButton( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		ChangePinDlg( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Change PIN1"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 346,207 ), long style = wxDEFAULT_DIALOG_STYLE ); 
		~ChangePinDlg();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class UnblockPinDlg
///////////////////////////////////////////////////////////////////////////////
class UnblockPinDlg : public wxDialog 
{
	private:
	
	protected:
		wxStaticText* m_puklabel;
		wxTextCtrl* m_puk;
		wxStaticText* m_newPinLabel;
		wxTextCtrl* m_newPin;
		wxStaticText* m_confirmNewPinLabel;
		wxTextCtrl* m_confirmNewPin;
		wxStaticText* m_triesLeftLabel;
		wxPanel* m_panel9;
		wxStdDialogButtonSizer* m_buttonsSizer;
		wxButton* m_buttonsSizerOK;
		wxButton* m_buttonsSizerCancel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void HandleTextChange( wxCommandEvent& event ) { event.Skip(); }
		virtual void HandleOkButton( wxCommandEvent& event ) { event.Skip(); }
		
	
	public:
		
		UnblockPinDlg( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Unblock PIN1"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 346,210 ), long style = wxDEFAULT_DIALOG_STYLE ); 
		~UnblockPinDlg();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class PinToolAboutDlg
///////////////////////////////////////////////////////////////////////////////
class PinToolAboutDlg : public wxDialog 
{
	private:
	
	protected:
		wxStaticBitmap* m_bitmap2;
		wxStaticText* m_staticText40;
		wxStaticText* m_staticText41;
		wxStaticText* m_staticText42;
		wxHyperlinkCtrl* m_hyperlink1;
		wxHyperlinkCtrl* m_hyperlink3;
		wxCollapsiblePane *m_developerPanel;
		wxStdDialogButtonSizer* m_sdbSizer4;
		wxButton* m_sdbSizer4OK;
		
		// Virtual event handlers, overide them in your derived class
		virtual void HandleLinkClick( wxHyperlinkEvent& event ) { event.Skip(); }
		virtual void handleChangeLog( wxHyperlinkEvent& event ) { event.Skip(); }
		
	
	public:
		
		PinToolAboutDlg( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("About PinTool"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( -1,-1 ), long style = wxCAPTION|wxCLOSE_BOX|wxSYSTEM_MENU ); 
		~PinToolAboutDlg();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class ChangePinPadDlg
///////////////////////////////////////////////////////////////////////////////
class ChangePinPadDlg : public wxDialog 
{
	private:
	
	protected:
		wxStaticBitmap* m_bitmap4;
		wxStaticText* m_description;
		wxStaticText* m_triesLeftLabel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void handleOnClose( wxCloseEvent& event ) { event.Skip(); }
		
	
	public:
		
		ChangePinPadDlg( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Change PIN1"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 455,132 ), long style = wxCAPTION ); 
		~ChangePinPadDlg();
	
};

///////////////////////////////////////////////////////////////////////////////
/// Class UnblockPinPadDlg
///////////////////////////////////////////////////////////////////////////////
class UnblockPinPadDlg : public wxDialog 
{
	private:
	
	protected:
		wxStaticBitmap* m_bitmap4;
		wxStaticText* m_description;
		wxStaticText* m_triesLeftLabel;
		
		// Virtual event handlers, overide them in your derived class
		virtual void handleOnClose( wxCloseEvent& event ) { event.Skip(); }
		
	
	public:
		
		UnblockPinPadDlg( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Unblock PIN1"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 455,132 ), long style = wxCAPTION ); 
		~UnblockPinPadDlg();
	
};

#endif //__PINTOOL_H__
