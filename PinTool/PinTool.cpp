///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version Apr 10 2012)
// http://www.wxformbuilder.org/
//
// PLEASE DO "NOT" EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include "PinTool.h"

#include "res/about.png.h"
#include "res/exit.png.h"
#include "res/help.png.h"
#include "res/logs.png.h"
#include "res/lv.png.h"
#include "res/pinpad.png.h"
#include "res/pintool.ico.h"
#include "res/settings.png.h"
#include "res/us.png.h"
#include "res/welcome.PNG.h"

///////////////////////////////////////////////////////////////////////////

PinToolFrame::PinToolFrame( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxFrame( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( 600,520 ), wxSize( 600,520 ) );
	
	wxBoxSizer* bSizer2;
	bSizer2 = new wxBoxSizer( wxVERTICAL );
	
	m_panel3 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer3;
	bSizer3 = new wxBoxSizer( wxVERTICAL );
	
	m_mainTabs = new wxNotebook( m_panel3, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxNB_NOPAGETHEME );
	m_WelcomePanel = new wxPanel( m_mainTabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer4;
	bSizer4 = new wxBoxSizer( wxVERTICAL );
	
	m_welcomeLogo = new wxStaticBitmap( m_WelcomePanel, wxID_ANY, welcome_PNG_to_wx_bitmap(), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer4->Add( m_welcomeLogo, 0, wxALIGN_CENTER|wxALL, 5 );
	
	m_ConnectReaderButton = new wxButton( m_WelcomePanel, wxID_ANY, _("Connect to a card reader"), wxDefaultPosition, wxDefaultSize, wxBU_BOTTOM|wxBU_LEFT|wxNO_BORDER );
	m_ConnectReaderButton->SetFont( wxFont( 16, 70, 90, 90, false, wxEmptyString ) );
	m_ConnectReaderButton->SetForegroundColour( wxColour( 145, 0, 2 ) );
#ifndef __APPLE__	
	m_ConnectReaderButton->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
#endif	
	bSizer4->Add( m_ConnectReaderButton, 0, wxALIGN_CENTER|wxALL|wxEXPAND, 27 );
	
	m_HelpButton = new wxButton( m_WelcomePanel, wxID_ANY, _("Help                                 "), wxDefaultPosition, wxDefaultSize, wxBU_BOTTOM|wxBU_LEFT|wxNO_BORDER );
	m_HelpButton->SetFont( wxFont( 16, 70, 90, 90, false, wxEmptyString ) );
	m_HelpButton->SetForegroundColour( wxColour( 145, 0, 2 ) );
#ifndef __APPLE__	
	m_HelpButton->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
#endif	
	bSizer4->Add( m_HelpButton, 0, wxALIGN_CENTER|wxEXPAND|wxLEFT|wxRIGHT, 27 );
	
	
	m_WelcomePanel->SetSizer( bSizer4 );
	m_WelcomePanel->Layout();
	bSizer4->Fit( m_WelcomePanel );
	m_mainTabs->AddPage( m_WelcomePanel, _("Welcome"), true );
	m_InformationPanel = new wxPanel( m_mainTabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_InformationPanel->Enable( false );
	
	wxBoxSizer* bSizer7;
	bSizer7 = new wxBoxSizer( wxVERTICAL );
	
	m_panel10 = new wxPanel( m_InformationPanel, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	wxBoxSizer* bSizer9;
	bSizer9 = new wxBoxSizer( wxVERTICAL );
	
	m_certTabs = new wxNotebook( m_panel10, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM|wxNB_NOPAGETHEME );
	m_certTabs->Enable( false );
	
	m_authCertTab = new wxPanel( m_certTabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_authCertTab->Enable( false );
	
	wxBoxSizer* bSizer8;
	bSizer8 = new wxBoxSizer( wxVERTICAL );
	
	m_staticText1 = new wxStaticText( m_authCertTab, wxID_ANY, _("Authentication Certificate"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText1->Wrap( -1 );
	m_staticText1->SetFont( wxFont( 18, 70, 90, 92, false, wxEmptyString ) );
	
	bSizer8->Add( m_staticText1, 0, wxALL|wxEXPAND, 5 );
	
	m_staticText2 = new wxStaticText( m_authCertTab, wxID_ANY, _("Issued to"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText2->Wrap( -1 );
	m_staticText2->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText2->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer8->Add( m_staticText2, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer1;
	fgSizer1 = new wxFlexGridSizer( 3, 2, 0, 0 );
	fgSizer1->AddGrowableCol( 1 );
	fgSizer1->SetFlexibleDirection( wxVERTICAL );
	fgSizer1->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText4 = new wxStaticText( m_authCertTab, wxID_ANY, _("First Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText4->Wrap( -1 );
	fgSizer1->Add( m_staticText4, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_authFirstName = new wxTextCtrl( m_authCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_authFirstName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer1->Add( m_authFirstName, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText5 = new wxStaticText( m_authCertTab, wxID_ANY, _("Last Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText5->Wrap( -1 );
	fgSizer1->Add( m_staticText5, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_authLastName = new wxTextCtrl( m_authCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_authLastName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer1->Add( m_authLastName, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText6 = new wxStaticText( m_authCertTab, wxID_ANY, _("Personal Number :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText6->Wrap( -1 );
	fgSizer1->Add( m_staticText6, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_authPersonalNumber = new wxTextCtrl( m_authCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_authPersonalNumber->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer1->Add( m_authPersonalNumber, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer8->Add( fgSizer1, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	m_staticText7 = new wxStaticText( m_authCertTab, wxID_ANY, _("Issued by"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText7->Wrap( -1 );
	m_staticText7->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText7->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer8->Add( m_staticText7, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer2;
	fgSizer2 = new wxFlexGridSizer( 1, 2, 0, 0 );
	fgSizer2->AddGrowableCol( 1 );
	fgSizer2->SetFlexibleDirection( wxVERTICAL );
	fgSizer2->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText8 = new wxStaticText( m_authCertTab, wxID_ANY, _("Authority Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText8->Wrap( -1 );
	fgSizer2->Add( m_staticText8, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_authAuthorityName = new wxTextCtrl( m_authCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_authAuthorityName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer2->Add( m_authAuthorityName, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer8->Add( fgSizer2, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	m_staticText9 = new wxStaticText( m_authCertTab, wxID_ANY, _("Validity"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText9->Wrap( -1 );
	m_staticText9->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText9->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer8->Add( m_staticText9, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer3;
	fgSizer3 = new wxFlexGridSizer( 2, 2, 0, 0 );
	fgSizer3->AddGrowableCol( 1 );
	fgSizer3->SetFlexibleDirection( wxVERTICAL );
	fgSizer3->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText10 = new wxStaticText( m_authCertTab, wxID_ANY, _("From :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText10->Wrap( -1 );
	fgSizer3->Add( m_staticText10, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_authFrom = new wxTextCtrl( m_authCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_authFrom->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer3->Add( m_authFrom, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText11 = new wxStaticText( m_authCertTab, wxID_ANY, _("To: "), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText11->Wrap( -1 );
	fgSizer3->Add( m_staticText11, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_authTo = new wxTextCtrl( m_authCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_authTo->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer3->Add( m_authTo, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer8->Add( fgSizer3, 1, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxBoxSizer* bSizer10;
	bSizer10 = new wxBoxSizer( wxHORIZONTAL );
	
	m_authExportCert = new wxButton( m_authCertTab, wxID_ANY, _("Export Certificate"), wxDefaultPosition, wxDefaultSize, 0 );
	m_authExportCert->Enable( false );
	
	bSizer10->Add( m_authExportCert, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_authChangePin1 = new wxButton( m_authCertTab, wxID_ANY, _("Change PIN1"), wxDefaultPosition, wxDefaultSize, 0 );
	m_authChangePin1->Enable( false );
	
	bSizer10->Add( m_authChangePin1, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_authUnblockPin1 = new wxButton( m_authCertTab, wxID_ANY, _("Unblock PIN1"), wxDefaultPosition, wxDefaultSize, 0 );
	m_authUnblockPin1->Enable( false );
	
	bSizer10->Add( m_authUnblockPin1, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	
	bSizer8->Add( bSizer10, 0, wxALIGN_RIGHT|wxBOTTOM|wxRIGHT, 5 );
	
	
	m_authCertTab->SetSizer( bSizer8 );
	m_authCertTab->Layout();
	bSizer8->Fit( m_authCertTab );
	m_certTabs->AddPage( m_authCertTab, _("Authentication Certificate"), true );
	m_signCertTab = new wxPanel( m_certTabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_signCertTab->Enable( false );
	
	wxBoxSizer* bSizer81;
	bSizer81 = new wxBoxSizer( wxVERTICAL );
	
	m_staticText13 = new wxStaticText( m_signCertTab, wxID_ANY, _("Signature Certificate"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText13->Wrap( -1 );
	m_staticText13->SetFont( wxFont( 18, 70, 90, 92, false, wxEmptyString ) );
	
	bSizer81->Add( m_staticText13, 0, wxALL|wxEXPAND, 5 );
	
	m_staticText21 = new wxStaticText( m_signCertTab, wxID_ANY, _("Issued to"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText21->Wrap( -1 );
	m_staticText21->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText21->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer81->Add( m_staticText21, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer11;
	fgSizer11 = new wxFlexGridSizer( 3, 2, 0, 0 );
	fgSizer11->AddGrowableCol( 1 );
	fgSizer11->SetFlexibleDirection( wxVERTICAL );
	fgSizer11->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText41 = new wxStaticText( m_signCertTab, wxID_ANY, _("First Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText41->Wrap( -1 );
	fgSizer11->Add( m_staticText41, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_signFirstName = new wxTextCtrl( m_signCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_signFirstName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer11->Add( m_signFirstName, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText51 = new wxStaticText( m_signCertTab, wxID_ANY, _("Last Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText51->Wrap( -1 );
	fgSizer11->Add( m_staticText51, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_signLastName = new wxTextCtrl( m_signCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_signLastName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer11->Add( m_signLastName, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText61 = new wxStaticText( m_signCertTab, wxID_ANY, _("Personal Number :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText61->Wrap( -1 );
	fgSizer11->Add( m_staticText61, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_signPersonalNumber = new wxTextCtrl( m_signCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_signPersonalNumber->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer11->Add( m_signPersonalNumber, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer81->Add( fgSizer11, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	m_staticText71 = new wxStaticText( m_signCertTab, wxID_ANY, _("Issued by"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText71->Wrap( -1 );
	m_staticText71->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText71->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer81->Add( m_staticText71, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer21;
	fgSizer21 = new wxFlexGridSizer( 1, 2, 0, 0 );
	fgSizer21->AddGrowableCol( 1 );
	fgSizer21->SetFlexibleDirection( wxVERTICAL );
	fgSizer21->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText81 = new wxStaticText( m_signCertTab, wxID_ANY, _("Authority Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText81->Wrap( -1 );
	fgSizer21->Add( m_staticText81, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_signAuthorityName = new wxTextCtrl( m_signCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_signAuthorityName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer21->Add( m_signAuthorityName, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer81->Add( fgSizer21, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	m_staticText91 = new wxStaticText( m_signCertTab, wxID_ANY, _("Validity"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText91->Wrap( -1 );
	m_staticText91->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText91->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer81->Add( m_staticText91, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer31;
	fgSizer31 = new wxFlexGridSizer( 2, 2, 0, 0 );
	fgSizer31->AddGrowableCol( 1 );
	fgSizer31->SetFlexibleDirection( wxVERTICAL );
	fgSizer31->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText101 = new wxStaticText( m_signCertTab, wxID_ANY, _("From :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText101->Wrap( -1 );
	fgSizer31->Add( m_staticText101, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_signFrom = new wxTextCtrl( m_signCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_signFrom->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer31->Add( m_signFrom, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText111 = new wxStaticText( m_signCertTab, wxID_ANY, _("To: "), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText111->Wrap( -1 );
	fgSizer31->Add( m_staticText111, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_signTo = new wxTextCtrl( m_signCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_signTo->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer31->Add( m_signTo, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer81->Add( fgSizer31, 1, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxBoxSizer* bSizer101;
	bSizer101 = new wxBoxSizer( wxHORIZONTAL );
	
	m_signExportCert = new wxButton( m_signCertTab, wxID_ANY, _("Export Certificate"), wxDefaultPosition, wxDefaultSize, 0 );
	m_signExportCert->Enable( false );
	
	bSizer101->Add( m_signExportCert, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_signChangePin2 = new wxButton( m_signCertTab, wxID_ANY, _("Change PIN2"), wxDefaultPosition, wxDefaultSize, 0 );
	m_signChangePin2->Enable( false );
	
	bSizer101->Add( m_signChangePin2, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_signUnblockPin2 = new wxButton( m_signCertTab, wxID_ANY, _("Unblock PIN2"), wxDefaultPosition, wxDefaultSize, 0 );
	m_signUnblockPin2->Enable( false );
	
	bSizer101->Add( m_signUnblockPin2, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	
	bSizer81->Add( bSizer101, 0, wxALIGN_RIGHT|wxBOTTOM|wxRIGHT, 5 );
	
	
	m_signCertTab->SetSizer( bSizer81 );
	m_signCertTab->Layout();
	bSizer81->Fit( m_signCertTab );
	m_certTabs->AddPage( m_signCertTab, _("Signature Certificate"), false );
	m_cipherCertTab = new wxPanel( m_certTabs, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	m_cipherCertTab->Enable( false );
	
	wxBoxSizer* bSizer82;
	bSizer82 = new wxBoxSizer( wxVERTICAL );
	
	m_staticText14 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Ciphering Certificate"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText14->Wrap( -1 );
	m_staticText14->SetFont( wxFont( 18, 70, 90, 92, false, wxEmptyString ) );
	
	bSizer82->Add( m_staticText14, 0, wxALL|wxEXPAND, 5 );
	
	m_staticText22 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Issued to"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText22->Wrap( -1 );
	m_staticText22->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText22->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer82->Add( m_staticText22, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer12;
	fgSizer12 = new wxFlexGridSizer( 3, 2, 0, 0 );
	fgSizer12->AddGrowableCol( 1 );
	fgSizer12->SetFlexibleDirection( wxVERTICAL );
	fgSizer12->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText42 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("First Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText42->Wrap( -1 );
	fgSizer12->Add( m_staticText42, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_cipherFirstName = new wxTextCtrl( m_cipherCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_cipherFirstName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer12->Add( m_cipherFirstName, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText52 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Last Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText52->Wrap( -1 );
	fgSizer12->Add( m_staticText52, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_cipherLastName = new wxTextCtrl( m_cipherCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_cipherLastName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer12->Add( m_cipherLastName, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText62 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Personal Number :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText62->Wrap( -1 );
	fgSizer12->Add( m_staticText62, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_cipherPersonalNumber = new wxTextCtrl( m_cipherCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_cipherPersonalNumber->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer12->Add( m_cipherPersonalNumber, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer82->Add( fgSizer12, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	m_staticText72 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Issued by"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText72->Wrap( -1 );
	m_staticText72->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText72->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer82->Add( m_staticText72, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer22;
	fgSizer22 = new wxFlexGridSizer( 1, 2, 0, 0 );
	fgSizer22->AddGrowableCol( 1 );
	fgSizer22->SetFlexibleDirection( wxVERTICAL );
	fgSizer22->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText82 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Authority Name :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText82->Wrap( -1 );
	fgSizer22->Add( m_staticText82, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_cipherAuthorityName = new wxTextCtrl( m_cipherCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_cipherAuthorityName->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer22->Add( m_cipherAuthorityName, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer82->Add( fgSizer22, 0, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	m_staticText92 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("Validity"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText92->Wrap( -1 );
	m_staticText92->SetFont( wxFont( 12, 70, 90, 92, false, wxEmptyString ) );
	m_staticText92->SetBackgroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_3DLIGHT ) );
	
	bSizer82->Add( m_staticText92, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxFlexGridSizer* fgSizer32;
	fgSizer32 = new wxFlexGridSizer( 2, 2, 0, 0 );
	fgSizer32->AddGrowableCol( 1 );
	fgSizer32->SetFlexibleDirection( wxVERTICAL );
	fgSizer32->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText102 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("From :"), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText102->Wrap( -1 );
	fgSizer32->Add( m_staticText102, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_cipherFrom = new wxTextCtrl( m_cipherCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_cipherFrom->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer32->Add( m_cipherFrom, 1, wxALL|wxEXPAND, 5 );
	
	m_staticText112 = new wxStaticText( m_cipherCertTab, wxID_ANY, _("To: "), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText112->Wrap( -1 );
	fgSizer32->Add( m_staticText112, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_cipherTo = new wxTextCtrl( m_cipherCertTab, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_READONLY );
	m_cipherTo->SetBackgroundColour( wxColour( 255, 255, 255 ) );
	
	fgSizer32->Add( m_cipherTo, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer82->Add( fgSizer32, 1, wxBOTTOM|wxEXPAND|wxLEFT|wxRIGHT, 10 );
	
	wxBoxSizer* bSizer102;
	bSizer102 = new wxBoxSizer( wxHORIZONTAL );
	
	m_cipherExportCert = new wxButton( m_cipherCertTab, wxID_ANY, _("Export Certificate"), wxDefaultPosition, wxDefaultSize, 0 );
	m_cipherExportCert->Enable( false );
	
	bSizer102->Add( m_cipherExportCert, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_cipherChangePin1 = new wxButton( m_cipherCertTab, wxID_ANY, _("Change PIN1"), wxDefaultPosition, wxDefaultSize, 0 );
	m_cipherChangePin1->Enable( false );
	
	bSizer102->Add( m_cipherChangePin1, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_cipherUnblockPin1 = new wxButton( m_cipherCertTab, wxID_ANY, _("Unblock PIN1"), wxDefaultPosition, wxDefaultSize, 0 );
	m_cipherUnblockPin1->Enable( false );
	
	bSizer102->Add( m_cipherUnblockPin1, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	
	bSizer82->Add( bSizer102, 0, wxALIGN_RIGHT|wxBOTTOM|wxRIGHT, 5 );
	
	
	m_cipherCertTab->SetSizer( bSizer82 );
	m_cipherCertTab->Layout();
	bSizer82->Fit( m_cipherCertTab );
	m_certTabs->AddPage( m_cipherCertTab, _("Ciphering Certificate"), false );
	
	bSizer9->Add( m_certTabs, 1, wxALL|wxEXPAND, 0 );
	
	
	m_panel10->SetSizer( bSizer9 );
	m_panel10->Layout();
	bSizer9->Fit( m_panel10 );
	bSizer7->Add( m_panel10, 1, wxEXPAND | wxALL, 0 );
	
	
	m_InformationPanel->SetSizer( bSizer7 );
	m_InformationPanel->Layout();
	bSizer7->Fit( m_InformationPanel );
	m_mainTabs->AddPage( m_InformationPanel, _("Card Information"), false );
	
	bSizer3->Add( m_mainTabs, 1, wxEXPAND | wxALL, 5 );
	
	
	m_panel3->SetSizer( bSizer3 );
	m_panel3->Layout();
	bSizer3->Fit( m_panel3 );
	bSizer2->Add( m_panel3, 1, wxEXPAND | wxALL, 0 );
	
	
	this->SetSizer( bSizer2 );
	this->Layout();
	m_menubar1 = new wxMenuBar( 0 );
	settings = new wxMenu();
	wxMenuItem* cardReader;
	cardReader = new wxMenuItem( settings, ID_CARD_READER, wxString( _("Card Reader") ) , _("Select your prefered smart card reader"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	cardReader->SetBitmaps( settings_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	cardReader->SetBitmap( settings_png_to_wx_bitmap() );
	#endif
	settings->Append( cardReader );
	
	language = new wxMenu();
	wxMenuItem* English;
	English = new wxMenuItem( language, ID_LANGUAGE_ENGLISH, wxString( _("English") ) , _("Choose English as a display language"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	English->SetBitmaps( us_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	English->SetBitmap( us_png_to_wx_bitmap() );
	#endif
	language->Append( English );
	
	wxMenuItem* Latvian;
	Latvian = new wxMenuItem( language, ID_LANGUAGE_LATVIAN, wxString( _("Latvian") ) , _("Choose Latvian as a display language"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	Latvian->SetBitmaps( lv_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	Latvian->SetBitmap( lv_png_to_wx_bitmap() );
	#endif
	language->Append( Latvian );
	
	settings->Append( -1, _("Language"), language );
	
	settings->AppendSeparator();
	
	wxMenuItem* exit;
	exit = new wxMenuItem( settings, wxID_EXIT, wxString( _("Exit") ) , _("Exit Latvia eID PinTool"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	exit->SetBitmaps( exit_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	exit->SetBitmap( exit_png_to_wx_bitmap() );
	#endif
	settings->Append( exit );
	
	m_menubar1->Append( settings, _("Settings") ); 
	
	help = new wxMenu();
	wxMenuItem* helpContents;
	helpContents = new wxMenuItem( help, ID_HELP_CONTENTS, wxString( _("Help Contents") ) , _("Display help for Latvia eID PinTool"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	helpContents->SetBitmaps( help_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	helpContents->SetBitmap( help_png_to_wx_bitmap() );
	#endif
	help->Append( helpContents );
	
	wxMenuItem* logs;
	logs = new wxMenuItem( help, ID_LOGS, wxString( _("Logs") ) , _("Display logs for Latvia eID PinTool"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	logs->SetBitmaps( logs_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	logs->SetBitmap( logs_png_to_wx_bitmap() );
	#endif
	help->Append( logs );
	
	wxMenuItem* about;
	about = new wxMenuItem( help, wxID_ABOUT, wxString( _("About") ) , _("About Latvia eID PinTool"), wxITEM_NORMAL );
	#ifdef __WXMSW__
	about->SetBitmaps( about_png_to_wx_bitmap() );
	#elif defined( __WXGTK__ )
	about->SetBitmap( about_png_to_wx_bitmap() );
	#endif
	help->Append( about );
	
	m_menubar1->Append( help, _("Help") ); 
	
	this->SetMenuBar( m_menubar1 );
	
	m_statusBar = this->CreateStatusBar( 1, wxST_SIZEGRIP, wxID_ANY );
	
	this->Centre( wxBOTH );
	
	// Connect Events
	m_mainTabs->Connect( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGING, wxNotebookEventHandler( PinToolFrame::HandlePageChanging ), NULL, this );
	m_ConnectReaderButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleConnectToCardReader ), NULL, this );
	m_ConnectReaderButton->Connect( wxEVT_ENTER_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_ConnectReaderButton->Connect( wxEVT_LEAVE_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_HelpButton->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleHelp ), NULL, this );
	m_HelpButton->Connect( wxEVT_ENTER_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_HelpButton->Connect( wxEVT_LEAVE_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_authExportCert->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleExportAuthCert ), NULL, this );
	m_authChangePin1->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleChangePin1 ), NULL, this );
	m_authUnblockPin1->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleUnblockPin1 ), NULL, this );
	m_signExportCert->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleExportSignCert ), NULL, this );
	m_signChangePin2->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleChangePin2 ), NULL, this );
	m_signUnblockPin2->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleUnblockPin2 ), NULL, this );
	m_cipherExportCert->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleExportCipherCert ), NULL, this );
	m_cipherChangePin1->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleChangePin1 ), NULL, this );
	m_cipherUnblockPin1->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleUnblockPin1 ), NULL, this );
	this->Connect( cardReader->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuCardReader ) );
	this->Connect( English->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuSelectEnglish ) );
	this->Connect( Latvian->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuSelectLatvia ) );
	this->Connect( exit->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::handleMenuExit ) );
	this->Connect( helpContents->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuHelp ) );
	this->Connect( logs->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuLogs ) );
	this->Connect( about->GetId(), wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuAbout ) );
}

PinToolFrame::~PinToolFrame()
{
	// Disconnect Events
	m_mainTabs->Disconnect( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGING, wxNotebookEventHandler( PinToolFrame::HandlePageChanging ), NULL, this );
	m_ConnectReaderButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleConnectToCardReader ), NULL, this );
	m_ConnectReaderButton->Disconnect( wxEVT_ENTER_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_ConnectReaderButton->Disconnect( wxEVT_LEAVE_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_HelpButton->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleHelp ), NULL, this );
	m_HelpButton->Disconnect( wxEVT_ENTER_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_HelpButton->Disconnect( wxEVT_LEAVE_WINDOW, wxMouseEventHandler( PinToolFrame::HandleMouseEvent ), NULL, this );
	m_authExportCert->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleExportAuthCert ), NULL, this );
	m_authChangePin1->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleChangePin1 ), NULL, this );
	m_authUnblockPin1->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleUnblockPin1 ), NULL, this );
	m_signExportCert->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleExportSignCert ), NULL, this );
	m_signChangePin2->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleChangePin2 ), NULL, this );
	m_signUnblockPin2->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleUnblockPin2 ), NULL, this );
	m_cipherExportCert->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleExportCipherCert ), NULL, this );
	m_cipherChangePin1->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleChangePin1 ), NULL, this );
	m_cipherUnblockPin1->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( PinToolFrame::HandleUnblockPin1 ), NULL, this );
	this->Disconnect( ID_CARD_READER, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuCardReader ) );
	this->Disconnect( ID_LANGUAGE_ENGLISH, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuSelectEnglish ) );
	this->Disconnect( ID_LANGUAGE_LATVIAN, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuSelectLatvia ) );
	this->Disconnect( wxID_EXIT, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::handleMenuExit ) );
	this->Disconnect( ID_HELP_CONTENTS, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuHelp ) );
	this->Disconnect( ID_LOGS, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuLogs ) );
	this->Disconnect( wxID_ABOUT, wxEVT_COMMAND_MENU_SELECTED, wxCommandEventHandler( PinToolFrame::HandleMenuAbout ) );
	
}

ReaderSelectionDlg::ReaderSelectionDlg( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( 450,120 ), wxDefaultSize );
	
	wxBoxSizer* bSizer12;
	bSizer12 = new wxBoxSizer( wxVERTICAL );
	
	wxFlexGridSizer* fgSizer13;
	fgSizer13 = new wxFlexGridSizer( 1, 2, 0, 0 );
	fgSizer13->AddGrowableCol( 1 );
	fgSizer13->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer13->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_staticText31 = new wxStaticText( this, wxID_ANY, _("Reader Name : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_staticText31->Wrap( -1 );
	fgSizer13->Add( m_staticText31, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_readersList = new wxComboBox( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0, NULL, wxCB_DROPDOWN|wxCB_READONLY ); 
	fgSizer13->Add( m_readersList, 0, wxALL|wxEXPAND, 5 );
	
	
	bSizer12->Add( fgSizer13, 0, wxALL|wxEXPAND, 5 );
	
	m_buttonsSizer = new wxStdDialogButtonSizer();
	m_buttonsSizerOK = new wxButton( this, wxID_OK );
	m_buttonsSizer->AddButton( m_buttonsSizerOK );
	m_buttonsSizerCancel = new wxButton( this, wxID_CANCEL );
	m_buttonsSizer->AddButton( m_buttonsSizerCancel );
	m_buttonsSizer->Realize();
	
	bSizer12->Add( m_buttonsSizer, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( bSizer12 );
	this->Layout();
	
	this->Centre( wxBOTH );
	
	// Connect Events
	m_buttonsSizerOK->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ReaderSelectionDlg::HandleOkButton ), NULL, this );
}

ReaderSelectionDlg::~ReaderSelectionDlg()
{
	// Disconnect Events
	m_buttonsSizerOK->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ReaderSelectionDlg::HandleOkButton ), NULL, this );
	
}

ChangePinDlg::ChangePinDlg( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );
	
	wxBoxSizer* bSizer14;
	bSizer14 = new wxBoxSizer( wxVERTICAL );
	
	wxFlexGridSizer* fgSizer10;
	fgSizer10 = new wxFlexGridSizer( 4, 2, 0, 0 );
	fgSizer10->AddGrowableCol( 1 );
	fgSizer10->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer10->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_currentPinlabel = new wxStaticText( this, wxID_ANY, _("Current PIN1 : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_currentPinlabel->Wrap( -1 );
	fgSizer10->Add( m_currentPinlabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_currentPin = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_currentPin->SetMaxLength( 64 ); 
	fgSizer10->Add( m_currentPin, 0, wxALL|wxEXPAND, 5 );
	
	m_newPinLabel = new wxStaticText( this, wxID_ANY, _("New PIN1 : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_newPinLabel->Wrap( -1 );
	fgSizer10->Add( m_newPinLabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_newPin = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_newPin->SetMaxLength( 64 ); 
	fgSizer10->Add( m_newPin, 0, wxALL|wxEXPAND, 5 );
	
	m_confirmNewPinLabel = new wxStaticText( this, wxID_ANY, _("Confirm New PIN1 : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_confirmNewPinLabel->Wrap( -1 );
	fgSizer10->Add( m_confirmNewPinLabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_confirmNewPin = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_confirmNewPin->SetMaxLength( 64 ); 
	fgSizer10->Add( m_confirmNewPin, 0, wxALL|wxEXPAND, 5 );
	
	m_triesLeftLabel = new wxStaticText( this, wxID_ANY, _("%s Tries Left = %d"), wxDefaultPosition, wxDefaultSize, 0 );
	m_triesLeftLabel->Wrap( -1 );
	fgSizer10->Add( m_triesLeftLabel, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_panel8 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	fgSizer10->Add( m_panel8, 1, wxEXPAND | wxALL, 5 );
	
	
	bSizer14->Add( fgSizer10, 1, wxALL|wxEXPAND, 5 );
	
	m_buttonsSizer = new wxStdDialogButtonSizer();
	m_buttonsSizerOK = new wxButton( this, wxID_OK );
	m_buttonsSizer->AddButton( m_buttonsSizerOK );
	m_buttonsSizerCancel = new wxButton( this, wxID_CANCEL );
	m_buttonsSizer->AddButton( m_buttonsSizerCancel );
	m_buttonsSizer->Realize();
	
	bSizer14->Add( m_buttonsSizer, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( bSizer14 );
	this->Layout();
	
	this->Centre( wxBOTH );
	
	// Connect Events
	m_currentPin->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( ChangePinDlg::HandleTextChange ), NULL, this );
	m_newPin->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( ChangePinDlg::HandleTextChange ), NULL, this );
	m_confirmNewPin->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( ChangePinDlg::HandleTextChange ), NULL, this );
	m_buttonsSizerOK->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ChangePinDlg::HandleOkButton ), NULL, this );
}

ChangePinDlg::~ChangePinDlg()
{
	// Disconnect Events
	m_currentPin->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( ChangePinDlg::HandleTextChange ), NULL, this );
	m_newPin->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( ChangePinDlg::HandleTextChange ), NULL, this );
	m_confirmNewPin->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( ChangePinDlg::HandleTextChange ), NULL, this );
	m_buttonsSizerOK->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( ChangePinDlg::HandleOkButton ), NULL, this );
	
}

UnblockPinDlg::UnblockPinDlg( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( 346,210 ), wxDefaultSize );
	
	wxBoxSizer* bSizer14;
	bSizer14 = new wxBoxSizer( wxVERTICAL );
	
	wxFlexGridSizer* fgSizer10;
	fgSizer10 = new wxFlexGridSizer( 4, 2, 0, 0 );
	fgSizer10->AddGrowableCol( 1 );
	fgSizer10->SetFlexibleDirection( wxHORIZONTAL );
	fgSizer10->SetNonFlexibleGrowMode( wxFLEX_GROWMODE_SPECIFIED );
	
	m_puklabel = new wxStaticText( this, wxID_ANY, _("PUK : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_puklabel->Wrap( -1 );
	fgSizer10->Add( m_puklabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_puk = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_puk->SetMaxLength( 64 ); 
	fgSizer10->Add( m_puk, 0, wxALL|wxEXPAND, 5 );
	
	m_newPinLabel = new wxStaticText( this, wxID_ANY, _("New PIN1 : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_newPinLabel->Wrap( -1 );
	fgSizer10->Add( m_newPinLabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_newPin = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_newPin->SetMaxLength( 64 ); 
	fgSizer10->Add( m_newPin, 0, wxALL|wxEXPAND, 5 );
	
	m_confirmNewPinLabel = new wxStaticText( this, wxID_ANY, _("Confirm New PIN1 : "), wxDefaultPosition, wxDefaultSize, 0 );
	m_confirmNewPinLabel->Wrap( -1 );
	fgSizer10->Add( m_confirmNewPinLabel, 0, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_confirmNewPin = new wxTextCtrl( this, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD );
	m_confirmNewPin->SetMaxLength( 64 ); 
	fgSizer10->Add( m_confirmNewPin, 0, wxALL|wxEXPAND, 5 );
	
	m_triesLeftLabel = new wxStaticText( this, wxID_ANY, _("PUK Tries Left = %d"), wxDefaultPosition, wxDefaultSize, 0 );
	m_triesLeftLabel->Wrap( -1 );
	fgSizer10->Add( m_triesLeftLabel, 0, wxALIGN_BOTTOM|wxALL, 5 );
	
	m_panel9 = new wxPanel( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxTAB_TRAVERSAL );
	fgSizer10->Add( m_panel9, 1, wxEXPAND | wxALL, 5 );
	
	
	bSizer14->Add( fgSizer10, 1, wxALL|wxEXPAND, 5 );
	
	m_buttonsSizer = new wxStdDialogButtonSizer();
	m_buttonsSizerOK = new wxButton( this, wxID_OK );
	m_buttonsSizer->AddButton( m_buttonsSizerOK );
	m_buttonsSizerCancel = new wxButton( this, wxID_CANCEL );
	m_buttonsSizer->AddButton( m_buttonsSizerCancel );
	m_buttonsSizer->Realize();
	
	bSizer14->Add( m_buttonsSizer, 0, wxALL|wxEXPAND, 5 );
	
	
	this->SetSizer( bSizer14 );
	this->Layout();
	
	this->Centre( wxBOTH );
	
	// Connect Events
	m_puk->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( UnblockPinDlg::HandleTextChange ), NULL, this );
	m_newPin->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( UnblockPinDlg::HandleTextChange ), NULL, this );
	m_confirmNewPin->Connect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( UnblockPinDlg::HandleTextChange ), NULL, this );
	m_buttonsSizerOK->Connect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( UnblockPinDlg::HandleOkButton ), NULL, this );
}

UnblockPinDlg::~UnblockPinDlg()
{
	// Disconnect Events
	m_puk->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( UnblockPinDlg::HandleTextChange ), NULL, this );
	m_newPin->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( UnblockPinDlg::HandleTextChange ), NULL, this );
	m_confirmNewPin->Disconnect( wxEVT_COMMAND_TEXT_UPDATED, wxCommandEventHandler( UnblockPinDlg::HandleTextChange ), NULL, this );
	m_buttonsSizerOK->Disconnect( wxEVT_COMMAND_BUTTON_CLICKED, wxCommandEventHandler( UnblockPinDlg::HandleOkButton ), NULL, this );
	
}

PinToolAboutDlg::PinToolAboutDlg( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( -1,-1 ), wxDefaultSize );
	
	wxBoxSizer* bSizer15;
	bSizer15 = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* bSizer16;
	bSizer16 = new wxBoxSizer( wxHORIZONTAL );
	
	m_bitmap2 = new wxStaticBitmap( this, wxID_ANY, pintool_ico_to_wx_bitmap(), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer16->Add( m_bitmap2, 0, wxALL, 5 );
	
	m_staticText40 = new wxStaticText( this, wxID_ANY, _("PinTool 1.1"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTRE );
	m_staticText40->Wrap( -1 );
	m_staticText40->SetFont( wxFont( 14, 70, 90, 92, false, wxEmptyString ) );
	
	bSizer16->Add( m_staticText40, 1, wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	
	bSizer15->Add( bSizer16, 0, wxEXPAND, 5 );
	
	m_staticText41 = new wxStaticText( this, wxID_ANY, _("(c) 2012"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTRE );
	m_staticText41->Wrap( -1 );
	bSizer15->Add( m_staticText41, 0, wxALIGN_CENTER|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_staticText42 = new wxStaticText( this, wxID_ANY, _("PinTool for Latvia eID Middleware"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTRE );
	m_staticText42->Wrap( -1 );
	bSizer15->Add( m_staticText42, 0, wxALIGN_CENTER|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_hyperlink1 = new wxHyperlinkCtrl( this, wxID_ANY, _("http://www.pmlp.gov.lv/en/"), wxT("http://www.pmlp.gov.lv/en/"), wxDefaultPosition, wxDefaultSize, wxHL_DEFAULT_STYLE );
	bSizer15->Add( m_hyperlink1, 0, wxALIGN_CENTER|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	m_hyperlink3 = new wxHyperlinkCtrl( this, wxID_ANY, _("Version History"), wxT("CHANGES.txt"), wxDefaultPosition, wxDefaultSize, wxHL_ALIGN_CENTRE|wxNO_BORDER );
	bSizer15->Add( m_hyperlink3, 0, wxALIGN_CENTER|wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5 );
	
	wxBoxSizer* bSizer21;
	bSizer21 = new wxBoxSizer( wxVERTICAL );
	
	m_developerPanel = new wxCollapsiblePane(this, wxID_ANY, _("Developers"));
	wxWindow *win = m_developerPanel->GetPane();
	wxSizer *paneSz = new wxBoxSizer(wxVERTICAL);
	paneSz->Add(new wxStaticBitmap( win, wxID_ANY, oberthur_png_to_wx_bitmap(), wxDefaultPosition, wxDefaultSize, 0 ), 1, wxGROW|wxALL, 2);
	win->SetSizer(paneSz);
	paneSz->SetSizeHints(win);
	bSizer21->Add( m_developerPanel, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer15->Add( bSizer21, 0, wxEXPAND, 5 );
	
	m_sdbSizer4 = new wxStdDialogButtonSizer();
	m_sdbSizer4OK = new wxButton( this, wxID_OK );
	m_sdbSizer4->AddButton( m_sdbSizer4OK );
	m_sdbSizer4->Realize();
	
	bSizer15->Add( m_sdbSizer4, 0, wxALIGN_RIGHT|wxALL, 5 );
	
	
	this->SetSizer( bSizer15 );
	this->Layout();
	bSizer15->Fit( this );
	
	this->Centre( wxBOTH );
	
	// Connect Events
	m_hyperlink1->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( PinToolAboutDlg::HandleLinkClick ), NULL, this );
	m_hyperlink3->Connect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( PinToolAboutDlg::handleChangeLog ), NULL, this );
}

PinToolAboutDlg::~PinToolAboutDlg()
{
	// Disconnect Events
	m_hyperlink1->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( PinToolAboutDlg::HandleLinkClick ), NULL, this );
	m_hyperlink3->Disconnect( wxEVT_COMMAND_HYPERLINK, wxHyperlinkEventHandler( PinToolAboutDlg::handleChangeLog ), NULL, this );
	
}

ChangePinPadDlg::ChangePinPadDlg( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( 455,132 ), wxDefaultSize );
	
	wxBoxSizer* bSizer18;
	bSizer18 = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* bSizer19;
	bSizer19 = new wxBoxSizer( wxHORIZONTAL );
	
	m_bitmap4 = new wxStaticBitmap( this, wxID_ANY, pinpad_png_to_wx_bitmap(), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer19->Add( m_bitmap4, 0, wxALL, 5 );
	
	m_description = new wxStaticText( this, wxID_ANY, _("Please type the current PIN1 and the new PIN1 twice using the pinpad"), wxDefaultPosition, wxDefaultSize, 0 );
	m_description->Wrap( -1 );
	bSizer19->Add( m_description, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer18->Add( bSizer19, 1, wxALL|wxEXPAND, 5 );
	
	m_triesLeftLabel = new wxStaticText( this, wxID_ANY, _("%s Tries Left = %d"), wxDefaultPosition, wxDefaultSize, 0 );
	m_triesLeftLabel->Wrap( -1 );
	bSizer18->Add( m_triesLeftLabel, 0, wxALIGN_BOTTOM|wxALL|wxEXPAND, 10 );
	
	
	this->SetSizer( bSizer18 );
	this->Layout();
	
	this->Centre( wxBOTH );
	
	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( ChangePinPadDlg::handleOnClose ) );
}

ChangePinPadDlg::~ChangePinPadDlg()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( ChangePinPadDlg::handleOnClose ) );
	
}

UnblockPinPadDlg::UnblockPinPadDlg( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxDialog( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxSize( 455,132 ), wxDefaultSize );
	
	wxBoxSizer* bSizer19;
	bSizer19 = new wxBoxSizer( wxVERTICAL );
	
	wxBoxSizer* bSizer20;
	bSizer20 = new wxBoxSizer( wxHORIZONTAL );
	
	m_bitmap4 = new wxStaticBitmap( this, wxID_ANY, pinpad_png_to_wx_bitmap(), wxDefaultPosition, wxDefaultSize, 0 );
	bSizer20->Add( m_bitmap4, 0, wxALL, 5 );
	
	m_description = new wxStaticText( this, wxID_ANY, _("Please type the PUK and the new PIN1 twice using the pinpad"), wxDefaultPosition, wxDefaultSize, 0 );
	m_description->Wrap( -1 );
	bSizer20->Add( m_description, 1, wxALL|wxEXPAND, 5 );
	
	
	bSizer19->Add( bSizer20, 1, wxALL|wxEXPAND, 5 );
	
	m_triesLeftLabel = new wxStaticText( this, wxID_ANY, _("PUK Tries Left = %d"), wxDefaultPosition, wxDefaultSize, 0 );
	m_triesLeftLabel->Wrap( -1 );
	bSizer19->Add( m_triesLeftLabel, 0, wxALIGN_BOTTOM|wxALL|wxEXPAND, 10 );
	
	
	this->SetSizer( bSizer19 );
	this->Layout();
	
	this->Centre( wxBOTH );
	
	// Connect Events
	this->Connect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( UnblockPinPadDlg::handleOnClose ) );
}

UnblockPinPadDlg::~UnblockPinPadDlg()
{
	// Disconnect Events
	this->Disconnect( wxEVT_CLOSE_WINDOW, wxCloseEventHandler( UnblockPinPadDlg::handleOnClose ) );
	
}
