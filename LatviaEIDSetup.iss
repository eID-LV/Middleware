[Files]
Source: "SignedCSP\32Bit\OTLvCSP.dll"; DestDir: "{sys}"; Flags: ignoreversion 32bit regserver overwritereadonly restartreplace uninsrestartdelete replacesameversion
Source: "SignedCSP\64bit\OTLvCSP.dll"; DestDir: "{sys}"; Flags: ignoreversion 64bit regserver overwritereadonly restartreplace uninsrestartdelete replacesameversion; Check: IsWin64
Source: "bin\Win32\OTLvCSPCore.dll"; DestDir: "{sys}"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsrestartdelete replacesameversion
Source: "bin\x64\OTLvCSPCore.dll"; DestDir: "{sys}"; Flags: ignoreversion 64bit overwritereadonly restartreplace uninsrestartdelete replacesameversion; Check: IsWin64
Source: "bin\Win32\OTLvP11.dll"; DestDir: "{sys}"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsrestartdelete replacesameversion
Source: "bin\x64\OTLvP11.dll"; DestDir: "{sys}"; Flags: ignoreversion 64bit overwritereadonly restartreplace uninsrestartdelete replacesameversion; Check: IsWin64
Source: "bin\Win32\OTLvCertProp.exe"; DestDir: "{win}"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsrestartdelete replacesameversion
Source: "latvia-eid.conf"; DestDir: "{commonappdata}\Latvia eID Middleware"; Flags: ignoreversion overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete replacesameversion
Source: "bin\Win32\PinTool.exe"; DestDir: "{app}"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete
Source: "CHANGES.txt"; DestDir: "{app}"; Flags: ignoreversion 32bit overwritereadonly uninsremovereadonly uninsrestartdelete
Source: "PinTool\pintool.mo"; DestDir: "{app}\Languages\lv"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete
Source: "PinTool\wx.mo"; DestDir: "{app}\Languages\lv"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete
Source: "PinTool\help\en\*.*"; DestDir: "{app}\help\en"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete
Source: "PinTool\help\en\contents\*.*"; DestDir: "{app}\help\en\contents"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete
Source: "PinTool\help\lv\*.*"; DestDir: "{app}\help\lv"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete
Source: "PinTool\help\lv\contents\*.*"; DestDir: "{app}\help\lv\contents"; Flags: ignoreversion 32bit overwritereadonly restartreplace uninsremovereadonly uninsrestartdelete

[Languages]
Name: Latvian; MessagesFile: Latvian.isl; 

[Setup]
AppName=Latvia eID Middleware
AppVersion= 1.1.0
OutputBaseFilename=LatviaEIDSetup
SolidCompression=true
ShowLanguageDialog=no
MinVersion=0,5.01
ArchitecturesAllowed=x86 x64
VersionInfoVersion=1.1.0
VersionInfoCompany=Oberthur Technologies
VersionInfoDescription=Latvia eID Middleware
VersionInfoProductName=Latvia eID Middleware
OutputDir=bin
VersionInfoCopyright=Copyright (C) 2012 Oberthur Technologies
VersionInfoTextVersion=1.1.0
AppCopyright=Copyright (C) 2012 Oberthur Technologies
ArchitecturesInstallIn64BitMode=x64
SetupIconFile=logo.ico
UninstallDisplayIcon={app}\PinTool.exe
UninstallRestartComputer=True
DefaultDirName={pf32}\Latvia eID Middleware
DefaultGroupName=Latvia eID Middleware
WizardSmallImageFile=SmallLogo.bmp
DisableProgramGroupPage=yes
WizardImageFile=compiler:WizModernImage-IS.bmp

[Registry]
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: none; Flags: uninsdeletekey
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: string; ValueName: "Crypto Provider"; ValueData: "Oberthur LATVIA-EID CSP"; Flags: uninsclearvalue
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: binary; ValueName: "ATR"; ValueData: "3b dd 18 00 81 31 fe 45 90 4c 41 54 56 49 41 2d 65 49 44 90 00 8c"; Flags: uninsclearvalue
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: binary; ValueName: "ATRMask"; ValueData: "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"; Flags: uninsclearvalue

Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "LatviaEIDCertificatePropagation"; ValueData: "OTLvCertProp.exe"; Flags: deletevalue uninsdeletevalue

Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: none; Flags: uninsdeletekey; Check: IsWin64
Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: string; ValueName: "Crypto Provider"; ValueData: "Oberthur LATVIA-EID CSP"; Flags: uninsclearvalue; Check: IsWin64
Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: binary; ValueName: "ATR"; ValueData: "3b dd 18 00 81 31 fe 45 90 4c 41 54 56 49 41 2d 65 49 44 90 00 8c"; Flags: uninsclearvalue; Check: IsWin64
Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID"; ValueType: binary; ValueName: "ATRMask"; ValueData: "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"; Flags: uninsclearvalue; Check: IsWin64

Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: none; Flags: uninsdeletekey
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: string; ValueName: "Crypto Provider"; ValueData: "Oberthur LATVIA-EID CSP"; Flags: uninsclearvalue
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: binary; ValueName: "ATR"; ValueData: "3B DD 18 00 81 31 FE 45 80 F9 A0 00 00 00 77 01 08 00 07 90 00 FE"; Flags: uninsclearvalue
Root: "HKLM32"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: binary; ValueName: "ATRMask"; ValueData: "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"; Flags: uninsclearvalue

Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: none; Flags: uninsdeletekey; Check: IsWin64
Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: string; ValueName: "Crypto Provider"; ValueData: "Oberthur LATVIA-EID CSP"; Flags: uninsclearvalue; Check: IsWin64
Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: binary; ValueName: "ATR"; ValueData: "3B DD 18 00 81 31 FE 45 80 F9 A0 00 00 00 77 01 08 00 07 90 00 FE"; Flags: uninsclearvalue; Check: IsWin64
Root: "HKLM64"; Subkey: "SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\Oberthur LATVIA-EID 2"; ValueType: binary; ValueName: "ATRMask"; ValueData: "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"; Flags: uninsclearvalue; Check: IsWin64



Root: "HKLM32"; Subkey: "Software\\LATVIA eID\\OpenSC"; ValueType: string; ValueName: "ConfigFile"; ValueData: "{commonappdata}\Latvia eID Middleware\latvia-eid.conf"; Flags: deletevalue uninsdeletekey
Root: "HKLM64"; Subkey: "Software\\LATVIA eID\\OpenSC"; ValueType: string; ValueName: "ConfigFile"; ValueData: "{commonappdata}\Latvia eID Middleware\latvia-eid.conf"; Flags: deletevalue uninsdeletekey; Check: IsWin64
Root: "HKLM"; Subkey: "SOFTWARE\Policies\Microsoft\Windows\CertProp"; ValueType: dword; ValueName: "CertPropEnabled"; ValueData: "0"; Flags: noerror uninsdeletekeyifempty uninsdeletevalue; MinVersion: 0,6.0
Root: HKLM; SubKey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\ScCertProp"; ValueType: none; Flags: DontCreateKey;
Root: HKLM; SubKey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\ScCertProp"; ValueType: dword; ValueName: Enabled; ValueData: 0; Flags: NoError;


[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Icons]
Name: "{group}\Latvia eID PinTool"; Filename: "{app}\PinTool.exe"
Name: "{group}\{cm:UninstallProgram,Latvia eID Middleware}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Latvia eID PinTool"; Filename: "{app}\PinTool.exe"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\Latvia eID PinTool"; Filename: "{app}\PinTool.exe"; Tasks: quicklaunchicon



[Run]
Filename: "{win}\OTLvCertProp.exe"; Flags: nowait runasoriginaluser 32bit

[UninstallDelete]
Type: filesandordirs; Name: "{app}\Languages"
Type: filesandordirs; Name: "{app}\help"