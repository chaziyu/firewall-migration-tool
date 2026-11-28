; Inno Setup script for Firewall Migration Tool
; Builds a per-user (or optional all-users) Windows installer from the PyInstaller --onedir output.

#ifndef AppVersion
  #define AppVersion "0.2.7"
#endif

#define AppName "Firewall Migration Tool"
#define AppPublisher "Firewall Migration Tool"
#define AppExeName "FirewallMigrationTool.exe"

[Setup]
; Stable GUID so newer installers upgrade the existing installation in-place.
AppId={{8F6A2E54-9C1D-4E7A-B3C2-5A4D7E9F1B02}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
DisableProgramGroupPage=yes
; Allow standard users to install to %LocalAppData%\Programs without admin rights,
; while still offering an "All users" choice when elevated.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
CloseApplicationsFilter={#AppExeName}
RestartApplications=no
OutputDir=..\..\dist
OutputBaseFilename=FirewallMigrationTool-Setup-{#AppVersion}
SetupIconFile=..\..\scripts\assets\app.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Remove stale PyInstaller _internal files before installing an updated version.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\..\dist\FirewallMigrationTool\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
