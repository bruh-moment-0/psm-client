#define PSMVersion "2.2.0"
#define InstallerVersion "1.0.0"

[Setup]
AppName=PSM Installer
AppVersion={#InstallerVersion}
DefaultDirName={pf}\PSM
OutputDir=.
OutputBaseFilename=PSMInstaller
Compression=lzma
SolidCompression=yes
LicenseFile=license.txt
DefaultGroupName=Private Safe Messaging

[Files]
Source: "python-3.10.11-amd64.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall
Source: "Git.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall
Source: "cmake.msi"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall
Source: "vs_BuildTools.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall
Source: "psm.zip"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall
Source: "icon.ico"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall

[Dirs]
Name: "{app}"; Flags: uninsneveruninstall

[Icons]
Name: "{commondesktop}\Private Safe Messaging Ver {#PSMVersion}"; Filename: "{app}\psm-{#PSMVersion}\psm\main.py"; IconFilename: "{tmp}\icon.ico"; WorkingDir: "{app}\psm-{#PSMVersion}\psm"
Name: "{group}\Private Safe Messaging Ver {#PSMVersion}"; Filename: "{app}\psm-{#PSMVersion}\psm\main.py"; IconFilename: "{tmp}\icon.ico"; WorkingDir: "{app}\psm-{#PSMVersion}\psm"

[Run]
Filename: "{tmp}\python-3.10.11-amd64.exe"; Parameters: "/quiet InstallAllUsers=1 PrependPath=1"; StatusMsg: "Installing Python 3.10.11..."; Flags: runhidden
Filename: "{tmp}\Git.exe"; Parameters: "/VERYSILENT /NORESTART"; StatusMsg: "Installing Git..."; Flags: runhidden
Filename: "msiexec.exe"; Parameters: "/i ""{tmp}\cmake.msi"" /quiet"; StatusMsg: "Installing CMake..."; Flags: runhidden
Filename: "{tmp}\vs_BuildTools.exe"; Parameters: "--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"; StatusMsg: "Installing Visual Studio Build Tools..."; Flags: runhidden
Filename: "cmd.exe"; Parameters: "/c set PATH=%PATH% && git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python && cd liboqs-python && pip install ."; StatusMsg: "Cloning and installing liboqs-python..."; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-Command ""Expand-Archive -Path '{tmp}\psm.zip' -DestinationPath '{app}\psm-{#PSMVersion}' -Force"""; StatusMsg: "Unzipping PSM..."; Flags: runhidden

[Code]
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  if CurPageID = wpLicense then
  begin
    MsgBox('Please ensure you have uninstalled any Python versions before proceeding. If you have any other version, exit the installer and run it again after removing any Python version. A restart may be required after installation. Click OK to continue.', mbInformation, MB_OK);
    Result := True;
  end
  else
    Result := True;
end;