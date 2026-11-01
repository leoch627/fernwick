Unicode True
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
Name "@PRODUCT_NAME@"
OutFile "@OUTPUT@"
InstallDir "$PROGRAMFILES64\@PRODUCT_NAME@"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
VIProductVersion "@NUMERIC_VERSION@"
VIAddVersionKey /LANG=1033 "ProductName" "@PRODUCT_NAME@"
VIAddVersionKey /LANG=1033 "FileDescription" "@PRODUCT_NAME@ installer"
VIAddVersionKey /LANG=1033 "FileVersion" "@VERSION@"
VIAddVersionKey /LANG=1033 "LegalCopyright" "@PRODUCT_NAME@"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This application requires 64-bit Windows 11."
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin11}
    MessageBox MB_ICONSTOP "This application requires Windows 11 or later."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd
Section "Install"
  SetOutPath "$INSTDIR"
  File /r "@STAGE@\*"
  nsExec::ExecToStack '"$INSTDIR\resources\native\win32-x64\helper.exe" install --app "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP "Network service installation failed. Repair the installation before using @PRODUCT_NAME@." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\@PRODUCT_NAME@"
  CreateShortcut "$SMPROGRAMS\@PRODUCT_NAME@\@PRODUCT_NAME@.lnk" "$INSTDIR\@EXE_NAME@"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "DisplayName" "@PRODUCT_NAME@"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "DisplayVersion" "@VERSION@"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@" "NoRepair" 1
SectionEnd
Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd
Section "Uninstall"
  nsExec::ExecToStack '"$PROGRAMFILES64\@PRODUCT_ID@-service\helper.exe" uninstall'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP "Network recovery did not complete. Repair @PRODUCT_NAME@ before uninstalling." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  Delete "$INSTDIR\@EXE_NAME@"
  RMDir /r "$INSTDIR\resources"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  RMDir /r "$SMPROGRAMS\@PRODUCT_NAME@"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@"
SectionEnd
