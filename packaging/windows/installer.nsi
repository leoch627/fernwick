Unicode True
ManifestDPIAware true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
Name "@PRODUCT_NAME@"
OutFile "@OUTPUT@"
InstallDir "$PROGRAMFILES64\@PRODUCT_NAME@"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails nevershow
ShowUninstDetails nevershow
BrandingText "@PRODUCT_NAME@ @VERSION@"
VIProductVersion "@NUMERIC_VERSION@"
VIAddVersionKey /LANG=1033 "ProductName" "@PRODUCT_NAME@"
VIAddVersionKey /LANG=1033 "FileDescription" "@PRODUCT_NAME@ installer"
VIAddVersionKey /LANG=1033 "FileVersion" "@VERSION@"
VIAddVersionKey /LANG=1033 "LegalCopyright" "@PRODUCT_NAME@"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\@APP_ID@"
!define WEBVIEW2_CLIENT "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "安装 @PRODUCT_NAME@"
!define MUI_WELCOMEPAGE_TEXT "将在这台电脑上安装 @PRODUCT_NAME@ @VERSION@。$\r$\n$\r$\n安装会同时配置网络服务，以后的版本在客户端内一键更新，不用再下载安装包。$\r$\n$\r$\n点击“下一步”继续。"
; Interactive installs end by starting the app as the signed-in user; the updater starts
; it itself after a silent install.
!define MUI_FINISHPAGE_TITLE "@PRODUCT_NAME@ 已安装"
!define MUI_FINISHPAGE_TEXT "桌面和开始菜单已添加快捷方式。"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "立即打开 @PRODUCT_NAME@"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApplication
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "@PRODUCT_NAME@ 需要 64 位 Windows 10 或更高版本。" /SD IDOK
    Abort
  ${EndIf}
  ; Windows 10 1809 (build 17763) or later, Windows 11 included.
  ${IfNot} ${AtLeastWin10}
  ${OrIfNot} ${AtLeastBuild} 17763
    MessageBox MB_ICONSTOP "@PRODUCT_NAME@ 需要 Windows 10 1809 或更高版本，请先更新系统。" /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  ; A silent install comes from the in-app updater, which has already closed the app.
  ${IfNot} ${Silent}
    Call EnsureApplicationClosed
  ${EndIf}
FunctionEnd

Function EnsureApplicationClosed
  retry:
  nsExec::ExecToStack '"$SYSDIR\cmd.exe" /c "$SYSDIR\tasklist.exe /FI "IMAGENAME eq @EXE_NAME@" /NH | $SYSDIR\find.exe /I "@EXE_NAME@""'
  Pop $0
  Pop $1
  ${If} $0 == 0
    MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "@PRODUCT_NAME@ 正在运行。请在任务栏右下角的图标菜单中选择“退出”，然后点“重试”。" IDRETRY retry
    Abort
  ${EndIf}
FunctionEnd

; The app is a WebView2 application. Windows 11 and up-to-date Windows 10 include the
; runtime; an older Windows 10 is pointed at Microsoft's installer.
Function CheckWebView2
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\${WEBVIEW2_CLIENT}" "pv"
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2_CLIENT}" "pv"
  ${EndIf}
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    ReadRegStr $0 HKCU "Software\Microsoft\EdgeUpdate\Clients\${WEBVIEW2_CLIENT}" "pv"
  ${EndIf}
  ${If} $0 == ""
  ${OrIf} $0 == "0.0.0.0"
    MessageBox MB_YESNO|MB_ICONINFORMATION "这台电脑缺少 Microsoft Edge WebView2 运行库，@PRODUCT_NAME@ 需要它才能显示界面。$\r$\n$\r$\n现在打开微软官方下载？安装运行库后即可正常使用。" /SD IDNO IDNO done
    ExecShell "open" "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
  ${EndIf}
  done:
FunctionEnd

; Started through Explorer so the app runs as the user, not with the installer's
; administrator rights.
Function LaunchApplication
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\@EXE_NAME@"'
FunctionEnd

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "@STAGE@\*"
  nsExec::ExecToStack '"$INSTDIR\resources\native\win32-x64\helper.exe" install --app "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "$1"
    MessageBox MB_ICONSTOP "网络服务安装失败。请重新运行安装程序，或在客户端设置中点“修复网络组件”。" /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\@PRODUCT_NAME@"
  CreateShortcut "$SMPROGRAMS\@PRODUCT_NAME@\@PRODUCT_NAME@.lnk" "$INSTDIR\@EXE_NAME@"
  ; The desktop shortcut is made once; an update keeps it, or keeps it deleted.
  ReadRegDWORD $2 HKLM "${UNINSTALL_KEY}" "DesktopShortcut"
  ${If} $2 != 1
  ${OrIfNot} ${Silent}
  ${OrIf} ${FileExists} "$DESKTOP\@PRODUCT_NAME@.lnk"
    CreateShortcut "$DESKTOP\@PRODUCT_NAME@.lnk" "$INSTDIR\@EXE_NAME@"
  ${EndIf}
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "@PRODUCT_NAME@"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" '"$INSTDIR\@EXE_NAME@",0'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "@PRODUCT_NAME@"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "DesktopShortcut" 1
  ; Written last: the in-app updater waits for this version before starting the app.
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "@VERSION@"
  ${IfNot} ${Silent}
    Call CheckWebView2
  ${EndIf}
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
    MessageBox MB_ICONSTOP "网络恢复没有完成。请先打开 @PRODUCT_NAME@，在设置中点“修复网络组件”，再卸载。" /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  Delete "$INSTDIR\@EXE_NAME@"
  RMDir /r "$INSTDIR\resources"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$DESKTOP\@PRODUCT_NAME@.lnk"
  RMDir /r "$SMPROGRAMS\@PRODUCT_NAME@"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd
