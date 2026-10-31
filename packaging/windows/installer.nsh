!macro customInstall
  nsExec::ExecToStack '"$INSTDIR\resources\native\win32-x64\helper.exe" install --app "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "${PRODUCT_NAME} service installation failed. Run the installer again as administrator."
    SetErrorLevel 1
    Quit
  ${EndIf}
!macroend

!macro customUnInstall
  ; Updating calls the new install macro. An explicit uninstall removes only owned state.
  ${IfNot} ${isUpdated}
    nsExec::ExecToStack '"$PROGRAMFILES64\@SERVICE_ID@-service\helper.exe" uninstall'
    Pop $0
    Pop $1
    ${If} $0 != 0
      MessageBox MB_ICONSTOP "Network recovery did not complete. Repair ${PRODUCT_NAME} before uninstalling."
      Abort
    ${EndIf}
  ${EndIf}
!macroend
