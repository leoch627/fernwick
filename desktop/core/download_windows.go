package core

import (
	"golang.org/x/sys/windows"
	"os"
)

func diskFreeBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	err = windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree)
	return free, err
}
func singleLink(info os.FileInfo) bool { return info.Mode().IsRegular() }
func openDownloadFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE|windows.GENERIC_READ, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, NewAppError("UPDATE_VERIFY_FAILED")
	}
	return os.NewFile(uintptr(h), path), nil
}
func safeDownloadSlot(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(h, &info) == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 && info.NumberOfLinks == 1
}
