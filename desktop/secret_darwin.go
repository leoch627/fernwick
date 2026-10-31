package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>
static CFMutableDictionaryRef keyQuery(const char *service, const char *account) {
 CFMutableDictionaryRef q=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 CFStringRef s=CFStringCreateWithCString(NULL,service,kCFStringEncodingUTF8);
 CFStringRef a=CFStringCreateWithCString(NULL,account,kCFStringEncodingUTF8);
 CFDictionarySetValue(q,kSecClass,kSecClassGenericPassword);
 CFDictionarySetValue(q,kSecAttrService,s);CFDictionarySetValue(q,kSecAttrAccount,a);
 CFRelease(s);CFRelease(a);return q;
}
static OSStatus readKey(const char *service,const char *account,unsigned char *out,int *length){
 CFMutableDictionaryRef q=keyQuery(service,account);CFDictionarySetValue(q,kSecReturnData,kCFBooleanTrue);CFDictionarySetValue(q,kSecMatchLimit,kSecMatchLimitOne);
 CFTypeRef data=NULL;OSStatus result=SecItemCopyMatching(q,&data);CFRelease(q);
 if(result==errSecSuccess){if(CFGetTypeID(data)!=CFDataGetTypeID()){CFRelease(data);return errSecDecode;}CFIndex n=CFDataGetLength((CFDataRef)data);if(n!=32){CFRelease(data);return errSecDecode;}memcpy(out,CFDataGetBytePtr((CFDataRef)data),n);*length=(int)n;CFRelease(data);}return result;
}
static OSStatus writeKey(const char *service,const char *account,const unsigned char *data,int length){
 CFMutableDictionaryRef q=keyQuery(service,account);CFDataRef value=CFDataCreate(NULL,data,length);CFDictionarySetValue(q,kSecValueData,value);CFDictionarySetValue(q,kSecAttrAccessible,kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);OSStatus result=SecItemAdd(q,NULL);CFRelease(value);CFRelease(q);return result;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func readSystemSecret(service, account string) ([]byte, error) {
	s, a := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(a))
	out := make([]byte, 32)
	var n C.int
	status := C.readKey(s, a, (*C.uchar)(unsafe.Pointer(&out[0])), &n)
	if status == C.errSecItemNotFound {
		return nil, errSecretMissing
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("keychain unavailable: %d", status)
	}
	return out, nil
}
func writeSystemSecret(service, account string, key []byte) error {
	s, a := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(a))
	status := C.writeKey(s, a, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)))
	if status != C.errSecSuccess {
		return fmt.Errorf("keychain unavailable: %d", status)
	}
	return nil
}
