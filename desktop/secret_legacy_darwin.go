package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Earlier builds stored raw bytes, not the base64 text used by other platforms.
static OSStatus readLegacySessionKey(const char *service, const char *account, unsigned char *out) {
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef serviceName = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef accountName = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    if (!query || !serviceName || !accountName) {
        if (query) CFRelease(query);
        if (serviceName) CFRelease(serviceName);
        if (accountName) CFRelease(accountName);
        return errSecParam;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, serviceName);
    CFDictionarySetValue(query, kSecAttrAccount, accountName);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFRelease(serviceName);
    CFRelease(accountName);
    CFTypeRef data = NULL;
    OSStatus result = SecItemCopyMatching(query, &data);
    CFRelease(query);
    if (result == errSecSuccess) {
        if (!data || CFGetTypeID(data) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)data) != 32) {
            result = errSecDecode;
        } else {
            memcpy(out, CFDataGetBytePtr((CFDataRef)data), 32);
        }
    }
    if (data) CFRelease(data);
    return result;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func readLegacyKeychainSecret(service, account string) ([]byte, error) {
	s, a := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(a))
	key := make([]byte, 32)
	status := C.readLegacySessionKey(s, a, (*C.uchar)(unsafe.Pointer(&key[0])))
	if status == C.errSecItemNotFound {
		return nil, errSecretMissing
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("legacy keychain unavailable: %d", status)
	}
	return key, nil
}
