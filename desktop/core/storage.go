package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// EncodeJSON preserves surrogate code units parsed from signed JavaScript JSON.
// Go's standard encoder replaces those units and cannot be used for persistence.
func EncodeJSON(value any) ([]byte, error) {
	var b bytes.Buffer
	if err := encodeJSONValue(&b, reflect.ValueOf(value)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func encodeJSONValue(b *bytes.Buffer, v reflect.Value) error {
	if !v.IsValid() {
		b.WriteString("null")
		return nil
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			b.WriteString("null")
			return nil
		}
		v = v.Elem()
	}
	if v.Type() == reflect.TypeOf(json.RawMessage{}) {
		raw := v.Bytes()
		if _, err := StrictJSON(raw, len(raw)); err != nil {
			return err
		}
		b.Write(raw)
		return nil
	}
	if v.Type() == reflect.TypeOf(json.Number("")) {
		raw := v.String()
		if _, err := StrictJSON([]byte(raw), len(raw)); err != nil {
			return err
		}
		b.WriteString(raw)
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		b.WriteString(JSString(v.String()))
	case reflect.Bool:
		b.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		b.WriteString(strconv.FormatUint(v.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		raw, err := json.Marshal(v.Float())
		if err != nil {
			return err
		}
		b.Write(raw)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			b.WriteString("null")
			return nil
		}
		b.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeJSONValue(b, v.Index(i)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case reflect.Map:
		if v.IsNil() {
			b.WriteString("null")
			return nil
		}
		if v.Type().Key().Kind() != reflect.String {
			return NewAppError("INVALID_INPUT")
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(JSString(key.String()))
			b.WriteByte(':')
			if err := encodeJSONValue(b, v.MapIndex(key)); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case reflect.Struct:
		b.WriteByte('{')
		first := true
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			name, optional, _ := jsonField(field)
			if name == "-" {
				continue
			}
			child := v.Field(i)
			if optional && jsonEmpty(child) {
				continue
			}
			if !first {
				b.WriteByte(',')
			}
			first = false
			b.WriteString(JSString(name))
			b.WriteByte(':')
			if err := encodeJSONValue(b, child); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return NewAppError("INVALID_INPUT")
	}
	return nil
}

func jsonEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}

func AtomicWrite(path string, data []byte, current func() bool) error {
	if current == nil {
		current = func() bool { return true }
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if !current() {
		return NewAppError("CANCELLED")
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		folder, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer folder.Close()
		return folder.Sync()
	}
	return nil
}
func readBounded(path string, maxBytes int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(raw) > maxBytes {
		return nil, NewAppError("STORAGE_FAILED")
	}
	return raw, nil
}

type JSONStore[T any] struct {
	mu       sync.Mutex
	path     string
	maxBytes int
}

func NewJSONStore[T any](path string, maxBytes int) *JSONStore[T] {
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024
	}
	return &JSONStore[T]{path: path, maxBytes: maxBytes}
}
func (s *JSONStore[T]) Load() (*T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := readBounded(s.path, s.maxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, NewAppError("STORAGE_FAILED")
	}
	var value T
	if err := DecodeStrict(raw, &value, s.maxBytes); err != nil {
		return nil, NewAppError("STORAGE_FAILED")
	}
	return &value, nil
}
func (s *JSONStore[T]) Save(value T, current func() bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := EncodeJSON(value)
	if err != nil || len(raw) > s.maxBytes {
		return NewAppError("STORAGE_FAILED")
	}
	var check T
	if err := DecodeStrict(raw, &check, s.maxBytes); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	if err = AtomicWrite(s.path, raw, current); err != nil {
		if CodeOf(err) == "CANCELLED" {
			return err
		}
		return NewAppError("STORAGE_FAILED")
	}
	return nil
}

var ErrKeyUnavailable = errors.New("system key storage unavailable")

type KeyProvider interface {
	Key(create bool) ([]byte, error)
}
type KeyProviderFunc func(bool) ([]byte, error)

func (f KeyProviderFunc) Key(create bool) ([]byte, error) { return f(create) }

type SecureStore[T any] struct {
	mu       sync.Mutex
	path     string
	provider KeyProvider
	mode     string
	memory   *T
}

func NewSecureStore[T any](path string, provider KeyProvider) *SecureStore[T] {
	return &SecureStore[T]{path: path, provider: provider, mode: "memory"}
}
func (s *SecureStore[T]) Mode() string { s.mu.Lock(); defer s.mu.Unlock(); return s.mode }
func (s *SecureStore[T]) key(create bool) ([]byte, error) {
	if s.provider == nil {
		return nil, ErrKeyUnavailable
	}
	key, err := s.provider.Key(create)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid encryption key")
	}
	return key, nil
}
func (s *SecureStore[T]) Load() (*T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := readBounded(s.path, 32*1024*1024+128)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := s.key(true); err == nil {
			s.mode = "encrypted"
		} else {
			s.mode = "memory"
		}
		return s.memory, nil
	}
	if err != nil {
		return nil, NewAppError("STORAGE_FAILED")
	}
	key, err := s.key(false)
	if err != nil {
		s.mode = "locked"
		return nil, NewAppError("STORAGE_LOCKED")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewAppError("STORAGE_LOCKED")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	prefix := []byte("STARRAIL-SESSION-V2\x00")
	if !bytes.HasPrefix(data, prefix) || len(data) < len(prefix)+gcm.NonceSize() {
		s.mode = "locked"
		return nil, NewAppError("STORAGE_LOCKED")
	}
	nonce := data[len(prefix) : len(prefix)+gcm.NonceSize()]
	raw, err := gcm.Open(nil, nonce, data[len(prefix)+gcm.NonceSize():], prefix)
	var value T
	if err != nil || DecodeStrict(raw, &value, 32*1024*1024) != nil {
		s.mode = "locked"
		return nil, NewAppError("STORAGE_LOCKED")
	}
	s.memory = &value
	s.mode = "encrypted"
	return &value, nil
}
func (s *SecureStore[T]) Save(value T, current func() bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current == nil {
		current = func() bool { return true }
	}
	if !current() {
		return NewAppError("CANCELLED")
	}
	if s.mode == "locked" {
		return NewAppError("STORAGE_LOCKED")
	}
	raw, err := EncodeJSON(value)
	if err != nil || len(raw) > 32*1024*1024 {
		return NewAppError("STORAGE_FAILED")
	}
	var copied T
	if err = DecodeStrict(raw, &copied, 32*1024*1024); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	key, err := s.key(true)
	if err != nil {
		if !errors.Is(err, ErrKeyUnavailable) {
			return NewAppError("STORAGE_FAILED")
		}
		s.mode = "memory"
		s.memory = &copied
		return nil
	}
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	prefix := []byte("STARRAIL-SESSION-V2\x00")
	encrypted := append(append([]byte{}, prefix...), nonce...)
	encrypted = gcm.Seal(encrypted, nonce, raw, prefix)
	if err = AtomicWrite(s.path, encrypted, current); err != nil {
		if CodeOf(err) == "CANCELLED" {
			return err
		}
		return NewAppError("STORAGE_FAILED")
	}
	if current() {
		s.memory = &copied
	}
	s.mode = "encrypted"
	return nil
}
func (s *SecureStore[T]) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return NewAppError("STORAGE_FAILED")
	}
	s.memory = nil
	if _, err := s.key(false); err == nil {
		s.mode = "encrypted"
	} else {
		s.mode = "memory"
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
func jsNumberString(n json.Number) string {
	v, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return string(n)
	}
	if v == 0 {
		return "0"
	}
	result := strconv.FormatFloat(v, 'f', -1, 64)
	if v >= 1e21 || v <= -1e21 || (v > 0 && v < 1e-6) || (v < 0 && v > -1e-6) {
		result = strconv.FormatFloat(v, 'e', -1, 64)
		result = strings.ReplaceAll(result, "e-0", "e-")
		result = strings.ReplaceAll(result, "e+0", "e+")
	}
	return result
}
