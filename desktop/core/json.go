package core

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?`)

// StrictJSON parses bounded JSON without losing number precision or accepting
// duplicate keys. Escaped unpaired UTF-16 surrogates use WTF-8 internally so the
// subscription hasher can reproduce JavaScript's JSON.stringify byte for byte.
func StrictJSON(raw []byte, maxBytes int) (any, error) {
	if len(raw) > maxBytes || !utf8.Valid(raw) {
		return nil, NewAppError("INVALID_INPUT")
	}
	p := jsonScanner{input: raw}
	v, err := p.value(0)
	p.whitespace()
	if err != nil || p.pos != len(raw) {
		return nil, NewAppError("INVALID_INPUT")
	}
	return v, nil
}

type jsonScanner struct {
	input []byte
	pos   int
}

func (p *jsonScanner) whitespace() {
	for p.pos < len(p.input) {
		switch p.input[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}
func (p *jsonScanner) take(b byte) bool {
	if p.pos < len(p.input) && p.input[p.pos] == b {
		p.pos++
		return true
	}
	return false
}
func (p *jsonScanner) value(depth int) (any, error) {
	if depth > 32 {
		return nil, NewAppError("INVALID_INPUT")
	}
	p.whitespace()
	if p.pos == len(p.input) {
		return nil, NewAppError("INVALID_INPUT")
	}
	switch p.input[p.pos] {
	case '"':
		return p.string()
	case '{':
		p.pos++
		p.whitespace()
		result := map[string]any{}
		if p.take('}') {
			return result, nil
		}
		for {
			if p.pos == len(p.input) || p.input[p.pos] != '"' {
				return nil, NewAppError("INVALID_INPUT")
			}
			key, err := p.string()
			if err != nil {
				return nil, err
			}
			if _, exists := result[key]; exists || oneOf(key, "__proto__", "prototype", "constructor") {
				return nil, NewAppError("INVALID_INPUT")
			}
			p.whitespace()
			if !p.take(':') {
				return nil, NewAppError("INVALID_INPUT")
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			result[key] = v
			p.whitespace()
			if p.take('}') {
				return result, nil
			}
			if !p.take(',') {
				return nil, NewAppError("INVALID_INPUT")
			}
			p.whitespace()
		}
	case '[':
		p.pos++
		p.whitespace()
		result := []any{}
		if p.take(']') {
			return result, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			result = append(result, v)
			p.whitespace()
			if p.take(']') {
				return result, nil
			}
			if !p.take(',') {
				return nil, NewAppError("INVALID_INPUT")
			}
		}
	default:
		for _, literal := range []struct {
			token string
			value any
		}{{"true", true}, {"false", false}, {"null", nil}} {
			if bytes.HasPrefix(p.input[p.pos:], []byte(literal.token)) {
				p.pos += len(literal.token)
				return literal.value, nil
			}
		}
		token := jsonNumberPattern.Find(p.input[p.pos:])
		if len(token) == 0 {
			return nil, NewAppError("INVALID_INPUT")
		}
		number := json.Number(string(token))
		n, err := number.Float64()
		if err != nil || math.IsInf(n, 0) || math.IsNaN(n) || (math.Trunc(n) == n && math.Abs(n) > float64(MaxSafeInteger)) {
			return nil, NewAppError("INVALID_INPUT")
		}
		p.pos += len(token)
		return number, nil
	}
}
func (p *jsonScanner) hexUnit() (uint16, error) {
	if p.pos+4 > len(p.input) {
		return 0, NewAppError("INVALID_INPUT")
	}
	for _, c := range p.input[p.pos : p.pos+4] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return 0, NewAppError("INVALID_INPUT")
		}
	}
	n, err := strconv.ParseUint(string(p.input[p.pos:p.pos+4]), 16, 16)
	if err != nil {
		return 0, NewAppError("INVALID_INPUT")
	}
	p.pos += 4
	return uint16(n), nil
}
func (p *jsonScanner) string() (string, error) {
	p.pos++
	result := make([]byte, 0)
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		p.pos++
		if c == '"' {
			return string(result), nil
		}
		if c < 0x20 {
			return "", NewAppError("INVALID_INPUT")
		}
		if c != '\\' {
			result = append(result, c)
			continue
		}
		if p.pos == len(p.input) {
			return "", NewAppError("INVALID_INPUT")
		}
		escape := p.input[p.pos]
		p.pos++
		switch escape {
		case '"', '\\', '/':
			result = append(result, escape)
		case 'b':
			result = append(result, '\b')
		case 'f':
			result = append(result, '\f')
		case 'n':
			result = append(result, '\n')
		case 'r':
			result = append(result, '\r')
		case 't':
			result = append(result, '\t')
		case 'u':
			u, err := p.hexUnit()
			if err != nil {
				return "", err
			}
			r := rune(u)
			if u >= 0xd800 && u <= 0xdbff && p.pos+6 <= len(p.input) && p.input[p.pos] == '\\' && p.input[p.pos+1] == 'u' {
				saved := p.pos
				p.pos += 2
				low, e := p.hexUnit()
				if e == nil && low >= 0xdc00 && low <= 0xdfff {
					r = 0x10000 + (rune(u)-0xd800)*0x400 + rune(low) - 0xdc00
				} else {
					p.pos = saved
				}
			}
			if r >= 0xd800 && r <= 0xdfff {
				result = append(result, byte(0xe0|(r>>12)), byte(0x80|((r>>6)&0x3f)), byte(0x80|(r&0x3f)))
			} else {
				result = utf8.AppendRune(result, r)
			}
		default:
			return "", NewAppError("INVALID_INPUT")
		}
	}
	return "", NewAppError("INVALID_INPUT")
}

type schemaValidator interface{ Validate() error }

// DecodeStrict validates the JSON shape before assigning it. All struct fields
// are required unless tagged omitempty or default. The nullable JSON tag accepts
// an explicit null; omitempty alone does not. Failed decoding leaves out intact.
func DecodeStrict(raw []byte, out any, maxBytes int) error {
	value, err := StrictJSON(raw, maxBytes)
	if err != nil {
		return err
	}
	ref := reflect.ValueOf(out)
	if ref.Kind() != reflect.Pointer || ref.IsNil() {
		return NewAppError("INVALID_INPUT")
	}
	temporary := reflect.New(ref.Elem().Type()).Elem()
	if temporary.Type() == reflect.TypeOf(Command{}) {
		command, err := decodeCommand(value)
		if err != nil {
			return err
		}
		temporary.Set(reflect.ValueOf(command))
	} else if err := decodeValue(value, temporary, false); err != nil {
		return err
	}
	ref.Elem().Set(temporary)
	return nil
}

func decodeValue(value any, dest reflect.Value, nullable bool) error {
	if value == nil {
		if !nullable {
			return NewAppError("INVALID_INPUT")
		}
		switch dest.Kind() {
		case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
			dest.SetZero()
			return nil
		default:
			return NewAppError("INVALID_INPUT")
		}
	}
	if dest.Kind() == reflect.Pointer {
		dest.Set(reflect.New(dest.Type().Elem()))
		return decodeValue(value, dest.Elem(), false)
	}
	if dest.Type() == reflect.TypeOf(json.Number("")) {
		n, ok := value.(json.Number)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		dest.SetString(string(n))
		return nil
	}
	switch dest.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		fields := map[string]int{}
		typ := dest.Type()
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := jsonField(f)
			if name != "-" {
				fields[name] = i
			}
		}
		for key := range object {
			if _, ok := fields[key]; !ok {
				return NewAppError("INVALID_INPUT")
			}
		}
		for name, i := range fields {
			field := typ.Field(i)
			_, optional, nullable := jsonField(field)
			v, present := object[name]
			if !present {
				if defaultJSON, has := field.Tag.Lookup("default"); has {
					var err error
					v, err = StrictJSON([]byte(defaultJSON), len(defaultJSON))
					if err != nil {
						return err
					}
				} else if optional {
					continue
				} else {
					return NewAppError("INVALID_INPUT")
				}
			}
			if err := decodeValue(v, dest.Field(i), nullable); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		if dest.Kind() == reflect.Slice {
			dest.Set(reflect.MakeSlice(dest.Type(), len(array), len(array)))
		} else if len(array) != dest.Len() {
			return NewAppError("INVALID_INPUT")
		}
		for i, v := range array {
			if err := decodeValue(v, dest.Index(i), false); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || dest.Type().Key().Kind() != reflect.String {
			return NewAppError("INVALID_INPUT")
		}
		dest.Set(reflect.MakeMapWithSize(dest.Type(), len(object)))
		for key, v := range object {
			entry := reflect.New(dest.Type().Elem()).Elem()
			if err := decodeValue(v, entry, false); err != nil {
				return err
			}
			dest.SetMapIndex(reflect.ValueOf(key).Convert(dest.Type().Key()), entry)
		}
	case reflect.String:
		str, ok := value.(string)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		dest.SetString(str)
	case reflect.Bool:
		b, ok := value.(bool)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		dest.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := value.(json.Number)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		v, err := n.Float64()
		if err != nil || math.Trunc(v) != v || dest.OverflowInt(int64(v)) {
			return NewAppError("INVALID_INPUT")
		}
		dest.SetInt(int64(v))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := value.(json.Number)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		v, err := n.Float64()
		if err != nil || v < 0 || math.Trunc(v) != v || dest.OverflowUint(uint64(v)) {
			return NewAppError("INVALID_INPUT")
		}
		dest.SetUint(uint64(v))
	case reflect.Float32, reflect.Float64:
		n, ok := value.(json.Number)
		if !ok {
			return NewAppError("INVALID_INPUT")
		}
		v, err := n.Float64()
		if err != nil || dest.OverflowFloat(v) {
			return NewAppError("INVALID_INPUT")
		}
		dest.SetFloat(v)
	case reflect.Interface:
		if dest.NumMethod() != 0 {
			return NewAppError("INVALID_INPUT")
		}
		dest.Set(reflect.ValueOf(value))
	default:
		return NewAppError("INVALID_INPUT")
	}
	if dest.CanAddr() {
		if validator, ok := dest.Addr().Interface().(schemaValidator); ok {
			return validator.Validate()
		}
	}
	if dest.CanInterface() {
		if validator, ok := dest.Interface().(schemaValidator); ok {
			return validator.Validate()
		}
	}
	return nil
}

func jsonField(field reflect.StructField) (name string, optional, nullable bool) {
	parts := strings.Split(field.Tag.Get("json"), ",")
	name = parts[0]
	if name == "" {
		name = field.Name
	}
	for _, part := range parts[1:] {
		if part == "omitempty" {
			optional = true
		}
		if part == "nullable" {
			nullable = true
		}
	}
	return
}

func ParseCommand(raw []byte) (Command, error) {
	value, err := StrictJSON(raw, 131072)
	if err != nil {
		return Command{}, err
	}
	return decodeCommand(value)
}
func decodeCommand(value any) (Command, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return Command{}, NewAppError("INVALID_INPUT")
	}
	kind, ok := object["type"].(string)
	if !ok {
		return Command{}, NewAppError("INVALID_INPUT")
	}
	command := Command{Type: kind}
	switch kind {
	case "login":
		var shape struct {
			Type     string `json:"type"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := decodeValue(value, reflect.ValueOf(&shape).Elem(), false); err != nil {
			return Command{}, err
		}
		if !validEmail(shape.Email) || !boundedText(shape.Password, 1, 1024) {
			return Command{}, NewAppError("INVALID_INPUT")
		}
		command.Email = shape.Email
		command.Password = shape.Password
	case "preferences":
		var shape struct {
			Type        string      `json:"type"`
			Preferences Preferences `json:"preferences"`
		}
		if err := decodeValue(value, reflect.ValueOf(&shape).Elem(), false); err != nil {
			return Command{}, err
		}
		command.Preferences = &shape.Preferences
	case "favorite-node":
		var shape struct {
			Type     string `json:"type"`
			NodeID   string `json:"nodeId"`
			Favorite bool   `json:"favorite"`
		}
		if err := decodeValue(value, reflect.ValueOf(&shape).Elem(), false); err != nil {
			return Command{}, err
		}
		if !textField(shape.NodeID) {
			return Command{}, NewAppError("INVALID_INPUT")
		}
		command.NodeID, command.Favorite = shape.NodeID, shape.Favorite
	case "probe-nodes":
		var shape struct {
			Type    string   `json:"type"`
			NodeIDs []string `json:"nodeIds"`
		}
		if err := decodeValue(value, reflect.ValueOf(&shape).Elem(), false); err != nil {
			return Command{}, err
		}
		if !inRange(len(shape.NodeIDs), 1, 64) {
			return Command{}, NewAppError("INVALID_INPUT")
		}
		for _, id := range shape.NodeIDs {
			if !textField(id) {
				return Command{}, NewAppError("INVALID_INPUT")
			}
		}
		command.NodeIDs = shape.NodeIDs
	case "open-link":
		var shape struct {
			Type string `json:"type"`
			Link string `json:"link"`
		}
		if err := decodeValue(value, reflect.ValueOf(&shape).Elem(), false); err != nil {
			return Command{}, err
		}
		if !oneOf(shape.Link, "website", "renew", "help") {
			return Command{}, NewAppError("INVALID_INPUT")
		}
		command.Link = shape.Link
	case "report":
		var shape struct {
			Type string `json:"type"`
			Note string `json:"note"`
		}
		if err := decodeValue(value, reflect.ValueOf(&shape).Elem(), false); err != nil {
			return Command{}, err
		}
		if !boundedText(shape.Note, 0, 500) {
			return Command{}, NewAppError("INVALID_INPUT")
		}
		command.Note = shape.Note
	case "state", "sync", "connect", "disconnect", "logout", "repair", "check-update", "download-update", "pause-update", "cancel-update", "install-update", "diagnostics", "renewal-return", "open-download-page":
		if len(object) != 1 {
			return Command{}, NewAppError("INVALID_INPUT")
		}
	default:
		return Command{}, NewAppError("INVALID_INPUT")
	}
	return command, nil
}
