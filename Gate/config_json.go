package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Validate exact schema field names and reject duplicate members, nulls and
// excess nesting before decoding into a security-sensitive config struct.
func strictConfigJSON(data []byte, target any) error {
	if len(data) > 1<<20 || !utf8.Valid(data) {
		return errors.New("oversized or non-UTF-8 JSON")
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		for i++; i < len(data) && data[i] != '"'; i++ {
			if data[i] != '\\' {
				continue
			}
			i++
			if i >= len(data) || data[i] != 'u' {
				continue
			}
			if i+4 >= len(data) {
				return errors.New("invalid Unicode escape")
			}
			unit, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			if err != nil {
				return err
			}
			i += 4
			if unit >= 0xd800 && unit <= 0xdbff {
				if i+6 >= len(data) || string(data[i+1:i+3]) != "\\u" {
					return errors.New("unpaired Unicode surrogate")
				}
				low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired Unicode surrogate")
				}
				i += 6
			} else if unit >= 0xdc00 && unit <= 0xdfff {
				return errors.New("unpaired Unicode surrogate")
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(reflect.Type, int) error
	walk = func(kind reflect.Type, depth int) error {
		if depth > 16 {
			return errors.New("configuration nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if text, ok := token.(string); ok && (len(text) > 65536 || strings.ContainsRune(text, 0) || !unicodeNFC(text)) {
			return errors.New("invalid bounded JSON string")
		}
		if number, ok := token.(json.Number); ok {
			integer, err := strconv.ParseInt(string(number), 10, 64)
			if err != nil || integer < -9007199254740991 || integer > 9007199254740991 {
				return errors.New("nonportable JSON number")
			}
		}
		if token == nil {
			if kind.Kind() == reflect.Slice {
				return nil
			} // Empty optional lists marshal as null.
			return errors.New("null is not a configuration value")
		}
		switch kind.Kind() {
		case reflect.Struct:
			if token != json.Delim('{') {
				return errors.New("expected configuration object")
			}
			fields := make(map[string]reflect.Type)
			for i := 0; i < kind.NumField(); i++ {
				field := kind.Field(i)
				name := field.Tag.Get("json")
				for j, c := range name {
					if c == ',' {
						name = name[:j]
						break
					}
				}
				if name != "" && name != "-" {
					fields[name] = field.Type
				}
			}
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("invalid member name")
				}
				field, ok := fields[name]
				if !ok || seen[name] {
					return errors.New("unknown or duplicate configuration field")
				}
				seen[name] = true
				if err := walk(field, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case reflect.Slice:
			if token != json.Delim('[') {
				return errors.New("expected configuration array")
			}
			for decoder.More() {
				if err := walk(kind.Elem(), depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			if _, ok := token.(json.Delim); ok {
				return errors.New("expected scalar configuration value")
			}
			return nil
		}
	}
	if err := walk(reflect.TypeOf(target).Elem(), 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("configuration contains trailing JSON data")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
