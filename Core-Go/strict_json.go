package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// encoding/json otherwise accepts duplicate keys, folded field names and
// invalid Unicode. These ambiguities are unsafe at signed/config boundaries.
func validateStrictJSON(data []byte, target reflect.Type) error {
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
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := strictJSONValue(decoder, target, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func jsonFields(target reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	for i := 0; i < target.NumField(); i++ {
		field := target.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		base := field.Type
		for base.Kind() == reflect.Pointer {
			base = base.Elem()
		}
		if field.Anonymous && name == "" && base.Kind() == reflect.Struct {
			for key, value := range jsonFields(base) {
				fields[key] = value
			}
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func strictJSONValue(decoder *json.Decoder, target reflect.Type, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		var fields map[string]reflect.Type
		if target != nil && target.Kind() == reflect.Struct {
			fields = jsonFields(target)
		}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON field")
			}
			seen[key] = true
			var child reflect.Type
			if fields != nil {
				child, ok = fields[key]
				if !ok {
					return fmt.Errorf("unknown JSON field %q", key)
				}
			} else if target != nil && target.Kind() == reflect.Map {
				child = target.Elem()
			}
			if err := strictJSONValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var child reflect.Type
		if target != nil && (target.Kind() == reflect.Slice || target.Kind() == reflect.Array) {
			child = target.Elem()
		}
		for decoder.More() {
			if err := strictJSONValue(decoder, child, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
