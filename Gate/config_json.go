package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
)

// Validate exact schema field names and reject duplicate members, nulls and
// excess nesting before decoding into a security-sensitive config struct.
func strictConfigJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(reflect.Type, int) error
	walk = func(kind reflect.Type, depth int) error {
		if depth > 32 {
			return errors.New("configuration nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
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
