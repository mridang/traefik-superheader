package superheader

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// toDashCase converts a camelCase or PascalCase field name to dash-case.
func toDashCase(fieldName string) string {
	var result []string
	for i, runeVal := range fieldName {
		if i > 0 && unicode.IsUpper(runeVal) {
			result = append(result, "-")
		}
		result = append(result, string(unicode.ToLower(runeVal)))
	}
	return strings.Join(result, "")
}

// ValidateConfigJSONTags validates that the JSON tags in a struct are all lowercase, dash-separated,
// and that the tag name matches the field name converted to dash-case.
func ValidateConfigJSONTags(cfg interface{}) error {
	v := reflect.TypeOf(cfg)
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("expected a struct, got %s", v.Kind())
	}

	// validKey matches lowercase letters and dash-separated words
	validKey := regexp.MustCompile(`^[a-z]+(-[a-z]+)*$`)

	// Iterate over each field in the struct
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" {
			continue
		}

		// Split tag on comma in case there are options (like omitempty)
		parts := strings.Split(tag, ",")
		key := parts[0]

		// Check if the tag is lowercase and dash-separated
		if !validKey.MatchString(key) {
			return fmt.Errorf("field %s has invalid json key %q; must be lower-case and dash-separated", field.Name, key)
		}

		// Convert the field name to dash-case and compare it to the json tag
		expectedTag := toDashCase(field.Name)
		if key != expectedTag {
			return fmt.Errorf("field %s has json tag %q; it must match the field name %q", field.Name, key, expectedTag)
		}
	}
	return nil
}

// TestValidateConfigJSONTags tests the ValidateConfigJSONTags function for the Config struct
func TestValidateConfigJSONTags(t *testing.T) {
	// Validate the Config struct directly
	err := ValidateConfigJSONTags(Config{})
	if err != nil {
		t.Errorf("ValidateConfigJSONTags() error = %v", err)
	}
}
