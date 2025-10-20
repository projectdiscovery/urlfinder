package extensions

import (
	"testing"
)

func TestNewValidator(t *testing.T) {
	// Test basic constructor functionality
	validator := NewValidator([]string{".html", ".php"}, []string{".exe", ".dll"}, true)

	if validator == nil {
		t.Error("Expected validator to be created, got nil")
	}

	// Test with default filter
	validatorWithDefault := NewValidator([]string{}, []string{}, false)
	if validatorWithDefault == nil {
		t.Error("Expected validator with default filter to be created, got nil")
	}

	// Test without default filter
	validatorNoDefault := NewValidator([]string{}, []string{}, true)
	if validatorNoDefault == nil {
		t.Error("Expected validator without default filter to be created, got nil")
	}
}

func TestValidatePath(t *testing.T) {
	// Test matching behavior
	t.Run("Match extensions", func(t *testing.T) {
		validator := NewValidator([]string{".html", ".php"}, []string{}, true)

		// Should match .html
		if !validator.ValidatePath("https://example.com/page.html") {
			t.Error("Expected .html to match")
		}

		// Should match .php
		if !validator.ValidatePath("https://example.com/page.php") {
			t.Error("Expected .php to match")
		}

		// Should not match .asp
		if validator.ValidatePath("https://example.com/page.asp") {
			t.Error("Expected .asp to not match")
		}

		// Should not match no extension
		if validator.ValidatePath("https://example.com/page") {
			t.Error("Expected no extension to not match when match list is specified")
		}
	})

	// Test filtering behavior
	t.Run("Filter extensions", func(t *testing.T) {
		validator := NewValidator([]string{}, []string{".exe", ".dll"}, true)

		// Should allow .html
		if !validator.ValidatePath("https://example.com/page.html") {
			t.Error("Expected .html to be allowed")
		}

		// Should block .exe
		if validator.ValidatePath("https://example.com/file.exe") {
			t.Error("Expected .exe to be blocked")
		}

		// Should block .dll
		if validator.ValidatePath("https://example.com/file.dll") {
			t.Error("Expected .dll to be blocked")
		}

		// Should allow no extension
		if !validator.ValidatePath("https://example.com/page") {
			t.Error("Expected no extension to be allowed")
		}
	})

	// Test case insensitive
	t.Run("Case insensitive", func(t *testing.T) {
		validator := NewValidator([]string{".html"}, []string{".exe"}, true)

		// Should match .HTML (uppercase)
		if !validator.ValidatePath("https://example.com/page.HTML") {
			t.Error("Expected .HTML to match")
		}

		// Should block .EXE (uppercase)
		if validator.ValidatePath("https://example.com/file.EXE") {
			t.Error("Expected .EXE to be blocked")
		}
	})

	// Test default filter
	t.Run("Default filter", func(t *testing.T) {
		validator := NewValidator([]string{}, []string{}, false)

		// Should allow .html (not in default filter)
		if !validator.ValidatePath("https://example.com/page.html") {
			t.Error("Expected .html to be allowed with default filter")
		}

		// Should block .pdf (in default filter)
		if validator.ValidatePath("https://example.com/document.pdf") {
			t.Error("Expected .pdf to be blocked by default filter")
		}
	})

	// Test edge cases
	t.Run("Edge cases", func(t *testing.T) {
		validator := NewValidator([]string{}, []string{}, true)

		// Empty URL should fail
		if validator.ValidatePath("") {
			t.Error("Expected empty URL to fail")
		}

		// Invalid URL should fail
		if validator.ValidatePath("://invalid") {
			t.Error("Expected invalid URL to fail")
		}

		// URL without path should pass
		if !validator.ValidatePath("https://example.com") {
			t.Error("Expected URL without path to pass")
		}
	})
}

func TestNormalizeExtension(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{".html", ".html"},
		{"html", ".html"},
		{".HTML", ".html"},
		{"HTML", ".html"},
		{".php", ".php"},
		{"php", ".php"},
		{".PHP", ".php"},
		{"PHP", ".php"},
		{".exe", ".exe"},
		{"exe", ".exe"},
		{".EXE", ".exe"},
		{"EXE", ".exe"},
		{"", "."},
		{".", "."},
		{"..", ".."},
		{".tar.gz", ".tar.gz"},
		{"tar.gz", ".tar.gz"},
		{".TAR.GZ", ".tar.gz"},
		{"TAR.GZ", ".tar.gz"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeExtension(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeExtension(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDefaultExtFilter(t *testing.T) {
	// Test that default filter contains expected extensions
	expectedExtensions := []string{".pdf", ".jpg", ".zip", ".exe", ".dll"}

	for _, ext := range expectedExtensions {
		found := false
		for _, defaultExt := range defaultExtFilter {
			if defaultExt == ext {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected extension %q not found in default filter", ext)
		}
	}
}

func TestValidatorEdgeCases(t *testing.T) {
	// Test with nil slices
	validator := NewValidator(nil, nil, true)
	if validator == nil {
		t.Error("Expected validator to be created with nil slices")
	}

	// Test with duplicate extensions
	validator = NewValidator([]string{".html", ".html", ".php"}, []string{".exe", ".exe", ".dll"}, true)
	if validator == nil {
		t.Error("Expected validator to be created with duplicate extensions")
	}

	// Test ValidatePath with empty validator
	validator = NewValidator([]string{}, []string{}, true)
	if !validator.ValidatePath("https://example.com/page.html") {
		t.Error("Expected empty validator to allow all extensions")
	}
	if !validator.ValidatePath("https://example.com/page") {
		t.Error("Expected empty validator to allow URLs without extensions")
	}
}
