package envload

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	const src = `
# comment
SSH_USERS=admin,root
SSH_PASSWORDS="password123,psw123!"
SSH_PORT=22

EMPTY=
QUOTED='hello world'
SPACED = value
`
	got, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]string{
		"SSH_USERS":     "admin,root",
		"SSH_PASSWORDS": "password123,psw123!",
		"SSH_PORT":      "22",
		"EMPTY":         "",
		"QUOTED":        "hello world",
		"SPACED":        "value",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse = %#v, want %#v", got, want)
	}
}

func TestParseBadLine(t *testing.T) {
	_, err := Parse(strings.NewReader("no-equals\n"))
	if err == nil {
		t.Fatal("expected error for missing =")
	}
}

func TestCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"admin", []string{"admin"}},
		{"admin,root", []string{"admin", "root"}},
		{" admin , root , ", []string{"admin", "root"}},
		{",,", nil},
	}
	for _, tc := range cases {
		got := CSV(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("CSV(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestLoadFileNoOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := "ENVLOAD_TEST_A=fromfile\nENVLOAD_TEST_B=fromfile\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ENVLOAD_TEST_A", "fromenv")
	os.Unsetenv("ENVLOAD_TEST_B")

	if err := LoadFile(path); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got := os.Getenv("ENVLOAD_TEST_A"); got != "fromenv" {
		t.Fatalf("A = %q, want fromenv (existing env must win)", got)
	}
	if got := os.Getenv("ENVLOAD_TEST_B"); got != "fromfile" {
		t.Fatalf("B = %q, want fromfile", got)
	}
}

func TestLoadFileMissing(t *testing.T) {
	if err := LoadFile(filepath.Join(t.TempDir(), "nope.env")); err != nil {
		t.Fatalf("missing file should be ok, got %v", err)
	}
}
