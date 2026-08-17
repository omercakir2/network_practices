// Package envload reads a local .env file into the process environment.
// Existing variables are never overwritten (shell / Compose win).
package envload

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// LoadDefault loads ".env" from the current working directory.
// A missing file is not an error.
func LoadDefault() error {
	return LoadFile(".env")
}

// LoadFile reads KEY=VALUE lines from path and sets them in the environment
// only when the key is not already set. A missing file is not an error.
func LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	vars, err := Parse(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for k, v := range vars {
		if _, ok := os.LookupEnv(k); ok {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return nil
}

// Parse reads KEY=VALUE lines. Blank lines and # comments are ignored.
// Values may be wrapped in single or double quotes.
func Parse(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		out[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseLine(line string) (string, string, error) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", fmt.Errorf("expected KEY=VALUE")
	}
	key := strings.TrimSpace(line[:i])
	if key == "" {
		return "", "", fmt.Errorf("empty key")
	}
	val := strings.TrimSpace(line[i+1:])
	val = unquote(val)
	return key, val, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// CSV splits a comma-separated list, trimming space and dropping empty items.
func CSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// LookupCSV is CSV(os.Getenv(key)).
func LookupCSV(key string) []string {
	return CSV(os.Getenv(key))
}
