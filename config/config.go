package config

import (
	"bufio"
	"os"
	"strings"
)

// Load reads a simple INI file into a flat map keyed by "section.key".
// Missing file returns empty map (no error). Supports # and ; comments.
func Load(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()

	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if i := strings.IndexByte(line, '='); i >= 0 {
			key := strings.TrimSpace(line[:i])
			val := strings.TrimSpace(line[i+1:])
			if section != "" {
				key = section + "." + key
			}
			m[key] = val
		}
	}
	return m
}

// Get returns the value for "section.key", or fallback if absent/empty.
func Get(m map[string]string, key, fallback string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return fallback
}
