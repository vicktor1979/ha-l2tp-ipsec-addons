package main

import (
	"strings"
	"testing"
)

func TestReadCredentials(t *testing.T) {
	c, err := readCredentials(strings.NewReader(`{"server":"203.0.113.5","username":"u","password":" p ","psk":"k"}`))
	if err != nil || c.Password != " p " {
		t.Fatalf("credential parsing: %v", err)
	}
}
func TestRejectInvalidCredentials(t *testing.T) {
	cases := []string{
		`{}`, `null`, `{"server":"203.0.113.5"}`,
		`{"server":"host.example","username":"u","password":"p","psk":"k"}`,
		`{"server":"203.0.113.5","username":"u","password":"p","psk":"k","extra":1}`,
		`{"server":"203.0.113.5","username":"u","password":"p","psk":"k"} {}`,
	}
	for _, text := range cases {
		if _, err := readCredentials(strings.NewReader(text)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}
