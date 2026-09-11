package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type credentials struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	PSK      string `json:"psk"`
}

func readCredentials(r io.Reader) (credentials, error) {
	var c credentials
	dec := json.NewDecoder(io.LimitReader(r, 32769))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid credential JSON")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("trailing credential data")
	}
	if ip := net.ParseIP(c.Server); ip == nil || ip.To4() == nil {
		return c, fmt.Errorf("server must be an IPv4 address")
	}
	for _, value := range []string{c.Username, c.Password, c.PSK} {
		if len(value) == 0 || len(value) > 8192 {
			return c, fmt.Errorf("invalid credential length")
		}
	}
	return c, nil
}
