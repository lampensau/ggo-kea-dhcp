package config

import "testing"

func TestParseMariaDSN(t *testing.T) {
	cases := []struct {
		dsn                    string
		host, user, pass, name string
	}{
		{"kea_user:vertas@tcp(localhost:3306)/kea", "localhost", "kea_user", "vertas", "kea"},
		{"root:s3cret@tcp(10.0.0.5:3306)/keadb", "10.0.0.5", "root", "s3cret", "keadb"},
		{"user@tcp(db:3306)/x", "db", "user", "", "x"},
	}
	for _, c := range cases {
		host, user, pass, name := ParseMariaDSN(c.dsn)
		if host != c.host || user != c.user || pass != c.pass || name != c.name {
			t.Errorf("ParseMariaDSN(%q) = (%q,%q,%q,%q), want (%q,%q,%q,%q)",
				c.dsn, host, user, pass, name, c.host, c.user, c.pass, c.name)
		}
	}
}
