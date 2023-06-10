package oar_test

import (
	"testing"

	"github.com/jogly/oar"
)

func TestRouter_IsUnsafe(t *testing.T) {
	r := &oar.Router{
		Domains: []string{"*.example.com"},
		Origins: []string{"*.example.com"},
	}
	if r.IsUnsafe() {
		t.Error("expected router to be safe")
	}

	r = &oar.Router{
		Domains: []string{"*", "*.example.com"},
		Origins: []string{"*", "*.example.com"},
	}
	if !r.IsUnsafe() {
		t.Error("expected router to be unsafe")
	}
}

func TestParseDomains(t *testing.T) {
	cases := []struct {
		input  string
		output []string
	}{
		{"", []string{}},
		{"*.example.com", []string{"*.example.com"}},
		{"*.example.com,*.example.org", []string{"*.example.com", "*.example.org"}},
		{",*", []string{"*"}},
		{"*,", []string{"*"}},
		{"*,*", []string{"*"}},
		{"*, ", []string{"*"}},
		{" , *", []string{"*"}},
		{" , ", []string{}},
		{"example.com,,example.com", []string{"example.com"}},
	}

	for _, c := range cases {
		output := oar.ParseDomainPatterns(c.input)
		if len(output) != len(c.output) {
			t.Errorf("expected %d domains, got %d", len(c.output), len(output))
		}
		for i, d := range output {
			if d != c.output[i] {
				t.Errorf("expected %s, got %s", c.output[i], d)
			}
		}
	}
}
