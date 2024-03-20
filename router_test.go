package oar_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jogly/oar"
)

func TestRouter_IsUnsafe(t *testing.T) {
	r := &oar.Router{
		Targets: []string{"*.example.com"},
		Origins: []string{"*.example.com"},
	}
	if r.IsUnsafe() {
		t.Error("expected router to be safe")
	}

	r = &oar.Router{
		Targets: []string{"*", "*.example.com"},
		Origins: []string{"*", "*.example.com"},
	}
	if !r.IsUnsafe() {
		t.Error("expected router to be unsafe")
	}
}

func TestRouter_ServeHTTP(t *testing.T) {
	t.Parallel()

	router := oar.Router{
		Targets: []string{"example.com"},
		Origins: []string{"example.com"},
	}

	t.Run("method not allowed", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("http://example.com", "")
		r.Method = http.MethodPost
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusBadRequest)
		expectBody(t, w, "method not allowed: POST")
	})

	t.Run("path not allowed", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("http://example.com", "state")
		r.URL.Path = "/foo"
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusBadRequest)
		expectBody(t, w, "path not allowed: /foo")
	})

	t.Run("invalid origin", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("%", "")
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusForbidden)
		expectBody(t, w, "invalid origin: parse origin")
	})

	t.Run("origin missing scheme", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("example.com", "")
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusForbidden)
		expectBody(t, w, "invalid origin: origin is missing scheme: example.com")
	})

	t.Run("origin missing host", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("http://", "")
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusForbidden)
		expectBody(t, w, "invalid origin: origin is missing host")
	})

	t.Run("origin not allowed", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("http://example.org", "")
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusForbidden)
		expectBody(t, w, "invalid origin: origin is not allowed: example.org")
	})

	t.Run("target not allowed", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := request("http://example.com", makeState("http://example.org"))
		router.ServeHTTP(w, r)
		expectStatus(t, w, http.StatusForbidden)
		expectBody(t, w, "target is not allowed: example.org")
	})
}

func TestRouter_EmptyOriginRequests(t *testing.T) {
	t.Parallel()

	origin, target := "", "http://example.com"

	router := oar.Router{
		Targets: []string{"example.com"},
		Origins: []string{"*"},
	}

	w := httptest.NewRecorder()
	r := request(origin, makeState(target))
	router.ServeHTTP(w, r)
	expectStatus(t, w, http.StatusFound)
	expectBody(t, w, target)
}

func TestRouter_URLMatching(t *testing.T) {
	t.Parallel()

	origin, target := "http://coming.from.origin.com", "http://going.to.target.com"

	router := oar.Router{
		Targets: []string{"*.*.*.*.*.*.com", "*.target.com"},
		Origins: []string{"*.*.*.*.*.*.com", "*.origin.com"},
	}

	w := httptest.NewRecorder()
	r := request(origin, makeState(target))
	router.ServeHTTP(w, r)
	expectStatus(t, w, http.StatusFound)
	expectBody(t, w, target)
}

func TestRouter_Logger(t *testing.T) {
	called := false
	logger := func(format string, args ...interface{}) {
		if format != "redirecting %s -> %s" {
			t.Errorf("expected format to be redirecting %%s -> %%s, got %s", format)
		}
		called = true
	}

	router := oar.Unsafe()
	router.Logger = logger

	w := httptest.NewRecorder()
	r := request("http://example.com", makeState("http://example.org"))
	router.ServeHTTP(w, r)

	if !called {
		t.Error("expected logger to be called")
	}
}

func TestParseDomainPatterns(t *testing.T) {
	t.Parallel()

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

	for _, tc := range cases {
		c := tc
		t.Run(c.input, func(t *testing.T) {
			t.Parallel()

			output := oar.ParseDomainPatterns(c.input)
			if len(output) != len(c.output) {
				t.Errorf("expected %d domains, got %d", len(c.output), len(output))
			}
			for i, d := range output {
				if d != c.output[i] {
					t.Errorf("expected %s, got %s", c.output[i], d)
				}
			}
		})
	}

	func() {
		defer expectPanic()

		oar.ParseDomainPatterns("baddomain")
	}()
}

func TestRouter_StateErrors(t *testing.T) {
	t.Parallel()

	r := oar.Unsafe()

	cases := []struct {
		state   string
		message string
		encode  bool
	}{
		{"", "invalid state: state is required", true},
		{"%20", "invalid state: state is empty", false},
		{"%invalid", "invalid state: state is not url encoded: invalid URL escape", false},
		{"notbase64", "invalid state: state is not base64 encoded: ", false},
		{"{}", "invalid state: state is missing redirect", true},
		{`{"redirect": "baduri"}`, "invalid state: state.redirect is invalid URL", true},
		{`{"redirect": "http://"}`, "invalid state: state.redirect is missing host", true},
		{"notjson", "invalid state: state is invalid json", true},
	}

	for _, tc := range cases {
		c := tc
		t.Run(c.state, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			if c.encode {
				c.state = b64(c.state)
			}
			r.ServeHTTP(w, request("http://example.com", c.state))
			expectStatus(t, w, http.StatusBadRequest)
			expectBody(t, w, c.message)
		})
	}
}

func TestRouter_StateMerge(t *testing.T) {
	router := oar.Unsafe()
	state := b64(`{"redirect": "http://example.com?embed=value", "foo": "bar"}`)

	query := url.Values{
		"code":  []string{"secret"},
		"state": []string{state},
	}

	url := &url.URL{
		Scheme:   "http",
		Host:     "example.com",
		RawQuery: query.Encode(),
	}

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, url.String(), nil)
	expectNoErr(t, err)
	r.Header.Set("Origin", "http://example.com")

	router.ServeHTTP(w, r)

	expectStatus(t, w, http.StatusFound)
	redirect := w.Header().Get("Location")

	redirectURL, err := url.Parse(redirect)
	expectNoErr(t, err)

	if redirectURL.Host != "example.com" {
		t.Errorf("expected redirect to example.com, got %s", redirectURL.Host)
	}

	actualQuery := redirectURL.Query()
	if len(actualQuery) != 3 { // 2 from URL, 1 from embed
		t.Errorf("expected 3 query params, got %d", len(actualQuery))
	}

	if actualQuery.Get("embed") != "value" {
		t.Errorf("expected embed=value, got %s", actualQuery.Get("embed"))
	}

	for k, v := range query {
		if actualQuery.Get(k) != v[0] {
			t.Errorf("expected %s=%s, got %s", k, v[0], actualQuery.Get(k))
		}
	}
}

func request(origin, state string) *http.Request {
	u, _ := url.Parse("http://example.com")
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()

	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}

	return r
}

func expectStatus(t *testing.T, w *httptest.ResponseRecorder, expected int) {
	t.Helper()

	if w.Code != expected {
		t.Errorf("expected status %d, got %d", expected, w.Code)
	}
}

func expectBody(t *testing.T, w *httptest.ResponseRecorder, expected string) {
	t.Helper()

	body := w.Body.String()
	if !strings.Contains(body, expected) {
		t.Errorf("expected body %q, got %q", expected, body)
	}
}

func expectNoErr(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Errorf("expected no error, got %s", err)
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func makeState(redirect string) string {
	return b64(`{"redirect": "` + redirect + `"}`)
}

func expectPanic() {
	if r := recover(); r == nil {
		panic("expected panic")
	}
}
