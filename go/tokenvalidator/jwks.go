package tokenvalidator

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// httpGetFunc fetches the body at url. Injectable so tests can avoid real HTTP.
type httpGetFunc func(url string) ([]byte, error)

// jwksProvider resolves issuer signing keys — from a static JWKS or a jwksURI
// (fetched and cached, refreshed on an unknown kid).
type jwksProvider struct {
	static  bool
	jwksURI string
	get     httpGetFunc

	mu  sync.Mutex
	set jwk.Set
}

// newJWKSProvider builds a provider from either static raw JWKS JSON or a
// jwksURI. The httpGet func is used for URI fetches; when nil a default
// net/http client is used.
func newJWKSProvider(raw json.RawMessage, jwksURI string, httpGet httpGetFunc) (*jwksProvider, error) {
	get := httpGet
	if get == nil {
		get = defaultHTTPGet
	}
	p := &jwksProvider{jwksURI: jwksURI, get: get}
	if len(raw) > 0 {
		set, err := jwk.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
		p.static = true
		p.set = set
	}
	return p, nil
}

// resolve returns the signing key for kid. When kid is empty and the set holds
// exactly one key, that key is returned. For a non-static provider an unknown
// kid triggers a single refresh from the jwks URI. Returns (nil, nil) when no
// matching key can be found.
func (p *jwksProvider) resolve(kid string) (jwk.Key, error) {
	if key, ok := p.lookup(kid); ok {
		return key, nil
	}
	if !p.static && p.jwksURI != "" {
		if err := p.refresh(); err != nil {
			return nil, err
		}
		if key, ok := p.lookup(kid); ok {
			return key, nil
		}
	}
	return nil, nil
}

// lookup checks the currently loaded set for kid (or the sole key when kid is
// empty) without any network access.
func (p *jwksProvider) lookup(kid string) (jwk.Key, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.set == nil {
		return nil, false
	}
	if kid != "" {
		return p.set.LookupKeyID(kid)
	}
	if p.set.Len() == 1 {
		return p.set.Key(0)
	}
	return nil, false
}

// refresh re-fetches and replaces the key set from the jwks URI.
func (p *jwksProvider) refresh() error {
	body, err := p.get(p.jwksURI)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}
	p.mu.Lock()
	p.set = set
	p.mu.Unlock()
	return nil
}

func defaultHTTPGet(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec // url is operator-configured
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
