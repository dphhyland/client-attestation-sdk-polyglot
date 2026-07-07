package tokenvalidator

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
)

// httpPostFunc performs a form POST and returns the parsed JSON object. Injectable so tests can avoid real
// HTTP; defaults to defaultHTTPPost.
type httpPostFunc func(endpoint, body string, headers map[string]string) (map[string]any, error)

// AccessTokenValidator validates access tokens for a resource server.
//
// Validate does local JWT validation in a fixed order — algorithm accepted, key resolvable, signature,
// iss, exp, nbf, audience, then scope — returning the first failure's stable error code. That order is
// part of the cross-language contract so every port reports the same verdict. ValidateActive instead uses
// RFC 7662 introspection.
type AccessTokenValidator struct {
	config   *Config
	jwks     *jwksProvider
	httpGet  httpGetFunc
	httpPost httpPostFunc
}

// Option customizes a validator (e.g. injecting HTTP transports for tests).
type Option func(*AccessTokenValidator)

// WithHTTPGet injects the transport used to fetch a jwks_uri.
func WithHTTPGet(f httpGetFunc) Option { return func(v *AccessTokenValidator) { v.httpGet = f } }

// WithHTTPPost injects the transport used for introspection.
func WithHTTPPost(f httpPostFunc) Option { return func(v *AccessTokenValidator) { v.httpPost = f } }

// New builds a validator from config.
func New(config *Config, opts ...Option) (*AccessTokenValidator, error) {
	v := &AccessTokenValidator{config: config, httpPost: defaultHTTPPost}
	for _, o := range opts {
		o(v)
	}
	provider, err := newJWKSProvider(config.JWKS, config.JWKSURI, v.httpGet)
	if err != nil {
		return nil, err
	}
	v.jwks = provider
	return v, nil
}

// Validate performs local JWT validation. requiredScopes overrides the configured RequiredScopes when non-nil.
func (v *AccessTokenValidator) Validate(token string, requiredScopes []string) Result {
	required := requiredScopes
	if required == nil {
		required = v.config.RequiredScopes
	}

	msg, err := jws.Parse([]byte(token))
	if err != nil || len(msg.Signatures()) == 0 {
		return failure(ErrInvalidToken, "malformed token")
	}
	header := msg.Signatures()[0].ProtectedHeaders()
	alg := header.Algorithm()
	kid := header.KeyID()

	if !contains(v.config.acceptedAlgorithms(), alg.String()) {
		return failure(ErrUnsupportedAlgorithm, "algorithm '"+alg.String()+"' not accepted")
	}

	key, err := v.jwks.resolve(kid)
	if err != nil {
		return failure(ErrKeyNotFound, err.Error())
	}
	if key == nil {
		return failure(ErrKeyNotFound, "no signing key for kid '"+kid+"'")
	}

	payload, err := jws.Verify([]byte(token), jws.WithKey(alg, key))
	if err != nil {
		return failure(ErrInvalidSignature, "signature verification failed")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return failure(ErrInvalidToken, "malformed claims")
	}

	if v.config.Issuer != "" && stringClaim(claims, "iss") != v.config.Issuer {
		return failure(ErrInvalidIssuer, "unexpected issuer '"+stringClaim(claims, "iss")+"'")
	}

	now := time.Now().Unix()
	leeway := int64(v.config.leeway())
	if exp, ok := toInt64(claims["exp"]); ok && now > exp+leeway {
		return failure(ErrExpired, "token has expired")
	}
	if nbf, ok := toInt64(claims["nbf"]); ok && now+leeway < nbf {
		return failure(ErrNotYetValid, "token is not yet valid")
	}

	audience := audienceList(claims["aud"])
	if len(v.config.Audiences) > 0 && !anyIn(v.config.Audiences, audience) {
		return failure(ErrInvalidAudience, "token audience is not accepted")
	}

	granted := scopesFromClaims(claims)
	if missing := missingScopes(required, granted); len(missing) > 0 {
		return failure(ErrInsufficientScope, "missing scopes: "+strings.Join(missing, " "))
	}

	return success(claims, granted, audience)
}

// Introspect performs an RFC 7662 introspection request and returns the parsed response.
func (v *AccessTokenValidator) Introspect(token string) (map[string]any, error) {
	cfg := v.config.Introspection
	if cfg == nil {
		return nil, errors.New("no introspection endpoint configured")
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	}
	if cfg.AuthMethod == "" || cfg.AuthMethod == "client_secret_basic" {
		creds := base64.StdEncoding.EncodeToString([]byte(cfg.ClientID + ":" + cfg.ClientSecret))
		headers["Authorization"] = "Basic " + creds
	} else {
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	}
	post := v.httpPost
	if post == nil {
		post = defaultHTTPPost
	}
	return post(cfg.Endpoint, form.Encode(), headers)
}

// ValidateActive introspects the token and enforces active plus scope/audience from the response.
func (v *AccessTokenValidator) ValidateActive(token string, requiredScopes []string) Result {
	data, err := v.Introspect(token)
	if err != nil {
		return failure(ErrInvalidToken, err.Error())
	}
	if active, _ := data["active"].(bool); !active {
		return failure(ErrInactive, "token is not active")
	}
	required := requiredScopes
	if required == nil {
		required = v.config.RequiredScopes
	}
	granted := scopesFromClaims(data)
	if missing := missingScopes(required, granted); len(missing) > 0 {
		return failure(ErrInsufficientScope, "missing scopes: "+strings.Join(missing, " "))
	}
	audience := audienceList(data["aud"])
	if len(v.config.Audiences) > 0 && len(audience) > 0 && !anyIn(v.config.Audiences, audience) {
		return failure(ErrInvalidAudience, "token audience is not accepted")
	}
	return success(data, granted, audience)
}

func defaultHTTPPost(endpoint, body string, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- claim helpers (also used by result.go's success) ---

func stringClaim(claims map[string]any, key string) string {
	if s, ok := claims[key].(string); ok {
		return s
	}
	return ""
}

func intClaim(claims map[string]any, key string) int64 {
	i, _ := toInt64(claims[key])
	return i
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, _ := n.Int64()
		return i, true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

func scopesFromClaims(claims map[string]any) []string {
	if s, ok := claims["scope"].(string); ok {
		return strings.Fields(s)
	}
	if arr, ok := claims["scp"].([]any); ok {
		out := make([]string, 0, len(arr))
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func audienceList(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func anyIn(want, have []string) bool {
	for _, w := range want {
		if contains(have, w) {
			return true
		}
	}
	return false
}

func missingScopes(required, granted []string) []string {
	var missing []string
	for _, r := range required {
		if !contains(granted, r) {
			missing = append(missing, r)
		}
	}
	return missing
}
