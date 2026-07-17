import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519

from client_attestation_sdk import SigningKeyPair
from token_validator import discover
from token_validator.jwks import JwksProvider


class JsonServer:
    """Serves one fixed JSON document on every GET, so the default urllib transports can be exercised
    without external network."""

    def __init__(self, body):
        self._body = body
        self._server = HTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self):
        self._server.shutdown()

    def _handler(srv):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                data = srv._body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler


def _jwk(algorithm, kid):
    jwk = SigningKeyPair.generate(algorithm).public_jwk()
    jwk["kid"] = kid
    jwk.pop("alg", None)
    return jwk


def _okp_jwk(kid):
    public = ed25519.Ed25519PrivateKey.generate().public_key()
    jwk = json.loads(jwt.get_algorithm_by_name("EdDSA").to_jwk(public))
    jwk["kid"] = kid
    return jwk


def test_algorithm_inferred_from_key_type_and_bad_keys_skipped():
    jwks = {"keys": [
        _jwk("ES256", "ec-key"),                            # EC without alg -> ES256
        _jwk("RS256", "rsa-key"),                           # RSA without alg -> RS256
        _okp_jwk("okp-key"),                                # OKP without alg -> EdDSA
        {"kty": "oct", "kid": "oct-key", "k": "c2VjcmV0"},  # unknown kty -> RS256 default, unloadable
        {"kty": "EC", "crv": "P-256", "kid": "broken"},     # malformed (no coordinates), skipped
    ]}
    provider = JwksProvider(jwks=jwks)
    assert provider.resolve("ec-key") is not None
    assert provider.resolve("rsa-key") is not None
    assert provider.resolve("okp-key") is not None
    assert provider.resolve("oct-key") is None
    assert provider.resolve("broken") is None


def test_resolve_without_kid_falls_back_to_single_key():
    provider = JwksProvider(jwks={"keys": [_jwk("ES256", "only-key")]})
    assert provider.resolve(None) is not None


def test_resolve_unknown_kid_from_static_jwks_returns_none():
    provider = JwksProvider(jwks={"keys": [_jwk("ES256", "only-key")]})
    assert provider.resolve("nope") is None


def test_jwks_uri_fetched_on_demand_with_injected_transport():
    document = {"keys": [_jwk("ES256", "remote-key")]}
    fetched = []

    def fake_get(url):
        fetched.append(url)
        return json.dumps(document)

    provider = JwksProvider(jwks_uri="https://issuer.example.com/jwks", http_get=fake_get)
    assert provider.resolve("remote-key") is not None
    assert fetched == ["https://issuer.example.com/jwks"]
    assert provider.resolve("still-unknown") is None


def test_jwks_uri_default_transport_fetches_over_http():
    server = JsonServer(json.dumps({"keys": [_jwk("ES256", "served-key")]}))
    try:
        provider = JwksProvider(jwks_uri=server.url + "/jwks")
        assert provider.resolve("served-key") is not None
    finally:
        server.close()


def test_discover_fetches_metadata_document():
    metadata = {
        "issuer": "https://issuer.example.com",
        "jwks_uri": "https://issuer.example.com/jwks",
        "introspection_endpoint": "https://issuer.example.com/introspect",
    }
    server = JsonServer(json.dumps(metadata))
    try:
        assert discover(server.url + "/.well-known/oauth-authorization-server") == metadata
    finally:
        server.close()


def test_discover_with_injected_transport():
    metadata = {"issuer": "https://issuer.example.com"}
    assert discover("https://issuer.example.com/.well-known/oauth-authorization-server",
                    http_get=lambda url: json.dumps(metadata)) == metadata
