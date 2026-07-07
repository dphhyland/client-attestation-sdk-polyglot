package com.pingidentity.ps.oidf.client;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Builds a DPoP proof JWT (RFC 9449, header {@code typ=dpop+jwt}) for attestation "combined mode"
 * ({@code attest_jwt_client_auth_dpop}): a single DPoP proof doubles as the attestation proof of
 * possession, so its embedded {@code jwk} header MUST be the instance key bound in the attestation's
 * {@code cnf}. Carries {@code htm}/{@code htu}/{@code iat}/{@code jti} and, when the AS issued one, the
 * challenge in {@code nonce}. Sign with the client instance key.
 */
public final class DpopProofBuilder {

    static final String TYP = "dpop+jwt";

    private final SigningKeyPair instanceKey;
    private String htm = "POST";
    private String htu;
    private String nonce;
    private String jwtId;
    private Instant issuedAt;

    public DpopProofBuilder(SigningKeyPair instanceKey) {
        this.instanceKey = Objects.requireNonNull(instanceKey, "instanceKey");
    }

    /** The token request's HTTP method ({@code htm}); defaults to {@code POST}. */
    public DpopProofBuilder method(String htm) {
        if (htm != null && !htm.isBlank()) {
            this.htm = htm;
        }
        return this;
    }

    /** The token endpoint URL ({@code htu}) — required. */
    public DpopProofBuilder uri(String htu) {
        this.htu = htu;
        return this;
    }

    /** The server challenge, carried in DPoP {@code nonce}. */
    public DpopProofBuilder nonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public DpopProofBuilder jwtId(String jwtId) {
        this.jwtId = jwtId;
        return this;
    }

    public DpopProofBuilder issuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public String build() {
        if (this.htu == null || this.htu.isBlank()) {
            throw new IllegalArgumentException("uri (htu) is required");
        }
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", this.htm);
        claims.setClaim("htu", this.htu);
        claims.setJwtId(this.jwtId != null ? this.jwtId : UUID.randomUUID().toString());
        Instant iat = this.issuedAt != null ? this.issuedAt : Instant.now();
        claims.setIssuedAt(NumericDate.fromSeconds(iat.getEpochSecond()));
        if (this.nonce != null && !this.nonce.isBlank()) {
            claims.setClaim("nonce", this.nonce);
        }
        return Jws.sign(claims.toJson(), this.instanceKey, TYP, true);
    }
}
