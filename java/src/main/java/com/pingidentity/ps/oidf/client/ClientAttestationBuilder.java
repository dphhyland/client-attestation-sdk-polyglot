package com.pingidentity.ps.oidf.client;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * Builds a Client Attestation JWT (header {@code typ=oauth-client-attestation+jwt}) — the credential a
 * Client Attester issues to name a client ({@code sub} = {@code client_id}) and bind its instance key via
 * the RFC 7800 {@code cnf.jwk} claim, per draft-ietf-oauth-attestation-based-client-auth. This is the
 * <em>attester</em> side: a client never mints its own attestation. Sign with the attester's issuing key.
 */
public final class ClientAttestationBuilder {

    static final String TYP = "oauth-client-attestation+jwt";

    private final SigningKeyPair attesterKey;
    private final JwsSigner attesterSigner;
    private final String issuer;
    private String clientId;
    private Map<String, Object> confirmationJwk;
    private Instant issuedAt;
    private Instant expiresAt;
    private Duration ttl;
    private List<Map<String, Object>> authorizationDetails;
    private Map<String, Object> workload;

    /**
     * @param attesterKey the attester's issuing key (signs the attestation)
     * @param issuer      the attester entity identifier ({@code iss})
     */
    public ClientAttestationBuilder(SigningKeyPair attesterKey, String issuer) {
        this.attesterKey = Objects.requireNonNull(attesterKey, "attesterKey");
        this.attesterSigner = null;
        this.issuer = requireText(issuer, "issuer");
    }

    /**
     * As {@link #ClientAttestationBuilder(SigningKeyPair, String)}, but signing through an external
     * {@link JwsSigner} (e.g. {@link OpenBaoTransitSigner}) so the attester's private key never enters
     * this JVM.
     */
    public ClientAttestationBuilder(JwsSigner attesterSigner, String issuer) {
        this.attesterKey = null;
        this.attesterSigner = Objects.requireNonNull(attesterSigner, "attesterSigner");
        this.issuer = requireText(issuer, "issuer");
    }

    /** The client being attested — becomes the attestation {@code sub} (= {@code client_id}). */
    public ClientAttestationBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    /** Binds the client instance key as {@code cnf.jwk}. Must be a public JWK. */
    public ClientAttestationBuilder confirmationJwk(Map<String, Object> publicInstanceJwk) {
        this.confirmationJwk = publicInstanceJwk;
        return this;
    }

    /** Convenience: binds the public half of the given instance key as {@code cnf.jwk}. */
    public ClientAttestationBuilder confirmationKey(SigningKeyPair instanceKey) {
        return confirmationJwk(instanceKey.publicJwk());
    }

    public ClientAttestationBuilder issuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    /** Sets an absolute {@code exp}. */
    public ClientAttestationBuilder expiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    /** Sets {@code exp} to {@code iat + ttl}. */
    public ClientAttestationBuilder expiresIn(Duration ttl) {
        this.ttl = ttl;
        return this;
    }

    /** The optional RFC 9396 {@code authorization_details} entitlement the attester asserts for this client. */
    public ClientAttestationBuilder authorizationDetails(List<Map<String, Object>> authorizationDetails) {
        this.authorizationDetails = authorizationDetails;
        return this;
    }

    /** Optional attester-asserted {@code workload} attributes. */
    public ClientAttestationBuilder workload(Map<String, Object> workload) {
        this.workload = workload;
        return this;
    }

    public String build() {
        String sub = requireText(this.clientId, "clientId");
        Map<String, Object> cnfJwk = Objects.requireNonNull(this.confirmationJwk, "confirmation key (cnf.jwk) is required");
        Instant iat = this.issuedAt != null ? this.issuedAt : Instant.now();
        Instant exp = resolveExpiry(iat);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer(this.issuer);
        claims.setSubject(sub);
        claims.setIssuedAt(NumericDate.fromSeconds(iat.getEpochSecond()));
        claims.setExpirationTime(NumericDate.fromSeconds(exp.getEpochSecond()));
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", cnfJwk);
        claims.setClaim("cnf", cnf);
        if (this.authorizationDetails != null && !this.authorizationDetails.isEmpty()) {
            claims.setClaim("authorization_details", this.authorizationDetails);
        }
        if (this.workload != null && !this.workload.isEmpty()) {
            claims.setClaim("workload", this.workload);
        }
        return this.attesterSigner != null
                ? Jws.sign(claims.toJson(), this.attesterSigner, TYP)
                : Jws.sign(claims.toJson(), this.attesterKey, TYP, false);
    }

    private Instant resolveExpiry(Instant iat) {
        if (this.expiresAt != null) {
            return this.expiresAt;
        }
        if (this.ttl != null) {
            return iat.plus(this.ttl);
        }
        throw new IllegalStateException("expiry is required: call expiresAt(...) or expiresIn(...)");
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }
}
