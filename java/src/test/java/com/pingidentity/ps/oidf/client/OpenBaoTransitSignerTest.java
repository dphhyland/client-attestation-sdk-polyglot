package com.pingidentity.ps.oidf.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationResult;
import com.pingidentity.ps.oidf.common.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.Jwks;
import com.pingidentity.ps.oidf.common.StaticAttesterKeyResolver;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link OpenBaoTransitSigner} against an in-process fake transit API — including the interoperability
 * contract: an attestation signed inside the (fake) vault verifies with the real AS-side verifier.
 */
class OpenBaoTransitSignerTest {

    private static final String TOKEN = "unit-test-token";
    private static final String ATTESTER_ISS = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String AUDIENCE = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = "https://as.example.com/as/token.oauth2";

    private FakeBaoServer bao;

    @BeforeEach
    void start() throws Exception {
        bao = new FakeBaoServer(TOKEN);
    }

    @AfterEach
    void stop() {
        bao.close();
    }

    @Test
    void derivesPublicJwkFromTransitKeyMetadata() {
        OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
        Map<String, Object> jwk = signer.publicJwk();
        Map<String, Object> expected = bao.key.toParams(org.jose4j.jwk.JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        assertEquals("ES256", signer.algorithm());
        assertEquals("EC", jwk.get("kty"));
        assertEquals("P-256", jwk.get("crv"));
        assertEquals(expected.get("x"), jwk.get("x"));
        assertEquals(expected.get("y"), jwk.get("y"));
        assertEquals(signer.keyId(), jwk.get("kid"), "kid must be carried in the public JWK");
    }

    @Test
    void vaultSignedAttestationRoundTripsAgainstRealVerifier() throws Exception {
        OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
        SigningKeyPair instanceKey = SigningKeyPair.generate("ES256");

        String attestation = new ClientAttestationBuilder(signer, ATTESTER_ISS)
                .clientId(CLIENT_ID)
                .confirmationKey(instanceKey)
                .expiresIn(Duration.ofMinutes(5))
                .build();
        Map<String, String> headers = new ClientAttestationCredential(attestation, instanceKey)
                .popHeaders(CLIENT_ID, AUDIENCE, null);

        StaticAttesterKeyResolver resolver = new StaticAttesterKeyResolver(
                Map.of(ATTESTER_ISS, List.of(Jwks.fromMap(signer.publicJwk()))));
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(AUDIENCE)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        ClientAttestationVerifier verifier = new ClientAttestationVerifier(resolver, config,
                new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());

        ClientAttestationResult result = verifier.verify(
                headers.get(ClientAttestationCredential.ATTESTATION_HEADER),
                headers.get(ClientAttestationCredential.POP_HEADER),
                null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, result.mode());
        assertEquals(ATTESTER_ISS, result.attesterIssuer());
        assertNotNull(result.proofJti());
    }

    @Test
    void wrongTokenFailsClosed() {
        assertThrows(IllegalStateException.class,
                () -> new OpenBaoTransitSigner(bao.url(), "wrong-token", FakeBaoServer.KEY_NAME));
    }

    @Test
    void vaultDownFailsClosed() {
        OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), TOKEN, FakeBaoServer.KEY_NAME);
        bao.close();
        assertThrows(IllegalStateException.class, () -> signer.sign("payload".getBytes()));
    }
}
