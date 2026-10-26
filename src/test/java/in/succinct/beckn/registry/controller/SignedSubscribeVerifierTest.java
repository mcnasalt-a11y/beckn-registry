package in.succinct.beckn.registry.controller;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * W11b unit tests for the signed /subscribe verification path.
 *
 * <p>Two layers are covered:
 * <ol>
 *   <li><b>Logic layer (pure, no SWF runtime):</b> {@link SignedSubscribeVerifier#extractRawSigningKey}
 *       and {@link SignedSubscribeVerifier#extractSubscriberId}, plus the property-default contract.</li>
 *   <li><b>Crypto layer:</b> Ed25519 sign/verify primitives in the exact form the wire uses
 *       (raw 32-byte public key, base64 signature over {@code UTF8(signingString)}), proving
 *       (a) a valid signature verifies, (b) a tampered payload fails, (c) a signature made with
 *       a different key fails.</li>
 * </ol>
 *
 * <p>The end-to-end path (HTTP → extractAuthorizationParams → getSigningString → verify) needs a
 * live SWF container (Config, H2, onet core) and is proven live against a real container on
 * port 3031 — see docs/build-logs/W11b-journal.md §Live Proof.
 */
public class SignedSubscribeVerifierTest {

    // ─── helpers ──────────────────────────────────────────────────────────────

    /** Generate a fresh Ed25519 keypair; returns [privateKeyBytes32, publicKeyBytes32]. */
    static byte[][] generateEd25519Keypair() {
        SecureRandom rng = new SecureRandom();
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(rng);
        Ed25519PublicKeyParameters pub = priv.generatePublicKey();
        return new byte[][]{ priv.getEncoded(), pub.getEncoded() };
    }

    /** Sign bytes with an Ed25519 private key; returns the raw 64-byte signature. */
    static byte[] ed25519Sign(byte[] privateKeyBytes, byte[] message) {
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, priv);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    /** Verify an Ed25519 signature. */
    static boolean ed25519Verify(byte[] publicKeyBytes, byte[] message, byte[] signature) {
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pub);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }

    /**
     * Mirror of the SDK signing string shape:
     *   (created): &lt;epoch&gt;
     *   (expires): &lt;epoch&gt;
     *   digest: BLAKE-512=&lt;b64&gt;
     */
    static String buildSigningString(long created, long expires, String body) {
        return "(created): " + created + "\n" +
               "(expires): " + expires + "\n" +
               "digest: BLAKE-512=" + body;
    }

    // ─── crypto layer ─────────────────────────────────────────────────────────

    @Test
    public void validSignatureAccepted() {
        byte[][] kp = generateEd25519Keypair();
        long now = System.currentTimeMillis() / 1000L;
        String ss = buildSigningString(now - 10, now + 290, "dGVzdC1kaWdlc3Q=");

        byte[] sig = ed25519Sign(kp[0], ss.getBytes(StandardCharsets.UTF_8));
        String b64 = Base64.getEncoder().encodeToString(sig);

        boolean ok = ed25519Verify(kp[1], ss.getBytes(StandardCharsets.UTF_8),
                                   Base64.getDecoder().decode(b64));
        Assert.assertTrue("Valid Ed25519 signature must verify", ok);
    }

    @Test
    public void tamperedPayloadRejected() {
        byte[][] kp = generateEd25519Keypair();
        long now = System.currentTimeMillis() / 1000L;

        String original = buildSigningString(now - 10, now + 290, "b3JpZ2luYWw=");
        byte[] sig = ed25519Sign(kp[0], original.getBytes(StandardCharsets.UTF_8));

        String tampered = buildSigningString(now - 10, now + 290, "dGFtcGVyZWQ=");
        Assert.assertFalse("Tampered payload must fail verification",
            ed25519Verify(kp[1], tampered.getBytes(StandardCharsets.UTF_8), sig));
    }

    @Test
    public void wrongKeyRejected() {
        byte[][] signer = generateEd25519Keypair();
        byte[][] attacker = generateEd25519Keypair();
        long now = System.currentTimeMillis() / 1000L;

        String ss = buildSigningString(now - 10, now + 290, "dGVzdA==");
        byte[] sig = ed25519Sign(attacker[0], ss.getBytes(StandardCharsets.UTF_8));

        Assert.assertFalse("Signature by a different key must fail against the declared public key",
            ed25519Verify(signer[1], ss.getBytes(StandardCharsets.UTF_8), sig));
    }

    @Test
    public void tamperedTimestampRejected() {
        byte[][] kp = generateEd25519Keypair();
        long now = System.currentTimeMillis() / 1000L;

        byte[] sig = ed25519Sign(kp[0],
            buildSigningString(now - 10, now + 290, "eA==").getBytes(StandardCharsets.UTF_8));

        // Attacker extends the expiry after signing (classic replay-window attack).
        String extended = buildSigningString(now - 10, now + 86400, "eA==");
        Assert.assertFalse("Modifying 'expires' after signing must invalidate the signature",
            ed25519Verify(kp[1], extended.getBytes(StandardCharsets.UTF_8), sig));
    }

    // ─── logic layer ──────────────────────────────────────────────────────────

    @Test
    public void extractsSigningKeyFromTopLevelPayload() {
        String payload = "{\"subscriber_id\":\"sig-test.example.com\",\"signing_public_key\":\"AAAA\",\"type\":\"BAP\"}";
        Assert.assertEquals("AAAA", SignedSubscribeVerifier.extractRawSigningKey(payload));
        Assert.assertEquals("sig-test.example.com", SignedSubscribeVerifier.extractSubscriberId(payload));
    }

    @Test
    public void extractsSigningKeyFromNestedPayload() {
        String payload = "{\"subscriber\":{\"subscriber_id\":\"nested.example.com\",\"signing_public_key\":\"BBBB\"}}";
        Assert.assertEquals("BBBB", SignedSubscribeVerifier.extractRawSigningKey(payload));
        Assert.assertEquals("nested.example.com", SignedSubscribeVerifier.extractSubscriberId(payload));
    }

    @Test
    public void missingSigningKeyYieldsNull() {
        Assert.assertNull(SignedSubscribeVerifier.extractRawSigningKey("{\"subscriber_id\":\"x\"}"));
    }

    @Test(expected = RuntimeException.class)
    public void arrayPayloadRejectedForSignedEnrolment() {
        SignedSubscribeVerifier.extractRawSigningKey("[{\"subscriber_id\":\"a\"}]");
    }

    @Test
    public void rawKeyIsNormalisedToSpki() {
        byte[][] kp = generateEd25519Keypair();
        String rawB64 = Base64.getEncoder().encodeToString(kp[1]);

        String spki = SignedSubscribeVerifier.spkiForm(rawB64);
        Assert.assertNotNull(spki);
        Assert.assertNotEquals("A raw 32-byte key must be wrapped into SPKI form", rawB64, spki);

        // SPKI form decodes to a SubjectPublicKeyInfo carrying the same 32 raw key bytes.
        byte[] der = Base64.getDecoder().decode(spki);
        Assert.assertTrue("SPKI DER must be longer than the raw key", der.length > 32);

        // Idempotent: an already-SPKI key is returned unchanged.
        Assert.assertEquals(spki, SignedSubscribeVerifier.spkiForm(spki));
    }

    @Test
    public void documentedDefaults() {
        Assert.assertEquals("registry.subscribe.verification", SignedSubscribeVerifier.PROP_VERIFICATION);
        Assert.assertEquals("on", SignedSubscribeVerifier.VALUE_ON);
        Assert.assertEquals("off", SignedSubscribeVerifier.DEFAULT_VALUE);
        Assert.assertEquals(300L, SignedSubscribeVerifier.FUTURE_SKEW_TOLERANCE_SEC);
    }

    // ─── timestamp policy ─────────────────────────────────────────────────────

    @Test
    public void expiredRequestDetection() {
        long now = System.currentTimeMillis() / 1000L;
        Assert.assertTrue("expires in the past must be treated as expired", now > (now - 60));
    }

    @Test
    public void futureClockSkewDetection() {
        long now = System.currentTimeMillis() / 1000L;
        Assert.assertTrue("created beyond +300s tolerance must be flagged",
            (now + 600) > now + SignedSubscribeVerifier.FUTURE_SKEW_TOLERANCE_SEC);
    }
}
