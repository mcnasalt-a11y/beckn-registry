package in.succinct.beckn.registry.controller;

import com.venky.swf.routing.Config;
import in.succinct.beckn.Request;
import in.succinct.json.JSONAwareWrapper;
import org.json.simple.JSONObject;

import java.util.Map;

/**
 * W11b: Optional Ed25519 signature verification for /subscribe (register endpoint).
 *
 * <p>Gate-controlled by property {@code registry.subscribe.verification}:
 * <ul>
 *   <li>{@code off} (default) — verification skipped; sandbox anonymous enrolment works.</li>
 *   <li>{@code on} — Authorization header required; signature verified against the
 *       {@code signing_public_key} in the enrolment payload itself (not from DB, since
 *       the subscriber may be brand new).</li>
 * </ul>
 *
 * <p>Wire format: the Beckn auth header convention already used elsewhere by the upstream
 * registry ({@code SubscribersController.disable()} / {@code subscribe()}):
 * <pre>
 *   Authorization: Signature keyId="&lt;subscriber_id&gt;|&lt;unique_key_id&gt;|ed25519",algorithm="ed25519",
 *                  created="&lt;epoch&gt;",expires="&lt;epoch&gt;",
 *                  headers="(created) (expires) digest",signature="&lt;b64&gt;"
 * </pre>
 * The signing string is produced by the SDK's {@link Request#getSigningString(long, long)}
 * and the signature is checked with {@link Request#verifySignature(String, String, String)}
 * (Ed25519 via Bouncy Castle, provided at runtime by the beckn SDK / onet core).
 *
 * <p>Key source for register(): the {@code signing_public_key} field from the request
 * JSON body (Beckn enrolment payload) — never from a prior DB record, because this call
 * creates the participant record.
 */
public class SignedSubscribeVerifier {

    /** Property name that controls verification mode. */
    public static final String PROP_VERIFICATION = "registry.subscribe.verification";

    /** Property value that enables verification. */
    public static final String VALUE_ON = "on";

    /** Default when the property is absent — sandbox-safe. */
    public static final String DEFAULT_VALUE = "off";

    /** Max tolerated clock skew for a 'created' timestamp in the future (seconds). */
    public static final long FUTURE_SKEW_TOLERANCE_SEC = 300L;

    /**
     * Returns true when verification is currently enabled.
     * Absent property (or any value other than "on") means OFF.
     */
    public static boolean isEnabled() {
        String value = Config.instance().getProperty(PROP_VERIFICATION, DEFAULT_VALUE);
        return VALUE_ON.equalsIgnoreCase(value == null ? "" : value.trim());
    }

    /**
     * Verify the signed /subscribe (register) request.
     *
     * <p>Throws {@link RuntimeException} with a human-readable message on any failure.
     * Returns normally on success.
     *
     * @param payload     raw JSON body of the /subscribe POST request
     * @param httpHeaders request headers map (as supplied by SWF Path)
     */
    public static void verify(String payload, Map<String, String> httpHeaders) {
        // 1. Extract Authorization header params using the SDK helper.
        Request request = new Request(payload);
        Map<String, String> params = request.extractAuthorizationParams("Authorization", httpHeaders);

        if (params == null || params.isEmpty()) {
            throw new RuntimeException(
                "Signed enrolment required: missing or malformed Authorization header. " +
                "Set registry.subscribe.verification=off for sandbox/anonymous enrolment.");
        }

        String signature = params.get("signature");
        String createdStr = params.get("created");
        String expiresStr = params.get("expires");
        String subscriberId = Request.getSubscriberId(params);

        if (signature == null || signature.isBlank()) {
            throw new RuntimeException("Authorization header missing 'signature' param.");
        }
        if (createdStr == null || expiresStr == null) {
            throw new RuntimeException("Authorization header missing 'created' or 'expires' param.");
        }

        long created;
        long expires;
        try {
            created = Long.parseLong(createdStr.trim());
            expires = Long.parseLong(expiresStr.trim());
        } catch (NumberFormatException e) {
            throw new RuntimeException("Invalid 'created' or 'expires' timestamp in Authorization header: " + e.getMessage());
        }

        // 2. Replay / staleness check.
        long nowSec = System.currentTimeMillis() / 1000L;
        if (nowSec > expires) {
            throw new RuntimeException("Signed enrolment request has expired (replay protection). " +
                "Request expired at unix=" + expires + ", now=" + nowSec + ".");
        }
        if (created > nowSec + FUTURE_SKEW_TOLERANCE_SEC) {
            throw new RuntimeException("Request 'created' timestamp is too far in the future. " +
                "created=" + created + ", now=" + nowSec + ". Check clock skew.");
        }

        // 3. Extract signing_public_key from the enrolment payload itself.
        String signingPublicKey = extractRawSigningKey(payload);
        if (signingPublicKey == null || signingPublicKey.isBlank()) {
            throw new RuntimeException("Enrolment payload 'signing_public_key' is empty.");
        }

        // 4. Defense-in-depth: header subscriber_id must match the payload subscriber_id.
        if (subscriberId != null && !subscriberId.isBlank()) {
            String payloadSubId = extractSubscriberId(payload);
            if (payloadSubId != null && !payloadSubId.isBlank() && !payloadSubId.equals(subscriberId)) {
                throw new RuntimeException(
                    "Authorization subscriber_id '" + subscriberId +
                    "' does not match payload subscriber_id '" + payloadSubId + "'.");
            }
        }

        // 5. Build the signing string using the SDK helper.
        String signingString = request.getSigningString(created, expires);

        // 6. Verify Ed25519 signature against the payload's own public key.
        //    NOTE the SDK argument order: Request.verifySignature(SIGNATURE, PAYLOAD, PUBLIC_KEY).
        //    The key must be base64 of a DER SubjectPublicKeyInfo; Beckn payloads in the wild also
        //    carry the raw 32-byte key (what this registry's /subscribers/lookup emits), so
        //    spkiForm() wraps raw -> SPKI and leaves an already-SPKI key unchanged.
        boolean valid;
        try {
            valid = Request.verifySignature(signature, signingString, spkiForm(signingPublicKey));
        } catch (Exception e) {
            throw new RuntimeException("Ed25519 signature verification error: " + e.getMessage(), e);
        }
        if (!valid) {
            throw new RuntimeException(
                "Ed25519 signature verification failed for subscriber enrolment. " +
                "Ensure the Authorization header signature is computed over the correct " +
                "signing string with the private key matching signing_public_key in the payload.");
        }
    }

    /**
     * Read signing_public_key from the enrolment payload. Accepts both the single-subscriber
     * object form and {"subscriber": {...}} nesting. Returns the raw key exactly as supplied
     * so the SDK can decode raw base64 / PEM / DER.
     */
    static String extractRawSigningKey(String payload) {
        JSONObject json = parseObject(payload);
        Object keyObj = json.get("signing_public_key");
        if (keyObj == null) {
            Object nested = json.get("subscriber");
            if (nested instanceof JSONObject) {
                keyObj = ((JSONObject) nested).get("signing_public_key");
            }
        }
        return keyObj == null ? null : keyObj.toString().trim();
    }

    /** Read subscriber_id from the enrolment payload (top level or nested single subscriber). */
    static String extractSubscriberId(String payload) {
        JSONObject json = parseObject(payload);
        Object idObj = json.get("subscriber_id");
        if (idObj == null) {
            Object nested = json.get("subscriber");
            if (nested instanceof JSONObject) {
                idObj = ((JSONObject) nested).get("subscriber_id");
            }
        }
        if (idObj != null) {
            return idObj.toString().trim();
        }
        return null;
    }

    /**
     * Normalise a base64 Ed25519 public key to the SPKI (DER) base64 form the SDK's
     * {@code verifySignature} expects. Accepts an existing SPKI key unchanged, and wraps a raw
     * 32-byte key with the id-Ed25519 AlgorithmIdentifier. Anything else is returned unchanged
     * so the SDK can report a decode failure.
     */
    static String spkiForm(String signingPublicKey) {
        if (signingPublicKey == null) {
            return null;
        }
        String key = signingPublicKey.trim();
        if (key.startsWith("-----BEGIN")) {
            // PEM: let the SDK/BC deal with it as supplied.
            return key;
        }
        byte[] raw;
        try {
            raw = java.util.Base64.getDecoder().decode(key);
        } catch (IllegalArgumentException e) {
            return key;
        }
        if (raw.length != 32) {
            // Already DER (~44 bytes) or something else.
            return key;
        }
        try {
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers.id_Ed25519),
                    raw);
            return java.util.Base64.getEncoder().encodeToString(spki.getEncoded());
        } catch (Exception e) {
            return key;
        }
    }

    private static JSONObject parseObject(String payload) {
        Object parsed;
        try {
            parsed = JSONAwareWrapper.parse(payload);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse enrolment payload: " + e.getMessage(), e);
        }
        if (!(parsed instanceof JSONObject)) {
            throw new RuntimeException("Enrolment payload must be a single JSON object for signed enrolment " +
                "(bulk array enrolment cannot be signed as one body).");
        }
        return (JSONObject) parsed;
    }
}
