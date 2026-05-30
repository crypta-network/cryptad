package network.crypta.platform.api.appvault;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustIssuer;
import network.crypta.platform.trustgraph.TrustStatementCanonicalizer;
import network.crypta.platform.trustgraph.TrustStatementPayload;
import network.crypta.platform.trustgraph.TrustSubject;
import network.crypta.platform.trustgraph.TrustSubjectKind;

/**
 * Validated bounded trust-statement signing request for one app-visible vault identity.
 *
 * <p>This request type is the trust-graph companion to the profile-document route. It accepts only
 * the public trust statement payload fields, fixes the signing domain, and canonicalizes a bounded
 * payload. It is not an arbitrary signing API, and it never receives private key material or raw
 * vault storage details from AppVault.
 *
 * <p>The record keeps the app id and identity id beside the parsed payload so the handler can bind
 * the request to the authenticated app principal before asking AppVault to sign. The generated
 * payload includes the issuer public key metadata that readers need for preview signature
 * verification, but the route still returns only public identity data, a payload hash, and the
 * signed trust statement document.
 *
 * @param appId authenticated app id requesting the bounded signature
 * @param identityId app-visible vault identity id used as the issuer
 * @param payload validated payload that will be canonicalized and signed
 */
record TrustStatementRequest(String appId, String identityId, TrustStatementPayload payload) {
  /** Fixed signing purpose and document domain used for Trust Graph Preview statements. */
  static final String SIGNING_PURPOSE = TrustDocumentTypes.TRUST_STATEMENT_V1;

  private static final String PARAM_CONFIDENCE = "confidence";
  private static final String PARAM_CONTEXT = "context";
  private static final String PARAM_EXPIRES_AT = "expiresAt";
  private static final String PARAM_PROFILE_URI = "profileUri";
  private static final String PARAM_REASON = "reason";
  private static final String PARAM_SCORE = "score";
  private static final String PARAM_SUBJECT_FINGERPRINT = "subjectFingerprint";
  private static final String PARAM_SUBJECT_KIND = "subjectKind";
  private static final String PARAM_SUBJECT_URI = "subjectUri";
  private static final String PARAM_TAGS = "tags";
  private static final int MAX_UNSIGNED_PAYLOAD_BYTES = 32 * 1024;
  private static final Set<String> SUPPORTED_PARAMETERS =
      Set.of(
          PARAM_CONFIDENCE,
          PARAM_CONTEXT,
          PARAM_EXPIRES_AT,
          PARAM_PROFILE_URI,
          PARAM_REASON,
          PARAM_SCORE,
          PARAM_SUBJECT_FINGERPRINT,
          PARAM_SUBJECT_KIND,
          PARAM_SUBJECT_URI,
          PARAM_TAGS);

  /**
   * Creates a request after confirming the caller-bound ids and payload are present.
   *
   * <p>Field-level payload validation already happened inside {@link TrustStatementPayload}; this
   * constructor only guards the route metadata that binds the signed bytes to one app-visible
   * identity.
   */
  TrustStatementRequest {
    java.util.Objects.requireNonNull(appId, "appId");
    java.util.Objects.requireNonNull(identityId, "identityId");
    java.util.Objects.requireNonNull(payload, "payload");
  }

  /**
   * Builds a validated trust statement request from decoded form parameters.
   *
   * <p>The route supplies issuer metadata from the already-authorized AppVault identity rather than
   * trusting caller-provided issuer fields. Subject, context, score, confidence, reason, tags, and
   * expiry still come from the app request and are bounded by the trust graph model. The issue time
   * is generated from the handler clock so browser callers cannot backdate the signed payload.
   *
   * @param appId normalized app principal that requested the bounded signing operation
   * @param identityId vault identity id already visible to the calling app
   * @param issuerFingerprint public fingerprint from AppVault identity metadata
   * @param issuerPublicKeyBase64 X.509 public key bytes encoded for later verification
   * @param queryParameters decoded form fields supplied to the trust-statement route
   * @param clock clock used to generate the server-side {@code issuedAt} timestamp
   * @return canonical request object ready for AppVault domain-separated signing
   * @throws PlatformApiException when query fields are malformed or exceed preview bounds
   */
  static TrustStatementRequest fromQuery(
      String appId,
      String identityId,
      String issuerFingerprint,
      String issuerPublicKeyBase64,
      Map<String, List<String>> queryParameters,
      Clock clock) {
    rejectUnsupportedParameters(queryParameters);
    Instant issuedAt = clock.instant();
    Instant expiresAt = readOptionalExpiresAt(queryParameters);
    TrustStatementPayload payload =
        new TrustStatementPayload(
            new TrustIssuer(
                identityId,
                issuerFingerprint,
                issuerPublicKeyBase64,
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_PROFILE_URI)),
            new TrustSubject(
                TrustSubjectKind.parse(
                    PlatformApiParameters.requireString(queryParameters, PARAM_SUBJECT_KIND)),
                PlatformApiParameters.requireString(queryParameters, PARAM_SUBJECT_URI),
                PlatformApiParameters.readOptionalString(
                    queryParameters, PARAM_SUBJECT_FINGERPRINT)),
            PlatformApiParameters.requireString(queryParameters, PARAM_CONTEXT),
            readInteger(queryParameters, PARAM_SCORE),
            readInteger(queryParameters, PARAM_CONFIDENCE),
            PlatformApiParameters.readOptionalString(queryParameters, PARAM_REASON),
            readTags(queryParameters),
            issuedAt,
            expiresAt);
    TrustStatementRequest request = new TrustStatementRequest(appId, identityId, payload);
    if (request.canonicalBytes().length > MAX_UNSIGNED_PAYLOAD_BYTES) {
      throw invalidQuery("Unsigned trust statement payload is too large.");
    }
    return request;
  }

  /**
   * Returns the exact bytes signed by AppVault for this bounded request.
   *
   * <p>The byte sequence includes the trust-statement domain separator and the canonical payload
   * JSON. Callers should pass this value directly to AppVault and should not reserialize the
   * payload independently.
   *
   * @return UTF-8 domain-separated canonical payload bytes
   */
  byte[] canonicalBytes() {
    return TrustStatementCanonicalizer.canonicalPayloadBytes(payload);
  }

  private static int readInteger(Map<String, List<String>> queryParameters, String name) {
    String raw = PlatformApiParameters.requireString(queryParameters, name);
    try {
      return Integer.parseInt(raw.trim());
    } catch (NumberFormatException _) {
      throw invalidQuery("Query parameter '" + name + "' must be an integer.");
    }
  }

  private static Instant readOptionalExpiresAt(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.readOptionalString(queryParameters, PARAM_EXPIRES_AT);
    if (raw == null || raw.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(raw.trim());
    } catch (java.time.format.DateTimeParseException _) {
      throw invalidQuery(
          "Query parameter '" + PARAM_EXPIRES_AT + "' must be an ISO-8601 UTC instant.");
    }
  }

  private static List<String> readTags(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.readOptionalString(queryParameters, PARAM_TAGS);
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    ArrayList<String> tags = new ArrayList<>();
    for (String part : raw.split(",", -1)) {
      String tag = part.trim();
      if (tag.isEmpty()) {
        throw invalidQuery("Query parameter 'tags' must not contain empty tags.");
      }
      tags.add(tag);
    }
    return List.copyOf(tags);
  }

  private static void rejectUnsupportedParameters(Map<String, List<String>> queryParameters) {
    for (String name : queryParameters.keySet()) {
      if (!SUPPORTED_PARAMETERS.contains(name)) {
        throw invalidQuery("Unsupported trust statement signing parameter.");
      }
    }
  }

  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
