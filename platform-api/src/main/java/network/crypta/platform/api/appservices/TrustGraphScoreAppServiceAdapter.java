package network.crypta.platform.api.appservices;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.trust.TrustGraphApiHandler;

/**
 * Built-in app-service adapter for the Trust Graph Preview score query.
 *
 * <p>The adapter is not a proxy to a provider localhost port. It calls the existing in-process
 * Trust Graph route handler with bounded score parameters, removes the raw subject URI from the
 * result, and returns a compact redacted score summary.
 *
 * <p>The adapter currently supports the {@code trust.score} proving service exposed by Trust Graph
 * Preview. It requires an active grant containing {@code score.read}, checks the invocation context
 * against both the grant and the advertised descriptor, then delegates to {@link
 * TrustGraphApiHandler#score(Map)} for the actual preview score. The returned shape is safe for a
 * consumer app: it includes the subject kind, context, score metadata, and an SHA-256 subject hash,
 * but not imported statement bodies, signatures, store paths, or private identity material.
 *
 * <p>Supported contexts must stay aligned with the Trust Graph scorer's own validation. The adapter
 * does not advertise or accept preview-only labels that the underlying scorer would reject, because
 * a descriptor should not lead operators to approve an unusable grant.
 */
public final class TrustGraphScoreAppServiceAdapter implements AppServiceAdapter {
  /** Public adapter id used in signed app manifests. */
  public static final String ADAPTER_ID = "trust-graph.score";

  private static final String PARAM_CONTEXT = "context";
  private static final String PARAM_SUBJECT_KIND = "subjectKind";
  private static final String PARAM_SUBJECT_URI = "subjectUri";
  private static final String REQUIRED_SCOPE = "score.read";
  private static final HexFormat HEX = HexFormat.of();

  private final TrustGraphApiHandler trustGraphApiHandler;

  /**
   * Creates an adapter backed by the supplied Trust Graph handler.
   *
   * <p>The handler owns the existing Trust Graph Preview scoring rules and validation for subject
   * kind, subject URI, and context. Passing the handler in keeps app-service mediation local to the
   * Platform API without requiring Trust Graph Preview to expose a separate localhost server.
   *
   * @param trustGraphApiHandler local Trust Graph Preview handler to invoke
   */
  public TrustGraphScoreAppServiceAdapter(TrustGraphApiHandler trustGraphApiHandler) {
    this.trustGraphApiHandler = java.util.Objects.requireNonNull(trustGraphApiHandler);
  }

  /**
   * Returns the manifest adapter id for Trust Graph score service descriptors.
   *
   * @return stable adapter id {@code trust-graph.score}
   */
  @Override
  public String adapterId() {
    return ADAPTER_ID;
  }

  /**
   * Invokes the Trust Graph score service through the active app-service grant.
   *
   * <p>The coordinator has already matched consumer, provider, service, scope, context, and grant
   * status. This method performs adapter-specific validation before calling the Trust Graph handler
   * and redacts the raw subject URI from the response. It throws stable Platform API errors when
   * the grant lacks {@code score.read}, the context is not allowed, or the descriptor does not
   * advertise the requested context.
   *
   * @param descriptor advertised Trust Graph service descriptor
   * @param grant active grant selected by the coordinator
   * @param queryParameters decoded invocation parameters including subject and context
   * @return redacted score summary for the Platform API service-call envelope
   */
  @Override
  public Map<String, Object> invoke(
      AppServiceDescriptor descriptor,
      AppServiceGrant grant,
      Map<String, List<String>> queryParameters) {
    if (!grant.scopes().contains(REQUIRED_SCOPE)) {
      throw new PlatformApiException(
          403, "app_service_scope_denied", "The active app-service grant lacks score.read.");
    }
    String subjectKind = PlatformApiParameters.requireString(queryParameters, PARAM_SUBJECT_KIND);
    String subjectUri = PlatformApiParameters.requireString(queryParameters, PARAM_SUBJECT_URI);
    String context = PlatformApiParameters.requireString(queryParameters, PARAM_CONTEXT);
    if (!grant.contexts().isEmpty()
        && !grant
            .contexts()
            .contains(AppServiceManifestParser.normalizeToken(PARAM_CONTEXT, context))) {
      throw new PlatformApiException(
          403,
          "app_service_context_denied",
          "The active app-service grant does not allow this context.");
    }
    if (!descriptor.supportsContext(context)) {
      throw new PlatformApiException(
          400, "app_service_context_unsupported", "The service does not support this context.");
    }
    Map<String, Object> score =
        trustGraphApiHandler.score(
            Map.of(
                PARAM_SUBJECT_KIND,
                List.of(subjectKind),
                PARAM_SUBJECT_URI,
                List.of(subjectUri),
                PARAM_CONTEXT,
                List.of(context)));
    return redactedScore(subjectKind, subjectUri, context, score);
  }

  private static Map<String, Object> redactedScore(
      String subjectKind, String subjectUri, String context, Map<String, Object> score) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put(PARAM_SUBJECT_KIND, subjectKind.trim().toLowerCase(java.util.Locale.ROOT));
    json.put("subjectUriHash", sha256(subjectUri));
    json.put(PARAM_CONTEXT, context.trim());
    json.put("status", score.get("status"));
    json.put("score", score.get("score"));
    json.put("confidence", score.get("confidence"));
    json.put("evidenceCount", score.get("evidenceCount"));
    json.put("contributingEvidenceCount", score.get("contributingEvidenceCount"));
    json.put("completeWot", false);
    return json;
  }

  /**
   * Returns a stable redacted subject hash for audit and invocation output.
   *
   * <p>The hash allows local correlation of repeated score requests without storing or returning
   * the raw subject URI. It is not a token or authorization value.
   *
   * @param value raw subject value to hash
   * @return {@code sha256:} prefixed lowercase hex digest
   */
  public static String sha256(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return "sha256:" + HEX.formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is required", exception);
    }
  }
}
