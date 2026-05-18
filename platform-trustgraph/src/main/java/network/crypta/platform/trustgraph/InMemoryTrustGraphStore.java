package network.crypta.platform.trustgraph;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Process-local Trust Graph Preview store used by the minimal service surface.
 *
 * <p>The store keeps imported statements and local anchors in memory with explicit retention caps.
 * It is suitable for reference apps, offline developer tools, and tests that need deterministic
 * behavior without introducing daemon-core storage or background crawler state. The implementation
 * is synchronized because callers may import, anchor, and score from different app-originated
 * Platform API requests.
 *
 * <p>Stored records are redacted summaries around parsed trust documents. Source URI metadata is
 * limited to Crypta content-key forms, signatures are verified when issuer public keys are present,
 * and insertion-order eviction bounds heap growth from granted apps.
 */
public final class InMemoryTrustGraphStore implements TrustGraphStore {
  /**
   * Default maximum number of imported trust statements retained in memory.
   *
   * <p>When the cap is reached, adding a distinct statement evicts the oldest retained statement.
   * Re-importing the same document refreshes its metadata without increasing the retained count.
   */
  public static final int DEFAULT_MAX_STATEMENTS = 512;

  /**
   * Default maximum number of local trust anchors retained in memory.
   *
   * <p>Anchors are local process policy inputs. The cap prevents a granted app from growing the
   * local response set or scorer lookup table without bound.
   */
  public static final int DEFAULT_MAX_ANCHORS = 256;

  private static final String CRYPTA_SCHEME_PREFIX = "crypta:";
  private static final String CHK_PREFIX = "CHK@";
  private static final String SSK_PREFIX = "SSK@";
  private static final String USK_PREFIX = "USK@";
  private static final String KSK_PREFIX = "KSK@";

  private final Clock clock;
  private final int maxStatements;
  private final int maxAnchors;
  private final Map<String, TrustAnchor> anchors = new LinkedHashMap<>();
  private final Map<String, StoredTrustStatement> statements = new LinkedHashMap<>();

  /**
   * Creates an in-memory store using the system UTC clock.
   *
   * <p>This constructor is used by default Platform API composition. Tests that assert timestamp or
   * expiry behavior should use a fixed-clock constructor.
   */
  public InMemoryTrustGraphStore() {
    this(Clock.systemUTC());
  }

  /**
   * Creates an in-memory store using an explicit clock.
   *
   * @param clock clock used for helper-created anchor timestamps
   */
  public InMemoryTrustGraphStore(Clock clock) {
    this(clock, DEFAULT_MAX_STATEMENTS);
  }

  /**
   * Creates an in-memory store using an explicit clock and statement retention limit.
   *
   * @param clock clock used for helper-created anchor timestamps
   * @param maxStatements positive maximum number of retained statement records
   */
  public InMemoryTrustGraphStore(Clock clock, int maxStatements) {
    this(clock, maxStatements, DEFAULT_MAX_ANCHORS);
  }

  /**
   * Creates an in-memory store using an explicit clock plus statement and anchor retention limits.
   *
   * @param clock clock used for helper-created anchor timestamps
   * @param maxStatements positive maximum number of retained statement records
   * @param maxAnchors positive maximum number of retained anchor records
   * @throws IllegalArgumentException when either retention limit is less than one
   */
  public InMemoryTrustGraphStore(Clock clock, int maxStatements, int maxAnchors) {
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
    if (maxStatements < 1) {
      throw new IllegalArgumentException("maxStatements must be positive.");
    }
    if (maxAnchors < 1) {
      throw new IllegalArgumentException("maxAnchors must be positive.");
    }
    this.maxStatements = maxStatements;
    this.maxAnchors = maxAnchors;
  }

  @Override
  public synchronized TrustGraphImportResult importStatement(
      TrustStatementDocument document, String source, String sourceUri, String sourceLabel) {
    String documentFingerprint = TrustStatementFingerprint.documentFingerprint(document);
    String payloadHash = TrustStatementFingerprint.payloadHash(document);
    boolean signatureVerified = TrustStatementVerifier.isSignatureVerified(document);
    String normalizedSource =
        TrustStatementValidator.optionalText("source", source, 32) == null
            ? "manual"
            : source.trim();
    String normalizedSourceUri = normalizeSourceUri(sourceUri);
    String normalizedSourceLabel =
        TrustStatementValidator.optionalText("sourceLabel", sourceLabel, 120);
    boolean imported = !statements.containsKey(documentFingerprint);
    if (imported) {
      evictEldestStatementIfFull();
    }
    statements.put(
        documentFingerprint,
        new StoredTrustStatement(
            document,
            documentFingerprint,
            payloadHash,
            signatureVerified,
            normalizedSource,
            normalizedSourceUri,
            normalizedSourceLabel));
    return new TrustGraphImportResult(
        documentFingerprint,
        payloadHash,
        imported,
        signatureVerified,
        normalizedSource,
        normalizedSourceUri,
        normalizedSourceLabel,
        document);
  }

  @Override
  public synchronized TrustAnchor addAnchor(TrustAnchor anchor) {
    if (!anchors.containsKey(anchor.issuerFingerprint())) {
      evictEldestAnchorIfFull();
    }
    anchors.put(anchor.issuerFingerprint(), anchor);
    return anchor;
  }

  /**
   * Adds an anchor using the store clock.
   *
   * <p>This convenience method is used by tests and local callers that do not already have a {@link
   * TrustAnchor} instance. It applies the same validation, replacement, and eviction policy as
   * {@link #addAnchor(TrustAnchor)}.
   *
   * @param fingerprint public issuer fingerprint to mark as locally anchored
   * @param label optional bounded display label for local UI summaries
   * @param source optional bounded local source label such as {@code manual}
   * @return stored anchor after validation and defaulting
   */
  public synchronized TrustAnchor addAnchor(String fingerprint, String label, String source) {
    return addAnchor(new TrustAnchor(fingerprint, label, source, clock.instant()));
  }

  @Override
  public synchronized boolean removeAnchor(String issuerFingerprint) {
    String normalized =
        TrustStatementValidator.requiredText("issuerFingerprint", issuerFingerprint, 128);
    return anchors.remove(normalized) != null;
  }

  @Override
  public synchronized List<TrustAnchor> anchors() {
    ArrayList<TrustAnchor> ordered = new ArrayList<>(anchors.values());
    ordered.sort(Comparator.comparing(TrustAnchor::issuerFingerprint));
    return List.copyOf(ordered);
  }

  @Override
  public synchronized List<StoredTrustStatement> statements() {
    return List.copyOf(statements.values());
  }

  @Override
  public synchronized List<TrustSubject> subjects() {
    TreeMap<String, TrustSubject> subjects = new TreeMap<>();
    for (StoredTrustStatement statement : statements.values()) {
      TrustSubject subject = statement.document().payload().subject();
      subjects.put(subject.kind().jsonValue() + "\n" + subject.uri(), subject);
    }
    ArrayList<TrustSubject> ordered = new ArrayList<>(subjects.values());
    ordered.sort(
        Comparator.comparing((TrustSubject subject) -> subject.kind().jsonValue())
            .thenComparing(TrustSubject::uri));
    return List.copyOf(ordered);
  }

  @Override
  public synchronized boolean isAnchor(String issuerFingerprint) {
    return anchors.containsKey(issuerFingerprint);
  }

  @Override
  public synchronized int statementCount() {
    return statements.size();
  }

  private static String normalizeSourceUri(String sourceUri) {
    String normalized = TrustStatementValidator.optionalText("sourceUri", sourceUri, 1024);
    if (normalized == null) {
      return null;
    }
    if (normalized.isEmpty()
        || containsWhitespace(normalized)
        || normalized.indexOf('?') >= 0
        || normalized.indexOf('#') >= 0) {
      throw invalidSourceUri();
    }
    String runtimeUri = runtimeFetchUri(normalized);
    if (runtimeUri.isEmpty()
        || containsWhitespace(runtimeUri)
        || runtimeUri.indexOf('?') >= 0
        || runtimeUri.indexOf('#') >= 0
        || runtimeUri.startsWith("/")
        || runtimeUri.startsWith("\\")
        || hasDisallowedScheme(runtimeUri)
        || isUnsupportedContentKey(runtimeUri)) {
      throw invalidSourceUri();
    }
    if (normalized.regionMatches(true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return CRYPTA_SCHEME_PREFIX + runtimeUri;
    }
    return runtimeUri;
  }

  private static String runtimeFetchUri(String requestedUri) {
    if (requestedUri.regionMatches(
        true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return requestedUri.substring(CRYPTA_SCHEME_PREFIX.length()).trim();
    }
    return requestedUri;
  }

  private static boolean hasDisallowedScheme(String uri) {
    int colon = uri.indexOf(':');
    int at = uri.indexOf('@');
    return colon >= 0 && (at < 0 || colon < at);
  }

  private static boolean isUnsupportedContentKey(String uri) {
    return !(uri.startsWith(CHK_PREFIX)
        || uri.startsWith(SSK_PREFIX)
        || uri.startsWith(USK_PREFIX)
        || uri.startsWith(KSK_PREFIX));
  }

  private static boolean containsWhitespace(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isWhitespace(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }

  private static TrustGraphException invalidSourceUri() {
    return new TrustGraphException(
        "invalid_trust_statement", "Field 'sourceUri' must be a Crypta content URI.");
  }

  private void evictEldestStatementIfFull() {
    while (statements.size() >= maxStatements) {
      Iterator<String> iterator = statements.keySet().iterator();
      if (!iterator.hasNext()) {
        return;
      }
      iterator.next();
      iterator.remove();
    }
  }

  private void evictEldestAnchorIfFull() {
    while (anchors.size() >= maxAnchors) {
      Iterator<String> iterator = anchors.keySet().iterator();
      if (!iterator.hasNext()) {
        return;
      }
      iterator.next();
      iterator.remove();
    }
  }
}
