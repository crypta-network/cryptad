package network.crypta.platform.trustgraph;

import java.util.Arrays;
import java.util.Locale;

/**
 * Supported bounded subject kinds for trust statements.
 *
 * <p>The enum values are the complete public vocabulary accepted by the version 1 preview format.
 * They are deliberately app-platform concepts rather than daemon-core objects, so adding trust data
 * does not require wire protocol, routing, datastore, or legacy plugin changes.
 */
public enum TrustSubjectKind {
  /** A Crypta profile document or profile URI selected by an app or user. */
  PROFILE("profile"),

  /** A feed document, feed snapshot, or feed source URI. */
  FEED("feed"),

  /** A local app id or cataloged app identifier. */
  APP("app"),

  /** A bounded public identity identifier that is not a private AppVault secret. */
  IDENTITY("identity"),

  /** A generic Crypta URI or stable subject string outside the narrower categories. */
  URI("uri");

  private static final String FIELD_SUBJECT_KIND = "subject.kind";

  private final String jsonValue;

  TrustSubjectKind(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the public JSON value for this subject kind.
   *
   * @return lowercase value stored in trust statement JSON
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses a public subject kind value.
   *
   * <p>Parsing is case-insensitive for app ergonomics, but the canonical JSON representation always
   * uses {@link #jsonValue()}.
   *
   * @param value raw subject kind
   * @return matching kind
   * @throws TrustGraphException when the value is unsupported
   */
  public static TrustSubjectKind parse(String value) {
    String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    for (TrustSubjectKind kind : values()) {
      if (kind.jsonValue.equals(normalized)) {
        return kind;
      }
    }
    throw invalid(Arrays.stream(values()).map(TrustSubjectKind::jsonValue).toList());
  }

  private static TrustGraphException invalid(Object allowed) {
    return new TrustGraphException(
        "invalid_trust_statement",
        "Field '" + FIELD_SUBJECT_KIND + "' must be one of " + allowed + ".");
  }
}
