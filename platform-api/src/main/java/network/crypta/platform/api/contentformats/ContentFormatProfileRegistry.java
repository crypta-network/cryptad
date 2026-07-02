package network.crypta.platform.api.contentformats;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Registry of Crypta app ecosystem content format profiles used by first-party apps.
 *
 * <p>The registry deliberately covers content documents rather than Platform API routes. Stable
 * route compatibility is still governed by the Platform API contract and compatibility-window
 * policy. These descriptors let Java code, SDK mirrors, reference apps, docs, and release
 * certification agree on identifiers, MIME types, filenames, signing domains, byte limits, and
 * version policy.
 */
public final class ContentFormatProfileRegistry {
  /** Profile document schema and signed document root identifier. */
  public static final String PROFILE_DOCUMENT_ID = "crypta.profile.v1";

  /** MIME type used for published profile documents. */
  public static final String PROFILE_DOCUMENT_CONTENT_TYPE = "application/vnd.crypta.profile+json";

  /** Default generated profile document target filename. */
  public static final String PROFILE_DOCUMENT_DEFAULT_FILENAME = "profile.json";

  /** Fixed AppVault purpose used when signing profile payload bytes. */
  public static final String PROFILE_DOCUMENT_SIGNING_PURPOSE = "profile.publish.v1";

  /** Feed snapshot document type. */
  public static final String FEED_SNAPSHOT_ID = "crypta.feed.snapshot.v1";

  /** MIME type used for feed snapshot generated documents. */
  public static final String FEED_SNAPSHOT_CONTENT_TYPE = "application/vnd.crypta.feed+json";

  /** Default generated feed snapshot target filename. */
  public static final String FEED_SNAPSHOT_DEFAULT_FILENAME = "feed.json";

  /** Trust statement document type and signing domain. */
  public static final String TRUST_STATEMENT_ID = "crypta.trust.statement.v1";

  /** MIME type used for trust statement generated documents. */
  public static final String TRUST_STATEMENT_CONTENT_TYPE = "application/vnd.crypta.trust+json";

  /** Default generated trust statement target filename. */
  public static final String TRUST_STATEMENT_DEFAULT_FILENAME = "trust.json";

  /** Social message document type and signing domain. */
  public static final String SOCIAL_MESSAGE_ID = "crypta.social.message.v1";

  /** Social outbox snapshot document type. */
  public static final String SOCIAL_OUTBOX_ID = "crypta.social.outbox.v1";

  /** MIME type used for social outbox generated documents. */
  public static final String SOCIAL_OUTBOX_CONTENT_TYPE =
      "application/vnd.crypta.social.outbox+json";

  /** Default generated social outbox target filename. */
  public static final String SOCIAL_OUTBOX_DEFAULT_FILENAME = "social-outbox.json";

  /** Shared v1 full-document byte cap for feed/profile/social generated documents. */
  public static final int DEFAULT_APP_DOCUMENT_MAX_BYTES = 64 * 1024;

  /** Default byte cap inherited from the bounded foreground content fetch route. */
  public static final int FETCHED_DOCUMENT_MAX_BYTES = 262_144;

  /** Byte cap for v1 signed profile, trust, and social canonical payloads. */
  public static final int DEFAULT_SIGNED_PAYLOAD_MAX_BYTES = 32 * 1024;

  /** Canonical profile descriptor. */
  public static final ContentFormatProfile PROFILE_DOCUMENT =
      new ContentFormatProfile(
          PROFILE_DOCUMENT_ID,
          1,
          PROFILE_DOCUMENT_CONTENT_TYPE,
          PROFILE_DOCUMENT_DEFAULT_FILENAME,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          DEFAULT_SIGNED_PAYLOAD_MAX_BYTES,
          true,
          PROFILE_DOCUMENT_SIGNING_PURPOSE,
          "profile_payload_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /** Canonical feed snapshot descriptor. */
  public static final ContentFormatProfile FEED_SNAPSHOT =
      new ContentFormatProfile(
          FEED_SNAPSHOT_ID,
          1,
          FEED_SNAPSHOT_CONTENT_TYPE,
          FEED_SNAPSHOT_DEFAULT_FILENAME,
          ContentFormatProfileStatus.STABLE,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          null,
          false,
          null,
          "deterministic_snapshot_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /** Canonical trust statement descriptor. */
  public static final ContentFormatProfile TRUST_STATEMENT =
      new ContentFormatProfile(
          TRUST_STATEMENT_ID,
          1,
          TRUST_STATEMENT_CONTENT_TYPE,
          TRUST_STATEMENT_DEFAULT_FILENAME,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          DEFAULT_SIGNED_PAYLOAD_MAX_BYTES,
          true,
          TRUST_STATEMENT_ID,
          "domain_separator_newline_canonical_payload_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /** Canonical social message descriptor. */
  public static final ContentFormatProfile SOCIAL_MESSAGE =
      new ContentFormatProfile(
          SOCIAL_MESSAGE_ID,
          1,
          "application/json",
          null,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          DEFAULT_SIGNED_PAYLOAD_MAX_BYTES,
          true,
          SOCIAL_MESSAGE_ID,
          "domain_separator_newline_canonical_message_json",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  /** Canonical social outbox descriptor. */
  public static final ContentFormatProfile SOCIAL_OUTBOX =
      new ContentFormatProfile(
          SOCIAL_OUTBOX_ID,
          1,
          SOCIAL_OUTBOX_CONTENT_TYPE,
          SOCIAL_OUTBOX_DEFAULT_FILENAME,
          ContentFormatProfileStatus.EXPERIMENTAL,
          DEFAULT_APP_DOCUMENT_MAX_BYTES,
          null,
          false,
          null,
          "deterministic_outbox_json_with_signed_message_entries",
          ContentFormatVersionPolicy.CONSERVATIVE_V1,
          null);

  private static final List<ContentFormatProfile> PROFILES =
      List.of(PROFILE_DOCUMENT, FEED_SNAPSHOT, TRUST_STATEMENT, SOCIAL_MESSAGE, SOCIAL_OUTBOX);

  private static final Map<String, ContentFormatProfile> BY_ID =
      Map.of(
          PROFILE_DOCUMENT.id(),
          PROFILE_DOCUMENT,
          FEED_SNAPSHOT.id(),
          FEED_SNAPSHOT,
          TRUST_STATEMENT.id(),
          TRUST_STATEMENT,
          SOCIAL_MESSAGE.id(),
          SOCIAL_MESSAGE,
          SOCIAL_OUTBOX.id(),
          SOCIAL_OUTBOX);

  private ContentFormatProfileRegistry() {}

  /**
   * Returns all registered first-party content profiles in deterministic order.
   *
   * @return immutable registry profile list
   */
  public static List<ContentFormatProfile> profiles() {
    return PROFILES;
  }

  /**
   * Looks up one profile by canonical id.
   *
   * @param id content profile id or document type
   * @return profile descriptor when registered
   */
  @SuppressWarnings("unused")
  public static Optional<ContentFormatProfile> findById(String id) {
    return Optional.ofNullable(BY_ID.get(id));
  }
}
