package network.crypta.platform.api.contentformats;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import network.crypta.platform.api.content.ContentFetchPolicy;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ContentFormatProfileRegistryTest {
  @Test
  void profiles_whenListed_expectAllFirstPartyFormatDescriptorsInStableOrder() {
    List<ContentFormatProfile> profiles = ContentFormatProfileRegistry.profiles();

    assertEquals(
        List.of(
            "crypta.profile.v1",
            "crypta.feed.snapshot.v1",
            "crypta.trust.statement.v1",
            "crypta.social.message.v1",
            "crypta.social.outbox.v1"),
        profiles.stream().map(ContentFormatProfile::id).toList());
    assertEquals(5, profiles.stream().map(ContentFormatProfile::id).distinct().count());
    assertTrue(profiles.stream().allMatch(profile -> profile.majorVersion() == 1));
    assertTrue(
        profiles.stream()
            .allMatch(
                profile ->
                    "reject_unknown_fields".equals(profile.versionPolicy().unknownFieldPolicy())));
  }

  @Test
  void profiles_whenMappedById_expectMimeFilenameSigningAndBounds() {
    Map<String, ContentFormatProfile> byId =
        ContentFormatProfileRegistry.profiles().stream()
            .collect(Collectors.toUnmodifiableMap(ContentFormatProfile::id, profile -> profile));

    assertProfile(
        byId.get("crypta.profile.v1"),
        "application/vnd.crypta.profile+json",
        "profile.json",
        true,
        "profile.publish.v1",
        32 * 1024);
    assertProfile(
        byId.get("crypta.feed.snapshot.v1"),
        "application/vnd.crypta.feed+json",
        "feed.json",
        false,
        null,
        null);
    assertProfile(
        byId.get("crypta.trust.statement.v1"),
        "application/vnd.crypta.trust+json",
        "trust.json",
        true,
        "crypta.trust.statement.v1",
        32 * 1024);
    assertProfile(
        byId.get("crypta.social.message.v1"),
        "application/json",
        null,
        true,
        "crypta.social.message.v1",
        32 * 1024);
    assertProfile(
        byId.get("crypta.social.outbox.v1"),
        "application/vnd.crypta.social.outbox+json",
        "social-outbox.json",
        false,
        null,
        null);
  }

  @Test
  void trustDocumentTypes_whenComparedWithRegistry_expectNoIdentifierDrift() {
    ContentFormatProfile profile = ContentFormatProfileRegistry.TRUST_STATEMENT;

    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_V1, profile.id());
    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_V1, profile.signingDomain());
    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_CONTENT_TYPE, profile.contentType());
    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_FILENAME, profile.defaultFilename());
  }

  @Test
  void
      contentFetchPolicy_whenComparedWithRegistry_expectDefaultFetchCoversGeneratedProfileBounds() {
    assertEquals(
        ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES,
        ContentFormatProfileRegistry.FETCHED_DOCUMENT_MAX_BYTES);
    assertEquals(
        ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES,
        ContentFormatProfileRegistry.FEED_SNAPSHOT.maxDocumentBytes());
    assertEquals(
        ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES,
        ContentFormatProfileRegistry.SOCIAL_OUTBOX.maxDocumentBytes());
    assertTrue(
        ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES
            >= ContentFormatProfileRegistry.FEED_SNAPSHOT.maxDocumentBytes());
    assertTrue(
        ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES
            >= ContentFormatProfileRegistry.SOCIAL_OUTBOX.maxDocumentBytes());
  }

  @Test
  void validateMetadata_whenOversizedFutureOrDeprecated_expectRedactionSafeOutcomes() {
    ContentFormatProfile profile = ContentFormatProfileRegistry.SOCIAL_OUTBOX;

    ContentFormatValidationResult oversized =
        profile.validateMetadata(profile.id(), profile.maxDocumentBytes() + 1L);
    ContentFormatValidationResult future =
        profile.validateMetadata("crypta.social.outbox.v2", 1024);
    ContentFormatProfile deprecated =
        new ContentFormatProfile(
            "crypta.example.v1",
            1,
            "application/json",
            "example.json",
            ContentFormatProfileStatus.DEPRECATED,
            1024,
            null,
            false,
            null,
            "deterministic_json",
            ContentFormatVersionPolicy.CONSERVATIVE_V1,
            "crypta.example.v2");

    assertFalse(oversized.accepted());
    assertEquals("oversized_document", oversized.errors().getFirst().code());
    assertFalse(future.accepted());
    assertEquals("unsupported_version", future.errors().getFirst().code());
    ContentFormatValidationResult deprecatedResult =
        deprecated.validateMetadata(deprecated.id(), 1);
    assertTrue(deprecatedResult.accepted());
    assertEquals("deprecated_version", deprecatedResult.warnings().getFirst().code());
    assertFalse(deprecatedResult.toString().contains("{\"type\""));
    assertFalse(deprecatedResult.toString().contains("signatureBase64"));
  }

  private static void assertProfile(
      ContentFormatProfile profile,
      String contentType,
      String defaultFilename,
      boolean signed,
      String signingDomain,
      Integer maxSignedPayloadBytes) {
    assertEquals(contentType, profile.contentType());
    assertEquals(defaultFilename, profile.defaultFilename());
    assertEquals(signed, profile.signed());
    assertEquals(signingDomain, profile.signingDomain());
    assertEquals(
        ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES, profile.maxDocumentBytes());
    assertEquals(maxSignedPayloadBytes, profile.maxSignedPayloadBytes());
  }
}
