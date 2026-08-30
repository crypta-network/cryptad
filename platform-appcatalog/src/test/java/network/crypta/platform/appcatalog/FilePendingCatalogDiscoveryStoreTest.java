package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import network.crypta.platform.appdist.TrustedAppKeyLifecycle;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilePendingCatalogDiscoveryStoreTest {
  private static final String ENDORSEMENT_ID = "endorsement-one";
  private static final String PENDING_DIRECTORY = "pending";
  private static final String SECOND_DESCRIPTOR_ID = "descriptor-second";

  @TempDir Path temporaryDirectory;

  @Test
  void importRecommendation_whenDocumentsAreCoherent_expectPendingRestartSafeRecord()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    CatalogEndorsement endorsement = coherentEndorsement(keyPair, descriptor);
    Path root = temporaryDirectory.resolve(PENDING_DIRECTORY);

    PendingCatalogDiscoveryRecommendation imported =
        new FilePendingCatalogDiscoveryStore(root)
            .importRecommendation(
                descriptor.canonicalDocumentBytes(),
                List.of(endorsement.canonicalDocumentBytes()),
                TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
                CatalogSignedDocumentTestSupport.NOW);
    PendingCatalogDiscoveryRecommendation restarted =
        new FilePendingCatalogDiscoveryStore(root).find(imported.descriptorId()).orElseThrow();

    assertEquals(imported, restarted);
    assertEquals("independent-beta", restarted.catalogId());
    assertEquals(1, restarted.endorsementVerifications().size());
    assertTrue(restarted.endorsementVerifications().getFirst().activeContribution());
    assertFalse(PendingCatalogDiscoveryRecommendation.TRUST_GRANTED);
    assertFalse(PendingCatalogDiscoveryRecommendation.SOURCE_CONFIGURED);
    assertFalse(PendingCatalogDiscoveryRecommendation.TRANSITIVE);
    assertFalse(restarted.toString().contains("https://"));
    assertFalse(restarted.toString().contains("valueBase64"));
  }

  @Test
  void importRecommendation_whenEndorsementNamesAnotherDescriptor_expectNothingPersisted()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    CatalogEndorsement endorsement =
        CatalogSignedDocumentTestSupport.signedEndorsement(
            keyPair,
            descriptor.catalogId(),
            descriptor.content().subject().signerFingerprintSha256(),
            "f".repeat(64),
            "endorsement-mismatch");
    FilePendingCatalogDiscoveryStore store =
        new FilePendingCatalogDiscoveryStore(temporaryDirectory.resolve(PENDING_DIRECTORY));
    byte[] descriptorBytes = descriptor.canonicalDocumentBytes();
    List<byte[]> endorsementBytes = List.of(endorsement.canonicalDocumentBytes());
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    assertThrows(
        AppCatalogException.class,
        () ->
            store.importRecommendation(
                descriptorBytes,
                endorsementBytes,
                trustedKeys,
                CatalogSignedDocumentTestSupport.NOW));
    assertTrue(store.list().isEmpty());
  }

  @Test
  void find_whenEnvelopeDigestIsSubstituted_expectClosedReadFails() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    Path root = temporaryDirectory.resolve(PENDING_DIRECTORY);
    FilePendingCatalogDiscoveryStore store = new FilePendingCatalogDiscoveryStore(root);
    store.importRecommendation(
        descriptor.canonicalDocumentBytes(),
        List.of(),
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
        CatalogSignedDocumentTestSupport.NOW);
    Path recordFile = firstFile(root);
    String substituted =
        Files.readString(recordFile, StandardCharsets.UTF_8)
            .replaceFirst(
                "\"selfDigestSha256\":\"[0-9a-f]{64}\"",
                "\"selfDigestSha256\":\"" + "0".repeat(64) + "\"");
    Files.writeString(recordFile, substituted, StandardCharsets.UTF_8);
    String descriptorId = descriptor.content().descriptorId();

    assertThrows(AppCatalogException.class, () -> store.find(descriptorId));
  }

  @Test
  void list_whenRecordContainsUnknownField_expectClosedReadFails() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    Path root = temporaryDirectory.resolve(PENDING_DIRECTORY);
    FilePendingCatalogDiscoveryStore store = new FilePendingCatalogDiscoveryStore(root);
    store.importRecommendation(
        descriptor.canonicalDocumentBytes(),
        List.of(),
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
        CatalogSignedDocumentTestSupport.NOW);
    Path recordFile = firstFile(root);
    String unknown =
        Files.readString(recordFile, StandardCharsets.UTF_8)
            .replaceFirst("\\{", "{\"trusted\":true,");
    Files.writeString(recordFile, unknown, StandardCharsets.UTF_8);

    assertThrows(AppCatalogException.class, store::list);
  }

  @Test
  void importRecommendation_whenStoreIsAtLimit_expectExistingRecordRemainsUnchanged()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    FilePendingCatalogDiscoveryStore store =
        new FilePendingCatalogDiscoveryStore(temporaryDirectory.resolve(PENDING_DIRECTORY), 1);
    PendingCatalogDiscoveryRecommendation first =
        store.importRecommendation(
            descriptor.canonicalDocumentBytes(),
            List.of(),
            TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
            CatalogSignedDocumentTestSupport.NOW);
    CatalogDiscoveryDescriptor second = descriptorWithId(keyPair);
    byte[] descriptorBytes = second.canonicalDocumentBytes();
    List<byte[]> endorsements = List.of();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    assertThrows(
        AppCatalogException.class,
        () ->
            store.importRecommendation(
                descriptorBytes, endorsements, trustedKeys, CatalogSignedDocumentTestSupport.NOW));
    assertEquals(List.of(first), store.list());
  }

  @Test
  void discard_whenTwoRecommendationsExist_expectOnlyRequestedEvidenceIsRemoved() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor first = CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    CatalogDiscoveryDescriptor second = descriptorWithId(keyPair);
    TrustedAppKeys keys = TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));
    FilePendingCatalogDiscoveryStore store =
        new FilePendingCatalogDiscoveryStore(temporaryDirectory.resolve(PENDING_DIRECTORY));
    store.importRecommendation(
        first.canonicalDocumentBytes(), List.of(), keys, CatalogSignedDocumentTestSupport.NOW);
    PendingCatalogDiscoveryRecommendation retained =
        store.importRecommendation(
            second.canonicalDocumentBytes(), List.of(), keys, CatalogSignedDocumentTestSupport.NOW);

    assertTrue(store.discard(first.content().descriptorId()));

    assertTrue(store.find(first.content().descriptorId()).isEmpty());
    assertEquals(List.of(retained), store.list());
    assertFalse(store.discard(first.content().descriptorId()));
  }

  @Test
  void importRecommendation_whenEndorsementCountExceedsLimit_expectRejectedBeforeWrite()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    byte[] placeholder = coherentEndorsement(keyPair, descriptor).canonicalDocumentBytes();
    List<byte[]> oversized =
        java.util.stream.IntStream.rangeClosed(
                0, PendingCatalogDiscoveryRecommendation.MAX_ENDORSEMENTS)
            .mapToObj(ignored -> placeholder)
            .toList();
    FilePendingCatalogDiscoveryStore store =
        new FilePendingCatalogDiscoveryStore(temporaryDirectory.resolve(PENDING_DIRECTORY));
    byte[] descriptorBytes = descriptor.canonicalDocumentBytes();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    assertThrows(
        AppCatalogException.class,
        () ->
            store.importRecommendation(
                descriptorBytes, oversized, trustedKeys, CatalogSignedDocumentTestSupport.NOW));
    assertTrue(store.list().isEmpty());
  }

  @Test
  void importRecommendation_whenEndorsementIdIsDuplicated_expectRejectedWithoutTraversal()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    byte[] endorsement = coherentEndorsement(keyPair, descriptor).canonicalDocumentBytes();
    FilePendingCatalogDiscoveryStore store =
        new FilePendingCatalogDiscoveryStore(temporaryDirectory.resolve(PENDING_DIRECTORY));
    byte[] descriptorBytes = descriptor.canonicalDocumentBytes();
    List<byte[]> endorsements = List.of(endorsement, endorsement);
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    assertThrows(
        AppCatalogException.class,
        () ->
            store.importRecommendation(
                descriptorBytes, endorsements, trustedKeys, CatalogSignedDocumentTestSupport.NOW));
    assertTrue(store.list().isEmpty());
  }

  @Test
  void reverifyEndorsements_whenIssuerIsRevoked_expectOnlyContributionBecomesInactive()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    PendingCatalogDiscoveryRecommendation recommendation =
        new FilePendingCatalogDiscoveryStore(temporaryDirectory.resolve(PENDING_DIRECTORY))
            .importRecommendation(
                descriptor.canonicalDocumentBytes(),
                List.of(coherentEndorsement(keyPair, descriptor).canonicalDocumentBytes()),
                TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
                CatalogSignedDocumentTestSupport.NOW);
    TrustedAppKeys revoked =
        TrustedAppKeys.ofPolicies(
            new TrustedAppKeyPolicy(
                CatalogSignedDocumentTestSupport.trustedKey(keyPair),
                TrustedAppKeyLifecycle.REVOKED,
                Instant.MIN,
                Instant.MAX));

    CatalogEndorsementVerification reverified =
        recommendation
            .reverifyEndorsements(revoked, CatalogSignedDocumentTestSupport.NOW)
            .getFirst();

    assertEquals(CatalogEndorsementVerification.Status.INACTIVE_ISSUER, reverified.status());
    assertFalse(reverified.activeContribution());
    assertFalse(CatalogEndorsementVerification.TRUST_GRANTED);
    assertEquals("independent-beta", recommendation.catalogId());
  }

  @Test
  void importRecommendation_whenStoreRootIsSymlink_expectRejected() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    Path actual = Files.createDirectory(temporaryDirectory.resolve("actual"));
    Path linked = Files.createSymbolicLink(temporaryDirectory.resolve("linked"), actual);

    FilePendingCatalogDiscoveryStore store = new FilePendingCatalogDiscoveryStore(linked);
    byte[] descriptorBytes = descriptor.canonicalDocumentBytes();
    List<byte[]> endorsements = List.of();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    assertThrows(
        AppCatalogException.class,
        () ->
            store.importRecommendation(
                descriptorBytes, endorsements, trustedKeys, CatalogSignedDocumentTestSupport.NOW));
    assertTrue(isDirectoryEmpty(actual));
  }

  private static CatalogEndorsement coherentEndorsement(
      KeyPair keyPair, CatalogDiscoveryDescriptor descriptor) throws Exception {
    return CatalogSignedDocumentTestSupport.signedEndorsement(
        keyPair,
        descriptor.catalogId(),
        descriptor.content().subject().signerFingerprintSha256(),
        descriptor.authentication().selfDigestSha256(),
        ENDORSEMENT_ID);
  }

  private static Path firstFile(Path directory) throws IOException {
    try (var files = Files.list(directory)) {
      return files.findFirst().orElseThrow();
    }
  }

  private static boolean isDirectoryEmpty(Path directory) throws IOException {
    try (var files = Files.list(directory)) {
      return files.findAny().isEmpty();
    }
  }

  private static CatalogDiscoveryDescriptor descriptorWithId(KeyPair keyPair) throws Exception {
    CatalogDiscoveryDescriptor existing =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    CatalogDiscoveryDescriptor.Content content =
        new CatalogDiscoveryDescriptor.Content(
            existing.content().schemaVersion(),
            SECOND_DESCRIPTOR_ID,
            existing.content().subject(),
            existing.content().display(),
            existing.content().transparency(),
            existing.content().validity(),
            existing.content().issuer());
    return CatalogSignedDocumentTestSupport.signDescriptor(keyPair, content);
  }
}
