package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FederatedCatalogTrustStoreTest {
  private static final String TRUST_DIRECTORY = "trust";
  private static final String BINDING_A = "binding-a";
  private static final String BINDING_B = "binding-b";
  private static final String CATALOG_A = "catalog-a";
  private static final String CATALOG_B = "catalog-b";
  private static final String CATALOG_KEY_A = "catalog-key-a";
  private static final String FINGERPRINT = "1".repeat(64);

  @TempDir Path temporaryDirectory;

  @Test
  void put_whenBindingIsValid_expectRestartSafeRoundTrip() throws Exception {
    Path root = temporaryDirectory.resolve(TRUST_DIRECTORY);
    FederatedCatalogTrustBinding binding = binding(BINDING_A, CATALOG_A);

    new FileFederatedCatalogTrustStore(root).put(binding);

    FederatedCatalogTrustBinding loaded =
        new FileFederatedCatalogTrustStore(root).find(BINDING_A).orElseThrow();
    assertEquals(binding, loaded);
    assertTrue(loaded.authorizes(CATALOG_A, CATALOG_KEY_A, FINGERPRINT, AppCatalogChannel.BETA));
    assertFalse(loaded.authorizes(CATALOG_B, CATALOG_KEY_A, FINGERPRINT, AppCatalogChannel.BETA));
  }

  @Test
  void find_whenSelfDigestIsSubstituted_expectRejected() throws Exception {
    Path root = temporaryDirectory.resolve(TRUST_DIRECTORY);
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    store.put(binding(BINDING_A, CATALOG_A));
    Path bindingRecord = root.resolve(BINDING_A + ".properties");
    Files.writeString(
        bindingRecord,
        Files.readString(bindingRecord)
            .replaceFirst("selfDigest=[0-9a-f]{64}", "selfDigest=" + "0".repeat(64)));

    assertThrows(AppCatalogException.class, () -> store.find(BINDING_A));
  }

  @Test
  void findByCatalogId_whenAnotherCatalogRecordIsCorrupt_expectScopedIsolation() throws Exception {
    Path root = temporaryDirectory.resolve("trust-isolation");
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    FederatedCatalogTrustBinding catalogA = binding(BINDING_A, CATALOG_A);
    store.put(catalogA);
    store.put(binding(BINDING_B, CATALOG_B));
    Path catalogBRecord = root.resolve(BINDING_B + ".properties");
    Files.writeString(
        catalogBRecord,
        Files.readString(catalogBRecord).replace("reason=operator approval", "reason=changed"));

    assertEquals(catalogA, store.findByCatalogId(CATALOG_A).orElseThrow());
    assertThrows(AppCatalogException.class, () -> store.findByCatalogId(CATALOG_B));
    assertThrows(AppCatalogException.class, store::list);
  }

  @Test
  void findByCatalogId_whenUnrelatedRecordIsOversized_expectScopedIsolation() throws Exception {
    Path root = temporaryDirectory.resolve("trust-oversized-isolation");
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    FederatedCatalogTrustBinding catalogA = binding(BINDING_A, CATALOG_A);
    store.put(catalogA);
    Files.writeString(
        root.resolve("unrelated.properties"),
        "catalogId=catalog-b\nreason=" + "x".repeat(65 * 1024));

    assertEquals(catalogA, store.findByCatalogId(CATALOG_A).orElseThrow());
    assertThrows(AppCatalogException.class, store::list);
  }

  @Test
  void findByCatalogId_whenUnrelatedRecordIsSymlink_expectScopedIsolation() throws Exception {
    Path root = temporaryDirectory.resolve("trust-symlink-isolation");
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    FederatedCatalogTrustBinding catalogA = binding(BINDING_A, CATALOG_A);
    store.put(catalogA);
    Path outside = temporaryDirectory.resolve("outside.properties");
    Files.writeString(outside, "catalogId=catalog-b\n");
    Files.createSymbolicLink(root.resolve("unrelated.properties"), outside);

    assertEquals(catalogA, store.findByCatalogId(CATALOG_A).orElseThrow());
    assertThrows(AppCatalogException.class, store::list);
  }

  @Test
  void put_whenTwoBindingsUseOneCatalogId_expectRejected() throws Exception {
    Path root = temporaryDirectory.resolve(TRUST_DIRECTORY);
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    store.put(binding(BINDING_A, CATALOG_A));
    FederatedCatalogTrustBinding duplicateCatalog = binding(BINDING_B, CATALOG_A);

    assertThrows(AppCatalogException.class, () -> store.put(duplicateCatalog));
  }

  @Test
  void put_whenBindingIdMovesToAnotherCatalog_expectRejectedAndOriginalRetained() throws Exception {
    Path root = temporaryDirectory.resolve("trust-moving-id");
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    FederatedCatalogTrustBinding original = binding(BINDING_A, CATALOG_A);
    store.put(original);
    FederatedCatalogTrustBinding movedBinding = binding(BINDING_A, CATALOG_B);

    assertThrows(AppCatalogException.class, () -> store.put(movedBinding));
    assertEquals(original, store.find(BINDING_A).orElseThrow());
  }

  @Test
  void put_whenCatalogAIsRevoked_expectCatalogBUnchanged() throws Exception {
    Path root = temporaryDirectory.resolve(TRUST_DIRECTORY);
    FileFederatedCatalogTrustStore store = new FileFederatedCatalogTrustStore(root);
    FederatedCatalogTrustBinding catalogA = binding(BINDING_A, CATALOG_A);
    FederatedCatalogTrustBinding catalogB = binding(BINDING_B, CATALOG_B);
    store.put(catalogA);
    store.put(catalogB);

    store.put(
        replacement(
            catalogA,
            FederatedCatalogTrustBinding.Status.REVOKED,
            catalogA.updatedAt().plusSeconds(1)));

    assertEquals(catalogB, store.find(BINDING_B).orElseThrow());
  }

  @Test
  void put_whenRevokedBindingIsReplaced_expectTerminalStatusRetained() throws Exception {
    FileFederatedCatalogTrustStore store =
        new FileFederatedCatalogTrustStore(temporaryDirectory.resolve("trust-terminal-revocation"));
    FederatedCatalogTrustBinding active = binding(BINDING_A, CATALOG_A);
    FederatedCatalogTrustBinding revoked =
        replacement(
            active, FederatedCatalogTrustBinding.Status.REVOKED, active.updatedAt().plusSeconds(1));
    store.put(active);
    store.put(revoked);
    FederatedCatalogTrustBinding reactivated =
        replacement(
            revoked,
            FederatedCatalogTrustBinding.Status.ACTIVE,
            revoked.updatedAt().plusSeconds(1));
    FederatedCatalogTrustBinding suspended =
        replacement(
            revoked,
            FederatedCatalogTrustBinding.Status.SUSPENDED,
            revoked.updatedAt().plusSeconds(1));

    assertThrows(AppCatalogException.class, () -> store.put(reactivated));
    assertThrows(AppCatalogException.class, () -> store.put(suspended));
    assertEquals(revoked, store.find(BINDING_A).orElseThrow());
  }

  @Test
  void put_whenReplacementChangesCreatedAt_expectAuditHistoryRetained() throws Exception {
    FileFederatedCatalogTrustStore store =
        new FileFederatedCatalogTrustStore(temporaryDirectory.resolve("trust-created-at"));
    FederatedCatalogTrustBinding original = binding(BINDING_A, CATALOG_A);
    store.put(original);
    FederatedCatalogTrustBinding rewritten =
        FederatedCatalogTrustBinding.create(
            original.bindingId(),
            original.catalogId(),
            original.signerFingerprints(),
            original.status(),
            original.allowedChannels(),
            original.localPriority(),
            original.discoveryProvenanceDigest().orElse(null),
            original.reviewerPolicyDigest().orElse(null),
            original.publisherPolicyDigest().orElse(null),
            original.createdAt().plusSeconds(1),
            original.updatedAt().plusSeconds(1),
            "rewritten audit history",
            "operator");

    assertThrows(AppCatalogException.class, () -> store.put(rewritten));
    assertEquals(original, store.find(BINDING_A).orElseThrow());
  }

  @Test
  void requireStoredBinding_whenExactBindingPersisted_expectAccepted() throws IOException {
    FileFederatedCatalogTrustStore store =
        new FileFederatedCatalogTrustStore(temporaryDirectory.resolve(TRUST_DIRECTORY));
    FederatedCatalogTrustBinding binding = binding(BINDING_A, CATALOG_A);
    store.put(binding);
    StoredCatalogSource storedSource = stored(binding.selfDigest());

    assertDoesNotThrow(() -> AppCatalogTrustVerification.requireStoredBinding(storedSource, store));
  }

  @Test
  void requireStoredBinding_whenPolicyDigestChanges_expectExplicitReapprovalRequired()
      throws Exception {
    FileFederatedCatalogTrustStore store =
        new FileFederatedCatalogTrustStore(temporaryDirectory.resolve(TRUST_DIRECTORY));
    store.put(binding(BINDING_A, CATALOG_A));
    StoredCatalogSource staleSource = stored("0".repeat(64));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogTrustVerification.requireStoredBinding(staleSource, store));

    assertTrue(exception.getMessage().contains("explicit source re-approval"));
  }

  private static StoredCatalogSource stored(String bindingDigest) {
    AppCatalogSource source = AppCatalogSource.parse("https://example.invalid/catalog.properties");
    AppCatalogMirror primary = AppCatalogMirror.primary(source, Instant.EPOCH);
    return new StoredCatalogSource(
        CATALOG_A,
        source,
        Instant.EPOCH,
        Instant.EPOCH,
        AppCatalogSourceRefreshMetadata.success(Instant.EPOCH, source.resolvedCatalogFetchUri()),
        new FetchedCatalog(new byte[] {1}, new byte[] {2}),
        List.of(primary),
        Map.of(),
        Optional.of(BINDING_A),
        Optional.of(bindingDigest));
  }

  private static FederatedCatalogTrustBinding binding(String bindingId, String catalogId) {
    return FederatedCatalogTrustBinding.create(
        bindingId,
        catalogId,
        Map.of(CATALOG_KEY_A, catalogId.endsWith("a") ? FINGERPRINT : "2".repeat(64)),
        FederatedCatalogTrustBinding.Status.ACTIVE,
        Set.of(AppCatalogChannel.BETA),
        100,
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64),
        Instant.EPOCH,
        Instant.EPOCH,
        "operator approval",
        "operator");
  }

  private static FederatedCatalogTrustBinding replacement(
      FederatedCatalogTrustBinding binding,
      FederatedCatalogTrustBinding.Status status,
      Instant updatedAt) {
    return FederatedCatalogTrustBinding.create(
        binding.bindingId(),
        binding.catalogId(),
        binding.signerFingerprints(),
        status,
        binding.allowedChannels(),
        binding.localPriority(),
        binding.discoveryProvenanceDigest().orElse(null),
        binding.reviewerPolicyDigest().orElse(null),
        binding.publisherPolicyDigest().orElse(null),
        binding.createdAt(),
        updatedAt,
        "operator lifecycle update",
        "operator");
  }
}
