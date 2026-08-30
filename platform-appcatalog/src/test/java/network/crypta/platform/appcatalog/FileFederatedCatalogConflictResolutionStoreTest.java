package network.crypta.platform.appcatalog;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileFederatedCatalogConflictResolutionStoreTest {
  private static final String RESOLUTIONS_DIRECTORY = "resolutions";
  private static final String CATALOG_A = "catalog-a";
  private static final String APP_ID = "example-app";

  @TempDir Path temporaryDirectory;

  @Test
  void put_whenResolutionMatchesConflict_expectRestartSafeApplicableLookup() throws Exception {
    Path root = temporaryDirectory.resolve(RESOLUTIONS_DIRECTORY);
    FederatedCatalogConflictEngine.ConflictSet conflict = conflict("2");
    FederatedCatalogConflictEngine.Resolution resolution = resolution(conflict, CATALOG_A);

    new FileFederatedCatalogConflictResolutionStore(root).put(conflict, resolution);
    FileFederatedCatalogConflictResolutionStore.Lookup lookup =
        new FileFederatedCatalogConflictResolutionStore(root).lookup(conflict);

    assertEquals(
        FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE, lookup.status());
    assertTrue(lookup.applicable());
    assertEquals(resolution, lookup.resolution().orElseThrow());
    try (var files = Files.list(root)) {
      assertFalse(files.anyMatch(path -> path.getFileName().toString().endsWith(".tmp")));
    }
  }

  @Test
  void lookup_whenAnyConflictSubjectChanges_expectStoredDecisionReportedStale() throws Exception {
    Path root = temporaryDirectory.resolve(RESOLUTIONS_DIRECTORY);
    FederatedCatalogConflictEngine.ConflictSet original = conflict("2");
    FederatedCatalogConflictEngine.Resolution resolution = resolution(original, CATALOG_A);
    FileFederatedCatalogConflictResolutionStore store =
        new FileFederatedCatalogConflictResolutionStore(root);
    store.put(original, resolution);
    FederatedCatalogConflictEngine.ConflictSet changed = conflict("3");

    FileFederatedCatalogConflictResolutionStore.Lookup lookup = store.lookup(changed);

    assertEquals(FileFederatedCatalogConflictResolutionStore.LookupStatus.STALE, lookup.status());
    assertFalse(lookup.applicable());
    assertEquals(resolution, lookup.resolution().orElseThrow());
  }

  @Test
  void retainLookup_whenExactResolutionIsReplaced_expectWriterWaitsForCommitLease()
      throws Exception {
    Path root = temporaryDirectory.resolve("retained-resolutions");
    FederatedCatalogConflictEngine.ConflictSet conflict = conflict("2");
    FileFederatedCatalogConflictResolutionStore store =
        new FileFederatedCatalogConflictResolutionStore(root);
    FederatedCatalogConflictEngine.Resolution original = resolution(conflict, CATALOG_A);
    FederatedCatalogConflictEngine.Resolution replacement = resolution(conflict, "catalog-b");
    store.put(conflict, original);
    FileFederatedCatalogConflictResolutionStore.RetainedLookup retained =
        store.retainLookup(conflict);
    FileFederatedCatalogConflictResolutionStore independentWriter =
        new FileFederatedCatalogConflictResolutionStore(root);
    CompletableFuture<Void> replacementWrite =
        CompletableFuture.runAsync(
            () -> {
              try {
                independentWriter.put(conflict, replacement);
              } catch (Exception exception) {
                throw new AssertionError(exception);
              }
            });

    try {
      assertEquals(original, retained.lookup().resolution().orElseThrow());
      assertThrows(TimeoutException.class, () -> replacementWrite.get(100, TimeUnit.MILLISECONDS));
    } finally {
      retained.close();
    }
    replacementWrite.get(5, TimeUnit.SECONDS);

    assertEquals(
        replacement,
        new FileFederatedCatalogConflictResolutionStore(root)
            .lookup(conflict)
            .resolution()
            .orElseThrow());
  }

  @Test
  void put_whenResolutionBindsAnotherConflictSet_expectRejected() {
    FederatedCatalogConflictEngine.ConflictSet original = conflict("2");
    FederatedCatalogConflictEngine.ConflictSet changed = conflict("3");
    FederatedCatalogConflictEngine.Resolution resolution = resolution(original, CATALOG_A);
    FileFederatedCatalogConflictResolutionStore store =
        new FileFederatedCatalogConflictResolutionStore(
            temporaryDirectory.resolve(RESOLUTIONS_DIRECTORY));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> store.put(changed, resolution));

    assertEquals("invalid_catalog_conflict_resolution_store", exception.errorCode());
  }

  @Test
  void put_whenPinnedCatalogIsNotAConflictSubject_expectRejected() {
    FederatedCatalogConflictEngine.ConflictSet conflict = conflict("2");
    FederatedCatalogConflictEngine.Resolution resolution = resolution(conflict, "catalog-c");
    FileFederatedCatalogConflictResolutionStore store =
        new FileFederatedCatalogConflictResolutionStore(
            temporaryDirectory.resolve(RESOLUTIONS_DIRECTORY));

    assertThrows(AppCatalogException.class, () -> store.put(conflict, resolution));
  }

  @Test
  void find_whenRecordDigestIsSubstituted_expectRejected() throws Exception {
    Path root = temporaryDirectory.resolve(RESOLUTIONS_DIRECTORY);
    FederatedCatalogConflictEngine.ConflictSet conflict = conflict("2");
    FileFederatedCatalogConflictResolutionStore store =
        new FileFederatedCatalogConflictResolutionStore(root);
    store.put(conflict, resolution(conflict, CATALOG_A));
    Path recordPath;
    try (var files = Files.list(root)) {
      recordPath = files.findFirst().orElseThrow();
    }
    Files.writeString(
        recordPath,
        Files.readString(recordPath)
            .replaceFirst("recordSelfDigest=[0-9a-f]{64}", "recordSelfDigest=" + "0".repeat(64)));

    assertThrows(AppCatalogException.class, () -> store.find(APP_ID));
  }

  @Test
  void find_whenUnknownPropertyIsAdded_expectClosedParsingRejectsRecord() throws Exception {
    Path root = temporaryDirectory.resolve(RESOLUTIONS_DIRECTORY);
    FederatedCatalogConflictEngine.ConflictSet conflict = conflict("2");
    FileFederatedCatalogConflictResolutionStore store =
        new FileFederatedCatalogConflictResolutionStore(root);
    store.put(conflict, resolution(conflict, CATALOG_A));
    Path recordPath;
    try (var files = Files.list(root)) {
      recordPath = files.findFirst().orElseThrow();
    }
    Files.writeString(recordPath, Files.readString(recordPath) + "unsupported=value\n");

    assertThrows(AppCatalogException.class, () -> store.find(APP_ID));
  }

  private static FederatedCatalogConflictEngine.ConflictSet conflict(String catalogBBundleDigit) {
    return FederatedCatalogConflictEngine.classify(
            List.of(subject(CATALOG_A, "1"), subject("catalog-b", catalogBBundleDigit)))
        .orElseThrow();
  }

  private static FederatedCatalogConflictEngine.Resolution resolution(
      FederatedCatalogConflictEngine.ConflictSet conflict, String catalogId) {
    return new FederatedCatalogConflictEngine.Resolution(
        conflict.conflictId(),
        conflict.subjectSetDigest(),
        FederatedCatalogConflictEngine.ResolutionKind.PIN_CATALOG,
        Optional.of(catalogId),
        Optional.empty(),
        Instant.EPOCH,
        "operator chose an exact catalog subject",
        null);
  }

  private static FederatedCatalogConflictEngine.Subject subject(
      String catalogId, String bundleDigit) {
    return new FederatedCatalogConflictEngine.Subject(
        catalogId,
        "a".repeat(64),
        APP_ID,
        "1.0.0",
        bundleDigit.repeat(64),
        "zip",
        "5".repeat(64),
        "5".repeat(64),
        "b".repeat(64),
        "allow",
        "c".repeat(64));
  }
}
