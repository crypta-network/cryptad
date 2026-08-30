package network.crypta.platform.apphost;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileInstalledAppOriginStoreTest {
  private static final String APP_ID = "example.app";
  private static final String ORIGINS_DIRECTORY = "origins";
  private static final String ORIGIN_FILE_NAME = "example.app.properties";
  private static final String OUTSIDE_CONTENT = "outside";
  private static final String VERSION_ONE = "1.0.0";
  private static final String VERSION_TWO = "2.0.0";

  @TempDir Path temporaryDirectory;

  @Test
  void put_whenStoreReopens_expectCurrentOriginSurvivesRestart() throws Exception {
    Path root = temporaryDirectory.resolve(ORIGINS_DIRECTORY);
    InstalledAppOrigin origin = origin(VERSION_ONE, "1".repeat(64), null);

    new FileInstalledAppOriginStore(root).put(origin);

    assertEquals(origin, new FileInstalledAppOriginStore(root).find(APP_ID).orElseThrow());
  }

  @Test
  void put_whenValidatedValuesContainDelimiters_expectExactRecordSurvivesRestart()
      throws Exception {
    Path root = temporaryDirectory.resolve("origins-with-delimiters");
    InstalledAppOrigin origin =
        InstalledAppOrigin.create(
            APP_ID,
            "1=0=0",
            "1".repeat(64),
            "catalog-a",
            "catalog=key=a",
            "3".repeat(64),
            "4".repeat(64),
            "publisher=key=a",
            "5".repeat(64),
            "a".repeat(64),
            "6".repeat(64),
            "trusted_reviewed",
            "binding-catalog-a",
            "7".repeat(64),
            "8".repeat(64),
            "9".repeat(64),
            Instant.parse("2026-08-25T00:00:00Z"),
            null);

    new FileInstalledAppOriginStore(root).put(origin);
    InstalledAppOrigin reloaded = new FileInstalledAppOriginStore(root).find(APP_ID).orElseThrow();

    assertEquals(origin, reloaded);
    assertEquals(origin.selfDigestSha256(), reloaded.selfDigestSha256());
  }

  @Test
  void find_whenSchemaOneRecordLacksSignedContentIdentity_expectReadableLegacyRecord()
      throws Exception {
    Path root = temporaryDirectory.resolve("legacy-schema-origins");
    InstalledAppOrigin current = origin(VERSION_ONE, "1".repeat(64), null);
    InstalledAppOrigin legacy =
        new InstalledAppOrigin(
            InstalledAppOrigin.LEGACY_SCHEMA_VERSION,
            current.appId(),
            current.appVersion(),
            current.bundleSha256(),
            current.catalogId(),
            current.catalogSignerKeyId(),
            current.catalogSignerFingerprintSha256(),
            current.catalogRevisionDigestSha256(),
            current.publisherKeyId(),
            current.publisherKeyFingerprintSha256(),
            "",
            current.reviewReceiptFingerprintSha256(),
            current.reviewStatus(),
            current.catalogTrustBindingId(),
            current.catalogTrustBindingDigestSha256(),
            current.publisherPolicyDigestSha256(),
            current.reviewerPolicyDigestSha256(),
            current.installedAt(),
            current.previousOriginDigestSha256(),
            null);
    new FileInstalledAppOriginStore(root).put(legacy);

    InstalledAppOrigin restored = new FileInstalledAppOriginStore(root).find(APP_ID).orElseThrow();

    assertEquals(InstalledAppOrigin.LEGACY_SCHEMA_VERSION, restored.schemaVersion());
    assertEquals("", restored.signedContentDigestSha256());
    assertEquals(legacy, restored);
  }

  @Test
  void swapRollback_whenUpdateHasPriorOrigin_expectExactOriginsSwap() throws Exception {
    FileInstalledAppOriginStore store =
        new FileInstalledAppOriginStore(temporaryDirectory.resolve(ORIGINS_DIRECTORY));
    InstalledAppOrigin previous = origin(VERSION_ONE, "1".repeat(64), null);
    InstalledAppOrigin current = origin(VERSION_TWO, "2".repeat(64), previous.selfDigestSha256());
    store.put(previous);
    store.put(current);

    store.swapRollback(APP_ID);

    assertEquals(previous, store.find(APP_ID).orElseThrow());
    assertTrue(store.hasRollback(APP_ID));
  }

  @Test
  void swapRollback_whenPriorBundlePredatesProvenance_expectAbsenceSwapsExplicitly()
      throws Exception {
    FileInstalledAppOriginStore store =
        new FileInstalledAppOriginStore(temporaryDirectory.resolve("legacy-origins"));
    InstalledAppOrigin current = origin(VERSION_TWO, "2".repeat(64), null);
    store.put(current);

    store.swapRollback(APP_ID);
    assertTrue(store.find(APP_ID).isEmpty());
    assertTrue(store.hasRollback(APP_ID));

    store.swapRollback(APP_ID);
    assertEquals(current, store.find(APP_ID).orElseThrow());
  }

  @Test
  void find_whenSelfDigestChanges_expectRejected() throws Exception {
    Path root = temporaryDirectory.resolve(ORIGINS_DIRECTORY);
    FileInstalledAppOriginStore store = new FileInstalledAppOriginStore(root);
    store.put(origin(VERSION_ONE, "1".repeat(64), null));
    Path file = root.resolve(ORIGIN_FILE_NAME);
    Files.writeString(
        file,
        Files.readString(file)
            .replaceFirst("selfDigestSha256=[0-9a-f]{64}", "selfDigestSha256=" + "0".repeat(64)));

    assertThrows(AppHostException.class, () -> store.find(APP_ID));
  }

  @Test
  void remove_whenStoreRootIsSymlink_expectOutsideRecordPreserved() throws Exception {
    Path root = temporaryDirectory.resolve(ORIGINS_DIRECTORY);
    Path outside = temporaryDirectory.resolve("outside-current");
    Files.createDirectories(outside);
    Path outsideRecord = outside.resolve(ORIGIN_FILE_NAME);
    Files.writeString(outsideRecord, OUTSIDE_CONTENT);
    createSymbolicLink(root, outside);
    FileInstalledAppOriginStore store = new FileInstalledAppOriginStore(root);

    assertThrows(AppHostException.class, () -> store.remove(APP_ID));

    assertEquals(OUTSIDE_CONTENT, Files.readString(outsideRecord));
  }

  @Test
  void remove_whenRollbackRootIsSymlink_expectNoRecordDeleted() throws Exception {
    Path root = temporaryDirectory.resolve("origins-with-linked-rollback");
    FileInstalledAppOriginStore store = new FileInstalledAppOriginStore(root);
    store.put(origin(VERSION_ONE, "1".repeat(64), null));
    Path rollbackRoot = root.resolve("rollback");
    Files.delete(rollbackRoot);
    Path outside = temporaryDirectory.resolve("outside-rollback");
    Files.createDirectories(outside);
    Path outsideRecord = outside.resolve(ORIGIN_FILE_NAME);
    Files.writeString(outsideRecord, OUTSIDE_CONTENT);
    createSymbolicLink(rollbackRoot, outside);

    assertThrows(AppHostException.class, () -> store.remove(APP_ID));

    assertTrue(Files.exists(root.resolve(ORIGIN_FILE_NAME)));
    assertEquals(OUTSIDE_CONTENT, Files.readString(outsideRecord));
  }

  @Test
  void remove_whenRootsAreSafe_expectBothRecordsRemoved() throws Exception {
    Path root = temporaryDirectory.resolve("safe-remove");
    FileInstalledAppOriginStore store = new FileInstalledAppOriginStore(root);
    InstalledAppOrigin previous = origin(VERSION_ONE, "1".repeat(64), null);
    store.put(previous);
    store.put(origin(VERSION_TWO, "2".repeat(64), previous.selfDigestSha256()));

    store.remove(APP_ID);

    assertFalse(Files.exists(root.resolve(ORIGIN_FILE_NAME)));
    assertFalse(Files.exists(root.resolve("rollback/example.app.properties")));
  }

  private static void createSymbolicLink(Path link, Path target) {
    try {
      Files.createSymbolicLink(link, target.toAbsolutePath());
    } catch (UnsupportedOperationException | java.io.IOException exception) {
      org.junit.jupiter.api.Assumptions.assumeTrue(
          false, "symbolic links unavailable: " + exception.getMessage());
    }
  }

  private static InstalledAppOrigin origin(
      String version, String bundleDigest, String previousDigest) {
    return InstalledAppOrigin.create(
        APP_ID,
        version,
        bundleDigest,
        "catalog-a",
        "catalog-key-a",
        "3".repeat(64),
        "4".repeat(64),
        "publisher-key-a",
        "5".repeat(64),
        "a".repeat(64),
        "6".repeat(64),
        "trusted_reviewed",
        "binding-catalog-a",
        "7".repeat(64),
        "8".repeat(64),
        "9".repeat(64),
        Instant.parse("2026-08-25T00:00:00Z"),
        previousDigest);
  }
}
