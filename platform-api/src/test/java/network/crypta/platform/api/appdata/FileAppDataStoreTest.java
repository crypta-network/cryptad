package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileAppDataStoreTest {
  private static final String APP_ID = "feed-reader";
  private static final String UI_STATE_NAMESPACE = "ui-state";
  private static final String SETTINGS_KEY = "settings";
  private static final String TEXT_PLAIN = "text/plain";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");

  @TempDir private Path tempDir;

  @Test
  void writeRecord_whenStoreReopened_expectDurableRecordAndNamespaceTotals() throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(
                "application/json", 1, "{\"theme\":\"dark\"}".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);

    store.writeNamespace(
        new AppDataNamespaceMetadata(
            APP_ID, UI_STATE_NAMESPACE, 1, 0, 0L, NOW, NOW, null, List.of()));
    store.writeRecord(appDataRecord);
    FileAppDataStore reopened = new FileAppDataStore(tempDir);

    AppDataRecord restored =
        reopened.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).orElseThrow();

    assertEquals("{\"theme\":\"dark\"}", new String(restored.value(), StandardCharsets.UTF_8));
    assertEquals(1, reopened.listNamespaces(APP_ID).getFirst().recordCount());
    assertFalse(allRelativePaths().contains(SETTINGS_KEY));
  }

  @Test
  void readNamespace_whenNamespaceMetadataNewerThanRecords_expectMetadataUpdatedAtPreserved()
      throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    Instant recordUpdatedAt = NOW.plusSeconds(10);
    Instant metadataUpdatedAt = NOW.plusSeconds(20);
    store.writeNamespace(
        new AppDataNamespaceMetadata(
            APP_ID,
            UI_STATE_NAMESPACE,
            2,
            0,
            0L,
            NOW,
            metadataUpdatedAt,
            metadataUpdatedAt,
            List.of(new AppDataMigrationRecord(1, 2, "schema update", metadataUpdatedAt))));
    store.writeRecord(
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(
                TEXT_PLAIN, 1, "older-record".getBytes(StandardCharsets.UTF_8)),
            NOW,
            recordUpdatedAt));

    AppDataNamespaceMetadata metadata =
        store.readNamespace(APP_ID, UI_STATE_NAMESPACE).orElseThrow();

    assertEquals(metadataUpdatedAt, metadata.updatedAt());
    assertEquals(metadataUpdatedAt, metadata.lastMigrationAt());
    assertEquals(1, metadata.recordCount());
  }

  @Test
  void writeRecord_whenUnreferencedGenerationExists_expectCurrentRecordUnaffected()
      throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "committed".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);
    store.writeRecord(appDataRecord);
    Path strayGeneration;
    try (var stream =
        Files.find(tempDir, 8, (path, _) -> path.getFileName().toString().equals("generations"))) {
      strayGeneration = stream.findFirst().orElseThrow().resolve("g-stray");
    }
    Files.createDirectories(strayGeneration);
    Files.writeString(strayGeneration.resolve("value.bin"), "partial", StandardCharsets.UTF_8);

    AppDataRecord restored =
        store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).orElseThrow();

    assertEquals("committed", new String(restored.value(), StandardCharsets.UTF_8));
    assertEquals(1, store.listRecords(APP_ID, UI_STATE_NAMESPACE).size());
  }

  @Test
  void listRecordSummaries_whenValueHashDoesNotMatch_expectSummaryButRecordReadFailure()
      throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "one".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);
    store.writeNamespace(
        new AppDataNamespaceMetadata(
            APP_ID, UI_STATE_NAMESPACE, 1, 0, 0L, NOW, NOW, null, List.of()));
    store.writeRecord(appDataRecord);
    Files.writeString(findValueFile(), "two", StandardCharsets.UTF_8);

    AppDataRecordSummary summary = store.listRecordSummaries(APP_ID, UI_STATE_NAMESPACE).getFirst();

    assertEquals(SETTINGS_KEY, summary.key());
    assertEquals(3, summary.valueBytes());
    assertEquals(appDataRecord.sha256(), summary.sha256());
    assertThrows(
        IOException.class, () -> store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY));
    assertEquals(1, store.listNamespaces(APP_ID).getFirst().recordCount());
  }

  @Test
  void readRecord_whenCurrentValueFileIsTruncated_expectStoreFailure() throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    store.writeRecord(
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "one".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW));
    Files.writeString(findValueFile(), "x", StandardCharsets.UTF_8);

    IOException readFailure =
        assertThrows(
            IOException.class, () -> store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY));
    IOException summaryFailure =
        assertThrows(
            IOException.class, () -> store.listRecordSummaries(APP_ID, UI_STATE_NAMESPACE));

    assertFalse(readFailure.getMessage().contains(tempDir.toString()));
    assertFalse(summaryFailure.getMessage().contains(tempDir.toString()));
  }

  @Test
  void readRecord_whenTamperedValueExceedsConfiguredCap_expectRecordIgnoredBeforeValueReturned()
      throws Exception {
    FileAppDataStore store =
        new FileAppDataStore(tempDir, new AppDataStoreConfig(8, 16, 4, 4096, 4096, 8));
    store.writeRecord(
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "ok".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW));
    byte[] tampered = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    Files.write(findValueFile(), tampered);
    Path recordMetadata = findFile("record.properties");
    Properties properties = new Properties();
    try (var reader = Files.newBufferedReader(recordMetadata, StandardCharsets.UTF_8)) {
      properties.load(reader);
    }
    properties.setProperty("valueBytes", Integer.toString(tampered.length));
    properties.setProperty("sha256", AppDataRecord.sha256(tampered));
    try (var writer = Files.newBufferedWriter(recordMetadata, StandardCharsets.UTF_8)) {
      properties.store(writer, "tampered oversized metadata");
    }

    assertTrue(store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).isEmpty());
    assertTrue(store.listRecordSummaries(APP_ID, UI_STATE_NAMESPACE).isEmpty());
  }

  @Test
  void readNamespace_whenMetadataPropertiesExceedsCap_expectNamespaceIgnoredBeforeLoad()
      throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    store.writeNamespace(
        new AppDataNamespaceMetadata(
            APP_ID, UI_STATE_NAMESPACE, 1, 0, 0L, NOW, NOW, null, List.of()));
    Files.writeString(findFile("metadata.properties"), oversizedPropertiesText());

    assertTrue(store.readNamespace(APP_ID, UI_STATE_NAMESPACE).isEmpty());
    assertTrue(store.listNamespaces(APP_ID).isEmpty());
  }

  @Test
  void readRecord_whenPointerOrRecordPropertiesExceedCap_expectRecordIgnoredBeforeLoad()
      throws Exception {
    for (String fileName : List.of("current.properties", "record.properties")) {
      Path root = tempDir.resolve(fileName.replace(".properties", ""));
      FileAppDataStore store = new FileAppDataStore(root);
      store.writeRecord(
          new AppDataRecord(
              APP_ID,
              UI_STATE_NAMESPACE,
              SETTINGS_KEY,
              new AppDataRecord.Payload(TEXT_PLAIN, 1, "ok".getBytes(StandardCharsets.UTF_8)),
              NOW,
              NOW));
      Files.writeString(findFile(root, fileName), oversizedPropertiesText());

      assertTrue(store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).isEmpty());
      assertTrue(store.listRecordSummaries(APP_ID, UI_STATE_NAMESPACE).isEmpty());
    }
  }

  @Test
  void readRecord_whenPlainPathFallbackForced_expectDurableRecordRead() throws Exception {
    AppDataStoreConfig config = new AppDataStoreConfig(128, 16, 4, 4096, 4096, 8);
    FileAppDataStore store = new FileAppDataStore(tempDir, config, true);
    store.writeRecord(
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "fallback".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW));

    AppDataRecord restored =
        store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).orElseThrow();

    assertEquals("fallback", new String(restored.value(), StandardCharsets.UTF_8));
  }

  @Test
  void readRecord_whenCurrentPointerCannotBeRead_expectIOException() throws Exception {
    FileAppDataStore store = new FileAppDataStore(tempDir);
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "one".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);
    store.writeRecord(appDataRecord);
    Path currentPointer = findFile("current.properties");
    Assumptions.assumeTrue(makeUnreadable(currentPointer));

    try {
      assertThrows(
          IOException.class, () -> store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY));
    } finally {
      assertTrue(
          currentPointer.toFile().setReadable(true, false) || Files.isReadable(currentPointer));
    }
  }

  @Test
  void writeRecord_whenAppDataStoreAncestorIsSymlink_expectWriteRejectedWithoutEscaping()
      throws Exception {
    Path outsideTarget = tempDir.resolve("outside-target");
    Files.createDirectories(outsideTarget);
    Path appDataDirectory = tempDir.resolve(APP_ID);
    Files.createDirectories(appDataDirectory);
    Assumptions.assumeTrue(
        createSymlink(appDataDirectory.resolve(".cryptad-app-data"), outsideTarget));
    FileAppDataStore store = new FileAppDataStore(tempDir);
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "blocked".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);

    assertThrows(IOException.class, () -> store.writeRecord(appDataRecord));

    assertFalse(Files.exists(outsideTarget.resolve("namespaces"), LinkOption.NOFOLLOW_LINKS));
  }

  @Test
  void writeRecord_whenConfiguredRootIsSymlink_expectWriteAllowedUnderResolvedRoot()
      throws Exception {
    Path realRoot = tempDir.resolve("real-app-data-root");
    Files.createDirectories(realRoot);
    Path linkedRoot = tempDir.resolve("operator-app-data-link");
    Assumptions.assumeTrue(createSymlink(linkedRoot, realRoot));
    FileAppDataStore store = new FileAppDataStore(linkedRoot);
    AppDataRecord appDataRecord =
        new AppDataRecord(
            APP_ID,
            UI_STATE_NAMESPACE,
            SETTINGS_KEY,
            new AppDataRecord.Payload(TEXT_PLAIN, 1, "allowed".getBytes(StandardCharsets.UTF_8)),
            NOW,
            NOW);

    store.writeRecord(appDataRecord);

    AppDataRecord restored =
        store.readRecord(APP_ID, UI_STATE_NAMESPACE, SETTINGS_KEY).orElseThrow();
    assertEquals("allowed", new String(restored.value(), StandardCharsets.UTF_8));
    assertTrue(
        Files.exists(
            realRoot.resolve(APP_ID).resolve(".cryptad-app-data"), LinkOption.NOFOLLOW_LINKS));
  }

  private String allRelativePaths() throws IOException {
    try (var stream = Files.walk(tempDir)) {
      return stream
          .map(path -> tempDir.relativize(path).toString())
          .sorted()
          .reduce("", (left, right) -> left + "\n" + right);
    }
  }

  private Path findValueFile() throws IOException {
    return findFile("value.bin");
  }

  private Path findFile(String fileName) throws IOException {
    return findFile(tempDir, fileName);
  }

  private static Path findFile(Path root, String fileName) throws IOException {
    try (var stream =
        Files.find(root, 10, (path, _) -> path.getFileName().toString().equals(fileName))) {
      return stream.findFirst().orElseThrow();
    }
  }

  private static String oversizedPropertiesText() {
    return "x=" + "a".repeat(70_000);
  }

  private static boolean makeUnreadable(Path path) {
    return path.toFile().setReadable(false, false) && !Files.isReadable(path);
  }

  private static boolean createSymlink(Path link, Path target) {
    try {
      Files.createSymbolicLink(link, target);
      return true;
    } catch (UnsupportedOperationException | IOException _) {
      return false;
    }
  }
}
