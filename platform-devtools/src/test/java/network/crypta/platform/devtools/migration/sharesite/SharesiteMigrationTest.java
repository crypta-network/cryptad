package network.crypta.platform.devtools.migration.sharesite;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import network.crypta.platform.devtools.CryptaAppCli;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.*;

class SharesiteMigrationTest {
  private static final UUID OPERATION = UUID.fromString("26c8bd03-cd47-44aa-ae02-b0ba6e9308de");
  private static final String CANARY = "SYNTHETIC_SECRET_CANARY_DO_NOT_EXPORT";
  @TempDir Path temporary;

  @Test
  void decode_whenPinnedWriterFixture_expectExactLiteralAndSkippedSecret() throws Exception {
    byte[] fixture = fixture("upstream-mixed.db");
    Map<String, String> fields = SharesiteSnapshot.decode(fixture);
    assertEquals("<script>inert</script>\r\nα\n🙂\r", fields.get("collection-0/text"));
    assertEquals("", fields.get("collection-0/insertSSK"));
    assertEquals("0 2", fields.get("keys"));
    assertEquals("1", fields.get("deleted_keys"));
    byte[] converted = convert(fields, List.of(0));
    String json = new String(converted, StandardCharsets.UTF_8);
    assertFalse(json.contains(CANARY));
    assertTrue(json.contains("private-user-data"));
    assertTrue(json.contains("unsupported_textile"));
    assertTrue(json.contains("recently_deleted"));
    // Exact literal fidelity is asserted in the decoded inner record, not by record counts.
    String base64 = json.split("\"valueBase64\":\"", -1)[1].split("\"", -1)[0];
    String dataset =
        new String(java.util.Base64.getDecoder().decode(base64), StandardCharsets.UTF_8);
    assertTrue(dataset.contains("<script>inert</script>\\r\\nα\\n🙂\\r"));
    assertTrue(dataset.contains("\"logicalPath\":\"Synthetic page 0\""));
    assertFalse(dataset.contains(CANARY));
  }

  @Test
  void decode_whenEmptyWriterMap_expectEmptyDistinctFromMalformed() throws Exception {
    byte[] empty = fixture("upstream-empty.db");
    assertEquals("ShareWiki-db-ver1".getBytes(StandardCharsets.UTF_8).length + 4, empty.length);
    assertTrue(SharesiteSnapshot.decode(empty).isEmpty());
    assertThrows(IllegalArgumentException.class, () -> convert(Map.of(), List.of()));
    assertThrows(IOException.class, () -> SharesiteSnapshot.decode(new byte[0]));
  }

  @Test
  void decode_whenTruncatedAtEveryByte_expectFailureNotEmpty() throws Exception {
    byte[] valid = encode(validFields());
    for (int length = 0; length < valid.length; length++) {
      byte[] truncated = Arrays.copyOf(valid, length);
      assertThrows(
          IOException.class, () -> SharesiteSnapshot.decode(truncated), "length " + length);
    }
    byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
    assertThrows(IOException.class, () -> SharesiteSnapshot.decode(trailing));
  }

  @Test
  void decode_whenNegativeOrOverflowFraming_expectBoundedFailure() throws Exception {
    byte[] empty = fixture("upstream-empty.db");
    for (int size : new int[] {-1, Integer.MIN_VALUE, Integer.MAX_VALUE, 4097}) {
      byte[] changed = empty.clone();
      java.nio.ByteBuffer.wrap(changed).putInt(changed.length - 4, size);
      assertThrows(IOException.class, () -> SharesiteSnapshot.decode(changed));
    }
    byte[] value = encode(Map.of("key", "value"));
    java.nio.ByteBuffer.wrap(value).putInt(21, Integer.MAX_VALUE);
    assertThrows(IOException.class, () -> SharesiteSnapshot.decode(value));
  }

  @Test
  void decode_whenInvalidUtf8OrDuplicateKeys_expectFailure() throws Exception {
    byte[] invalid = encode(Map.of("key", "value"));
    invalid[invalid.length - 1] = (byte) 0xff;
    assertThrows(IOException.class, () -> SharesiteSnapshot.decode(invalid));
    byte[] secret = encode(Map.of("collection-0/insertSSK", "value"));
    secret[secret.length - 1] = (byte) 0xff;
    assertThrows(IOException.class, () -> SharesiteSnapshot.decode(secret));
    byte[] one = encode(Map.of("key", "value"));
    ByteArrayOutputStream duplicate = new ByteArrayOutputStream();
    duplicate.write(one);
    duplicate.write(one, 21, one.length - 21);
    byte[] bytes = duplicate.toByteArray();
    java.nio.ByteBuffer.wrap(bytes).putInt(17, 2);
    assertThrows(IOException.class, () -> SharesiteSnapshot.decode(bytes));
  }

  @Test
  void convert_whenMapOrderChanges_expectIdenticalPrivatePayload() {
    Map<String, String> fields = validFields();
    List<Map.Entry<String, String>> entries = new ArrayList<>(fields.entrySet());
    java.util.Collections.reverse(entries);
    Map<String, String> reversed = new LinkedHashMap<>();
    entries.forEach(entry -> reversed.put(entry.getKey(), entry.getValue()));
    assertArrayEquals(convert(fields, List.of(0)), convert(reversed, List.of(0)));
    fields.put("collection-0/text", "");
    assertNotNull(convert(fields, List.of(0)));
  }

  @Test
  void convert_whenAmbiguousOrMalformedMembership_expectFailure() {
    List<Integer> selectedIds = List.of(0);
    for (String ids : List.of("0 0", "-1", "2147483648", " 0", "0  ", "0\t1", "00", "1١")) {
      Map<String, String> fields = validFields();
      fields.put("keys", ids);
      assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
    }
    Map<String, String> overlap = validFields();
    overlap.put("deleted_keys", "0");
    assertThrows(IllegalArgumentException.class, () -> convert(overlap, selectedIds));
    Map<String, String> orphan = validFields();
    orphan.put("collection-5/name", "orphan");
    assertThrows(IllegalArgumentException.class, () -> convert(orphan, selectedIds));
  }

  @Test
  void convert_whenIdListIsLong_expectBoundedFailureWithoutStackOverflow() {
    Map<String, String> fields = validFields();
    List<Integer> selection = List.of(0);
    fields.put("keys", "1 ".repeat(20000) + "2");
    IllegalArgumentException oversized =
        assertThrows(IllegalArgumentException.class, () -> convert(fields, selection));
    assertEquals("sharesite_page_count_limit", oversized.getMessage());

    fields.put("keys", "1 ".repeat(20000) + "02");
    IllegalArgumentException malformed =
        assertThrows(IllegalArgumentException.class, () -> convert(fields, selection));
    assertEquals("sharesite_invalid_id_list", malformed.getMessage());
  }

  @Test
  void convert_whenUnsupportedOrBrokenSelectedRecord_expectExplicitFailure() {
    List<Integer> selectedIds = List.of(0);
    for (String value : List.of("false", "TRUE", "maybe")) {
      Map<String, String> fields = validFields();
      fields.put("collection-0/pastebin", value);
      assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
    }
    for (String field : List.of("pastebin", "text", "name", "edition")) {
      Map<String, String> fields = validFields();
      fields.remove("collection-0/" + field);
      assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
    }
    Map<String, String> fields = validFields();
    fields.put("collection-0/unknown", "private unknown value");
    assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
    fields.remove("collection-0/unknown");
    fields.put("collection-0/text", "a".repeat(65537));
    assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
  }

  @Test
  void convert_whenSelectedTextContainsSecret_expectNoEchoOrAutomaticEditing() {
    List<Integer> selectedIds = List.of(0);
    for (String text :
        List.of(
            "password=" + CANARY,
            "Authorization: Bearer " + CANARY,
            "insertURI=" + CANARY,
            "-----BEGIN PRIVATE KEY-----\n" + CANARY,
            "-----BEGIN RSA PRIVATE KEY-----\n" + CANARY,
            "INSERTSSK " + CANARY,
            "private_key " + CANARY,
            "private-key " + CANARY,
            "private key " + CANARY,
            "privatekey " + CANARY,
            "secret : " + CANARY,
            "token=" + CANARY,
            "seed=" + CANARY,
            "USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/WebOfTrust/5")) {
      Map<String, String> fields = validFields();
      fields.put("collection-0/text", text);
      IllegalArgumentException exception =
          assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
      assertFalse(exception.toString().contains(text));
      assertFalse(exception.toString().contains(CANARY));
      assertNull(exception.getCause());
    }
  }

  @Test
  void convert_whenTypedPublicReference_expectRetainedOnlyInsidePrivateRecord() {
    List<Integer> selectedIds = List.of(0);
    Map<String, String> fields = validFields();
    String reference =
        "SSK@sdFxM0Z4zx4-gXhGwzXAVYvOUi6NRfdGbyJa797bNAg,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQACAAE/";
    fields.put("collection-0/requestSSK", reference);
    assertNotNull(convert(fields, selectedIds));
    fields.put("collection-0/requestSSK", "SSK@not-proof-of-public");
    assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
  }

  @Test
  void inspect_whenFailureOrConcurrentChanges_expectSourcePreservationOrChangeRefusal()
      throws Exception {
    Path source = temporary.resolve("Sharesite.db");
    byte[] bytes = encode(validFields());
    Files.write(source, bytes);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SharesiteSnapshot.inspect(
                source,
                _ -> {
                  throw new IllegalArgumentException("sharesite_test_failure");
                }));
    assertArrayEquals(bytes, Files.readAllBytes(source));
    IOException exception =
        assertThrows(
            IOException.class,
            () ->
                SharesiteSnapshot.inspect(
                    source,
                    _ -> {
                      try {
                        Files.write(source, new byte[] {1});
                      } catch (IOException failure) {
                        throw new AssertionError(failure);
                      }
                      return true;
                    }));
    assertEquals("sharesite_snapshot_changed", exception.getMessage());
  }

  @Test
  void inspect_whenRecoverySidecarSymlinkOrDirectory_expectRefusalWithoutMutation()
      throws Exception {
    Path source = temporary.resolve("Sharesite.db");
    byte[] bytes = encode(validFields());
    Files.write(source, bytes);
    Files.write(source.resolveSibling("Sharesite.db.tmp"), new byte[] {1});
    assertThrows(
        IOException.class, () -> SharesiteSnapshot.inspect(source, SharesiteConversion::inspect));
    assertArrayEquals(bytes, Files.readAllBytes(source));
    for (String filename : List.of("selected.db.tmp", "selected.db.corrupted")) {
      Path recovery = temporary.resolve(filename);
      Files.write(recovery, bytes);
      IOException rejection =
          assertThrows(
              IOException.class,
              () -> SharesiteSnapshot.inspect(recovery, SharesiteConversion::inspect));
      assertEquals("sharesite_recovery_artifact_not_snapshot", rejection.getMessage());
      assertArrayEquals(bytes, Files.readAllBytes(recovery));
    }
    Path link = temporary.resolve("link.db");
    Files.createSymbolicLink(link, source);
    assertThrows(
        IOException.class, () -> SharesiteSnapshot.inspect(link, SharesiteConversion::inspect));
    assertThrows(
        IOException.class,
        () -> SharesiteSnapshot.inspect(temporary, SharesiteConversion::inspect));
  }

  @Test
  void cli_whenPlanThenExport_expectPrivateExactPayloadAndNoSourceMutation() throws Exception {
    Path source = temporary.resolve("private-source-name.db");
    byte[] original = encode(validFields());
    Files.write(source, original);
    Path workspace = temporary.resolve("operation");
    StringWriter log = new StringWriter();
    assertEquals(0, cli(log, "inspect", source, workspace));
    assertEquals(0, cli(log, "plan", source, workspace, selectionArgs()));
    byte[] plan = Files.readAllBytes(workspace.resolve("plan.json"));
    List<String> arguments = new ArrayList<>(List.of(selectionArgs()));
    arguments.addAll(List.of("--ack-plan-sha256", SharesiteSnapshot.sha256(plan)));
    assertEquals(0, cli(log, "export", source, workspace, arguments.toArray(String[]::new)));
    assertArrayEquals(plan, Files.readAllBytes(workspace.resolve("migration.json")));
    assertArrayEquals(original, Files.readAllBytes(source));
    assertEquals(
        PosixFilePermissions.fromString("rw-------"),
        Files.getPosixFilePermissions(workspace.resolve("migration.json")));
    assertFalse(log.toString().contains(source.toString()));
    assertFalse(log.toString().contains(CANARY));
    assertFalse(log.toString().contains("Literal"));
    assertNotEquals(0, cli(log, "export", source, workspace, arguments.toArray(String[]::new)));
    assertArrayEquals(original, Files.readAllBytes(source));
  }

  @Test
  void cli_whenChangedSnapshotOrUnsafeWorkspace_expectNoExport() throws Exception {
    Path source = temporary.resolve("Sharesite.db");
    Files.write(source, encode(validFields()));
    Path workspace = temporary.resolve("operation");
    StringWriter log = new StringWriter();
    assertNotEquals(0, cli(log, "plan", source, workspace, selectionArgs()));
    assertEquals(0, cli(log, "inspect", source, workspace));
    assertEquals(0, cli(log, "plan", source, workspace, selectionArgs()));
    String digest = SharesiteSnapshot.sha256(Files.readAllBytes(workspace.resolve("plan.json")));
    Map<String, String> changed = validFields();
    changed.put("collection-0/text", "changed");
    Files.write(source, encode(changed));
    List<String> arguments = new ArrayList<>(List.of(selectionArgs()));
    arguments.addAll(List.of("--ack-plan-sha256", digest));
    assertNotEquals(0, cli(log, "export", source, workspace, arguments.toArray(String[]::new)));
    assertFalse(Files.exists(workspace.resolve("migration.json")));
    Files.setPosixFilePermissions(workspace, PosixFilePermissions.fromString("rwxr-xr-x"));
    assertNotEquals(0, cli(log, "inspect", source, workspace));
  }

  private int cli(StringWriter log, String action, Path source, Path workspace, String... more) {
    List<String> arguments =
        new ArrayList<>(
            List.of(
                "migration",
                "sharesite",
                action,
                "--snapshot",
                source.toString(),
                "--workspace",
                workspace.toString(),
                "--writer-stopped"));
    arguments.addAll(List.of(more));
    return new CommandLine(new CryptaAppCli())
        .setOut(new PrintWriter(log))
        .setErr(new PrintWriter(log))
        .execute(arguments.toArray(String[]::new));
  }

  @Test
  void convert_whenSelectionOrEncodedDatasetExceedsLimits_expectNoPayload() {
    Map<String, String> fields = validFields();
    List<Integer> duplicateIds = List.of(0, 0);
    assertThrows(IllegalArgumentException.class, () -> convert(fields, duplicateIds));
    List<Integer> seventeen = java.util.stream.IntStream.range(0, 17).boxed().toList();
    assertThrows(IllegalArgumentException.class, () -> convert(fields, seventeen));
    fields.put("keys", "0 1 2");
    for (int id = 0; id < 3; id++) {
      fields.put("collection-" + id + "/name", "bounded");
      fields.put("collection-" + id + "/description", "bounded");
      fields.put("collection-" + id + "/text", "x".repeat(65536));
      fields.put("collection-" + id + "/pastebin", "true");
      fields.put("collection-" + id + "/edition", "-1");
    }
    // Three maximum text values alone fill the cap; metadata must also fit before output exists.
    List<Integer> selectedIds = List.of(0, 1, 2);
    assertThrows(IllegalArgumentException.class, () -> convert(fields, selectedIds));
  }

  @Test
  void convert_whenCommittedDatasetAtSizeBoundary_expectControllerAcceptsAndNextByteRejected()
      throws Exception {
    List<Integer> selectedIds = List.of(0, 1, 2);
    int accepted = 0;
    int rejected = 3 * 65536;
    while (accepted + 1 < rejected) {
      int candidate = (accepted + rejected) / 2;
      try {
        convert(threePages(candidate), selectedIds);
        accepted = candidate;
      } catch (IllegalArgumentException failure) {
        assertEquals("sharesite_dataset_limit", failure.getMessage());
        rejected = candidate;
      }
    }
    byte[] converted = convert(threePages(accepted), selectedIds);
    Map<String, String> oversizedFields = threePages(rejected);
    var failure =
        assertThrows(IllegalArgumentException.class, () -> convert(oversizedFields, selectedIds));
    assertEquals("sharesite_dataset_limit", failure.getMessage());
    assertControllerAccepts(converted, 0);

    Path source = temporary.resolve("Sharesite.db");
    byte[] original = encode(oversizedFields);
    Files.write(source, original);
    Path workspace = temporary.resolve("operation");
    Files.createDirectory(
        workspace,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    assertEquals(0, cli(new StringWriter(), "inspect", source, workspace));
    StringWriter diagnostics = new StringWriter();
    String[] selection = selectionArgs();
    selection[1] = "0,1,2";
    assertNotEquals(0, cli(diagnostics, "plan", source, workspace, selection));
    assertTrue(diagnostics.toString().contains("sharesite_dataset_limit"));
    assertFalse(Files.exists(workspace.resolve("plan.json")));
    assertArrayEquals(original, Files.readAllBytes(source));
  }

  @Test
  void convert_whenCombinedInventoryExceeds512_expectControllerAcceptsSelectedSubset()
      throws Exception {
    for (int deletedCount : List.of(1, 512)) {
      Map<String, String> fields = validFields();
      fields.put(
          "keys",
          java.util.stream.IntStream.range(0, 512)
              .mapToObj(Integer::toString)
              .collect(java.util.stream.Collectors.joining(" ")));
      fields.put(
          "deleted_keys",
          java.util.stream.IntStream.range(512, 512 + deletedCount)
              .mapToObj(Integer::toString)
              .collect(java.util.stream.Collectors.joining(" ")));
      fields.put("increasingCounter", Integer.toString(512 + deletedCount));
      for (int id = 0; id < 512 + deletedCount; id++) {
        fields.put("collection-" + id + "/insertSSK", CANARY);
      }
      byte[] original = encode(fields);
      Path source = temporary.resolve("inventory-" + deletedCount + ".db");
      Files.write(source, original);
      byte[] converted =
          SharesiteSnapshot.inspect(
              source,
              decoded ->
                  SharesiteConversion.convert(
                      decoded, List.of(0), OPERATION, "synthetic stopped snapshot"));

      assertControllerAccepts(converted, 512 + deletedCount);
      assertArrayEquals(original, Files.readAllBytes(source));
      assertFalse(new String(converted, StandardCharsets.UTF_8).contains(CANARY));
    }
  }

  private void assertControllerAccepts(byte[] converted, int inventoryCount) throws Exception {
    Path workspace = Files.createTempDirectory(temporary, "controller-");
    Path payload = workspace.resolve("private-boundary.json");
    Files.write(payload, converted);
    Path harness = workspace.resolve("import-boundary.cjs");
    try (var input = getClass().getResourceAsStream("import-boundary.cjs")) {
      assertNotNull(input);
      Files.copy(input, harness);
    }
    Path script =
        Path.of(
            System.getProperty("sharesite.synthetic.sitePublisherBundle"), "static", "drafts.js");
    Path log = workspace.resolve("synthetic-boundary.log");
    Process process =
        new ProcessBuilder(
                "node",
                harness.toString(),
                script.toString(),
                payload.toString(),
                Integer.toString(inventoryCount))
            .redirectErrorStream(true)
            .redirectOutput(log.toFile())
            .start();
    boolean finished = process.waitFor(20, TimeUnit.SECONDS);
    if (!finished) process.destroyForcibly();
    assertTrue(finished, "Synthetic controller boundary check timed out");
    assertEquals(0, process.exitValue(), Files.readString(log));
  }

  private static Map<String, String> threePages(int textBytes) {
    Map<String, String> fields = validFields();
    fields.put("keys", "0 1 2");
    int remaining = textBytes;
    for (int id = 0; id < 3; id++) {
      fields.put("collection-" + id + "/name", "bounded 雪");
      fields.put("collection-" + id + "/description", "bounded");
      int length = Math.min(remaining, 65536);
      fields.put("collection-" + id + "/text", "x".repeat(length));
      remaining -= length;
      fields.put("collection-" + id + "/pastebin", "true");
      fields.put("collection-" + id + "/edition", "-1");
    }
    return fields;
  }

  @Test
  void cli_whenPrivateOutputIsLinkOrExistingTarget_expectNoOverwrite() throws Exception {
    Path source = temporary.resolve("Sharesite.db");
    byte[] original = encode(validFields());
    Files.write(source, original);
    Path workspace = temporary.resolve("operation");
    Files.createDirectory(
        workspace,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    Files.createSymbolicLink(workspace.resolve("inspection.json"), source);
    assertNotEquals(0, cli(new StringWriter(), "inspect", source, workspace));
    assertArrayEquals(original, Files.readAllBytes(source));
  }

  private static String[] selectionArgs() {
    return new String[] {
      "--select",
      "0",
      "--operation-id",
      OPERATION.toString(),
      "--provenance",
      "Synthetic stopped-writer vector",
      "--ack-exclusions"
    };
  }

  private static byte[] convert(Map<String, String> fields, List<Integer> selected) {
    return SharesiteConversion.convert(
        new SharesiteSnapshot.Decoded(fields, "0".repeat(64)),
        selected,
        OPERATION,
        "Synthetic stopped-writer vector");
  }

  private static Map<String, String> validFields() {
    Map<String, String> fields = new LinkedHashMap<>();
    fields.put("keys", "0");
    fields.put("deleted_keys", "");
    fields.put("increasingCounter", "1");
    fields.put("lastDeletedTime", "0");
    fields.put("collection-0/name", "Literal name");
    fields.put("collection-0/description", "Literal description");
    fields.put("collection-0/text", "literal <b>inert</b>\r\n🙂");
    fields.put("collection-0/pastebin", "true");
    fields.put("collection-0/edition", "-1");
    fields.put("collection-0/insertSSK", CANARY);
    return fields;
  }

  private static byte[] encode(Map<String, String> fields) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (DataOutputStream output = new DataOutputStream(bytes)) {
      output.write("ShareWiki-db-ver1".getBytes(StandardCharsets.UTF_8));
      output.writeInt(fields.size());
      for (var entry : fields.entrySet()) {
        for (String value : List.of(entry.getKey(), entry.getValue())) {
          byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
          output.writeInt(encoded.length);
          output.write(encoded);
        }
      }
    }
    return bytes.toByteArray();
  }

  private static byte[] fixture(String name) throws IOException {
    try (var input = SharesiteMigrationTest.class.getResourceAsStream(name)) {
      assertNotNull(input);
      return input.readAllBytes();
    }
  }
}
