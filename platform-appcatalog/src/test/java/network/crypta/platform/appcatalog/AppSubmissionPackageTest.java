package network.crypta.platform.appcatalog;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleStructureValidator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SuppressWarnings("java:S100")
class AppSubmissionPackageTest {
  private static final String AUTHORIZATION_HEADER = "Authorization: Bearer abcdefghijklmnop";
  private static final String PERMISSION_RATIONALE_FILE = "permission-rationale.md";

  @TempDir private Path tempDir;

  @Test
  void create_whenSameInputs_expectDeterministicVerifiedSubmission() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path firstOutput = tempDir.resolve("first-submission.zip");
    Path secondOutput = tempDir.resolve("second-submission.zip");

    AppSubmissionPackage first =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, firstOutput));
    AppSubmissionPackage second =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, secondOutput));

    assertEquals(first.metadata(), second.metadata());
    assertEquals(sha256(firstOutput), sha256(secondOutput));
    assertEquals(
        first.metadata().submissionId(),
        AppSubmissionPackageVerifier.verify(firstOutput).metadata().submissionId());
    assertEquals(
        sha256(
            readZipBytes(
                firstOutput,
                AppSubmissionPackageVerifier.BUNDLE_PREFIX + AppBundleDigest.MANIFEST_FILE_NAME)),
        first.manifestDigest());
    assertTrue(first.entryNames().contains(AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY));
    assertTrue(first.entryNames().contains(AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY));
    AppSubmissionPackageVerifier.VerifiedBundleArtifact artifact =
        AppSubmissionPackageVerifier.readVerifiedBundleArtifact(firstOutput);
    assertEquals(first.submissionDigest(), artifact.submission().submissionDigest());
    assertArrayEquals(
        readZipBytes(firstOutput, AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY),
        artifact.bytes());
  }

  @Test
  void verify_whenSubmissionParentDisallowsWrites_expectAccepted() throws Exception {
    Path submissionParent = tempDir.resolve("read-only-submissions");
    Files.createDirectory(submissionParent);
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path output = submissionParent.resolve("submission.zip");
    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, output));
    Set<PosixFilePermission> originalPermissions = originalPosixPermissions(submissionParent);

    try {
      Files.setPosixFilePermissions(submissionParent, PosixFilePermissions.fromString("r-x------"));
      assumeTrue(!canCreateFile(submissionParent.resolve("verifier-probe.tmp")));

      AppSubmissionPackage verified = AppSubmissionPackageVerifier.verify(output);

      assertEquals(created.metadata().submissionId(), verified.metadata().submissionId());
    } finally {
      Files.setPosixFilePermissions(submissionParent, originalPermissions);
    }
  }

  @Test
  void create_whenReviewDocContainsAuthorizationHeader_expectRedactionFailure() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale(AUTHORIZATION_HEADER + "\n");
    AppSubmissionPackageWriter.CreateRequest request =
        createRequest(bundle, permissionRationale, tempDir.resolve("leaky.zip"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppSubmissionPackageWriter.create(request));

    assertTrue(exception.getMessage().contains("redaction.authorization-header"));
  }

  @Test
  void create_whenOutputIsInsideBundleRoot_expectFailure() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    AppSubmissionPackageWriter.CreateRequest request =
        createRequest(bundle, permissionRationale, bundle.resolve("submission.zip"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppSubmissionPackageWriter.create(request));

    assertTrue(exception.getMessage().contains("submission output must not be inside"));
  }

  @Test
  void create_whenOutputParentSymlinksIntoBundleRoot_expectFailure() throws Exception {
    Path symlinkProbe = tempDir.resolve("symlink-probe");
    assumeTrue(canCreateSymlink(symlinkProbe));
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path linkedOutputParent = tempDir.resolve("linked-output-parent");
    Files.createSymbolicLink(linkedOutputParent, bundle);

    AppSubmissionPackageWriter.CreateRequest request =
        createRequest(bundle, permissionRationale, linkedOutputParent.resolve("submission.zip"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppSubmissionPackageWriter.create(request));

    assertTrue(exception.getMessage().contains("submission output must not be inside"));
    assertFalse(Files.exists(bundle.resolve("submission.zip")));
  }

  @Test
  void create_whenSourceReferenceUsesPublicCryptaUsk_expectAccepted() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path output = tempDir.resolve("public-crypta-source.zip");

    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(
            createRequest(
                bundle,
                permissionRationale,
                output,
                URI.create("crypta:USK@PUBLIC/repo/42/source.tar")));

    assertEquals(
        created.metadata().submissionId(),
        AppSubmissionPackageVerifier.verify(output).metadata().submissionId());
  }

  @Test
  void create_whenSourceReferenceUsesPrivateCryptaInsertUri_expectFailure() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path output = tempDir.resolve("private-crypta-source.zip");
    URI sourceUri = URI.create("crypta:USK@PRIVATE-insert-material/repo/42/source.tar");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                createSubmissionWithSourceReference(
                    bundle, permissionRationale, output, sourceUri));

    assertTrue(exception.getMessage().contains("private insert URI"));
  }

  @Test
  void create_whenSourceReferenceUsesGeneratedPrivateCryptaInsertUri_expectFailure()
      throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    URI privateInsertUri =
        URI.create(
            "crypta:USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,"
                + "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/catalog/42");

    Path output = tempDir.resolve("generated-private-crypta-source.zip");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                createSubmissionWithSourceReference(
                    bundle, permissionRationale, output, privateInsertUri));

    assertTrue(exception.getMessage().contains("private insert URI"));
  }

  @Test
  void sourceReference_whenHttpUrlHasNoHost_expectFailure() {
    URI sourceUrl = URI.create("https:repo");
    Optional<String> noRevision = Optional.empty();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> new AppSubmissionSourceReference(sourceUrl, noRevision));

    assertTrue(exception.getMessage().contains("public host"));
  }

  @Test
  void sourceReference_whenHttpUrlUsesLocalHost_expectFailure() {
    for (String rawUri :
        new String[] {
          "http://localhost/repo",
          "http://localhost./repo",
          "http://127.0.0.1/repo",
          "http://2130706433/repo",
          "http://017700000001/repo",
          "http://0x7f000001/repo",
          "http://127.1/repo",
          "http://10.0.0.1/repo",
          "http://192.168.1.2/repo",
          "http://[::1]/repo",
          "http://[::01]/repo",
          "http://[0:0:0:0:0:0:0:0001]/repo",
          "http://[fe90::1]/repo",
          "http://[::ffff:7f00:1]/repo",
          "http://[fd00::1]/repo"
        }) {
      URI sourceUrl = URI.create(rawUri);
      Optional<String> noRevision = Optional.empty();

      AppCatalogException exception =
          assertThrows(
              AppCatalogException.class,
              () -> new AppSubmissionSourceReference(sourceUrl, noRevision));

      assertTrue(exception.getMessage().contains("public host"), rawUri);
    }
  }

  @Test
  void sourceReference_whenHttpUrlUsesPublicHost_expectAccepted() {
    AppSubmissionSourceReference reference =
        new AppSubmissionSourceReference(
            URI.create("http://example.invalid/repo"), Optional.empty());
    AppSubmissionSourceReference ipv6Reference =
        new AppSubmissionSourceReference(
            URI.create("http://[2001:4860:4860::8888]/repo"), Optional.empty());

    assertEquals("http://example.invalid/repo", reference.url().toString());
    assertEquals("http://[2001:4860:4860::8888]/repo", ipv6Reference.url().toString());
  }

  @Test
  void inspectAndExtractBundle_whenExecReliesOnArtifactMode_expectExecutableBitRestored()
      throws Exception {
    assumeTrue(Files.getFileStore(tempDir).supportsFileAttributeView("posix"));
    Path bundle = createBundle("bin/server", "native launcher payload\n", true);
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("executable-submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path extracted = tempDir.resolve("extracted");

    AppSubmissionVerification verification =
        AppSubmissionPackageVerifier.inspectAndExtractBundle(submission, extracted);

    assertFalse(verification.hasBlockers());
    assertEquals("sample-app", verification.submission().metadata().appId());
    assertTrue(Files.isExecutable(extracted.resolve("bin/server")));
    assertEquals("sample-app", AppBundleStructureValidator.validate(extracted).manifest().appId());
  }

  @Test
  void inspectAndExtractBundle_whenBundleFileHasChildPath_expectBlockerWithoutExtraction()
      throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("bundle-prefix-conflict.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_PREFIX + "conflict",
            "parent\n".getBytes(StandardCharsets.UTF_8),
            AppSubmissionPackageVerifier.BUNDLE_PREFIX + "conflict/child.txt",
            "child\n".getBytes(StandardCharsets.UTF_8)));
    Path extracted = tempDir.resolve("prefix-conflict-extracted");

    AppSubmissionVerification verification =
        AppSubmissionPackageVerifier.inspectAndExtractBundle(tampered, extracted);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("package.bundle-path-prefix-conflict")));
    assertFalse(Files.exists(extracted));
  }

  @Test
  void extractBundle_whenTargetContainsExistingSymlink_expectFailureWithoutOverwrite()
      throws Exception {
    Path symlinkProbe = tempDir.resolve("symlink-probe");
    assumeTrue(canCreateSymlink(symlinkProbe));
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("symlink-target-submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path extracted = tempDir.resolve("extracted-with-link");
    Files.createDirectories(extracted.resolve("bin"));
    Path outside = tempDir.resolve("outside.txt");
    Files.writeString(outside, "outside\n", StandardCharsets.UTF_8);
    Files.createSymbolicLink(extracted.resolve("bin/start.sh"), outside);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppSubmissionPackageVerifier.extractBundle(submission, extracted));

    assertTrue(exception.getMessage().contains("bundle extraction target must be empty"));
    assertEquals("outside\n", Files.readString(outside, StandardCharsets.UTF_8));
  }

  @Test
  void extractBundle_whenTargetDirectoryIsSymlink_expectFailure() throws Exception {
    Path symlinkProbe = tempDir.resolve("symlink-probe");
    assumeTrue(canCreateSymlink(symlinkProbe));
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("symlink-directory-submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path realTarget = tempDir.resolve("real-target");
    Files.createDirectory(realTarget);
    Path linkedTarget = tempDir.resolve("linked-target");
    Files.createSymbolicLink(linkedTarget, realTarget);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppSubmissionPackageVerifier.extractBundle(submission, linkedTarget));

    assertTrue(
        exception
            .getMessage()
            .contains("bundle extraction target must not contain symbolic links"));
  }

  @Test
  void extractBundle_whenTargetParentIsSymlink_expectFailure() throws Exception {
    Path symlinkProbe = tempDir.resolve("symlink-probe");
    assumeTrue(canCreateSymlink(symlinkProbe));
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("symlink-parent-submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path realParent = tempDir.resolve("real-parent");
    Files.createDirectory(realParent);
    Path linkedParent = tempDir.resolve("linked-parent");
    Files.createSymbolicLink(linkedParent, realParent);
    Path extractionTarget = linkedParent.resolve("extracted");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppSubmissionPackageVerifier.extractBundle(submission, extractionTarget));

    assertTrue(
        exception
            .getMessage()
            .contains("bundle extraction target must not contain symbolic links"));
  }

  @Test
  void verify_whenArtifactZipDoesNotMatchReviewedBundle_expectBlocker() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path alteredBundle = createBundle("#!/bin/sh\necho altered\n");
    Path alteredArtifact = tempDir.resolve("altered-app-bundle.zip");
    AppBundlePackager.packageBundle(alteredBundle, alteredArtifact);
    byte[] alteredArtifactBytes = Files.readAllBytes(alteredArtifact);
    String alteredDigest = sha256(alteredArtifactBytes);
    Path tampered = tempDir.resolve("tampered-submission.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY,
            alteredArtifactBytes,
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            readSubmissionMetadataText(submission)
                .replace(created.metadata().bundleDigest(), alteredDigest)
                .getBytes(StandardCharsets.UTF_8)));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("artifact.bundle-entry-mismatch"));
  }

  @Test
  void verify_whenSubmissionMetadataIsForged_expectBlocker() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("tampered-metadata.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            readSubmissionMetadataText(submission)
                .replace("\"backupRestoreDeclared\":false", "\"backupRestoreDeclared\":true")
                .getBytes(StandardCharsets.UTF_8)));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("metadata.backup-restore-mismatch"));
  }

  @Test
  void verify_whenOptionalPermissionRationaleDigestIsStale_expectBlocker() throws Exception {
    Path bundle = createBundleWithoutPermissions();
    Path permissionRationale = writePermissionRationale("No permissions requested.\n");
    Path submission = tempDir.resolve("optional-rationale-submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("tampered-optional-rationale.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.PERMISSION_RATIONALE_ENTRY,
            "Changed optional rationale.\n".getBytes(StandardCharsets.UTF_8)));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("review.permission-rationale-digest-mismatch"));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        AppSubmissionPackageVerifier.PERMISSION_RATIONALE_ENTRY,
        AppSubmissionPackageVerifier.SANDBOX_RATIONALE_ENTRY,
        AppSubmissionPackageVerifier.DATA_SCHEMA_ENTRY,
        AppSubmissionPackageVerifier.BACKUP_RESTORE_ENTRY
      })
  void verify_whenRequiredReviewEvidenceIsBlank_expectBlocker(String entryName) throws Exception {
    Path bundle =
        createBundle(
            "bin/start.sh",
            "#!/bin/sh\necho sample\n",
            false,
            "queue.read,app.data.write",
            """
            sandbox.mode=restricted-process
            app.data.schema.current=1
            """);
    Path permissionRationale = writeReviewDoc("permission-rationale.md", "queue.read: lists.\n");
    Path sandboxRationale = writeReviewDoc("sandbox-rationale.md", "Uses process sandbox.\n");
    Path dataSchema = writeReviewDoc("data-schema.md", "Schema version 1.\n");
    Path backupRestore = writeReviewDoc("backup-restore.md", "Backup supported.\n");
    Path submission = tempDir.resolve("required-review-evidence.zip");
    AppSubmissionPackageWriter.create(
        createRequestWithReviewDocs(
            bundle, submission, permissionRationale, sandboxRationale, dataSchema, backupRestore));
    Path tampered = tempDir.resolve("blank-required-review-evidence.zip");
    writeSubmissionWithReplacements(
        submission, tampered, Map.of(entryName, "\n\t  \n".getBytes(StandardCharsets.UTF_8)));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("review.required-evidence-empty")));
  }

  @Test
  void verify_whenArtifactZipMetadataChangesWithoutPayloadChange_expectBlocker() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    byte[] recodedArtifact =
        recodeArtifactWithNonCanonicalZipMetadata(
            readZipBytes(submission, AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY));
    Path tampered = tempDir.resolve("tampered-artifact-metadata.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY,
            recodedArtifact,
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            readSubmissionMetadataText(submission)
                .replace(created.metadata().bundleDigest(), sha256(recodedArtifact))
                .getBytes(StandardCharsets.UTF_8)));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("artifact.zip-entry-metadata"));
  }

  @Test
  void verify_whenArtifactCentralDirectoryIsEmptyButPayloadExists_expectBlocker() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    byte[] recodedArtifact =
        artifactWithEmptyCentralDirectoryMetadata(
            readZipBytes(submission, AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY));
    Path tampered = tempDir.resolve("tampered-empty-central-directory.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY,
            recodedArtifact,
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            readSubmissionMetadataText(submission)
                .replace(created.metadata().bundleDigest(), sha256(recodedArtifact))
                .getBytes(StandardCharsets.UTF_8)));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("artifact.zip-metadata-missing"));
  }

  @Test
  void verify_whenArtifactZipContainsGapBeforeEndOfCentralDirectory_expectBlocker()
      throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    byte[] recodedArtifact =
        artifactWithGapBeforeEndOfCentralDirectory(
            readZipBytes(submission, AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY));
    Path tampered =
        writeTamperedArtifactSubmission(
            submission, created, recodedArtifact, "tampered-artifact-gap.zip");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("artifact.zip-metadata-invalid"));
  }

  @Test
  void verify_whenArtifactZipContainsEndOfCentralDirectoryComment_expectBlocker() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackage created =
        AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    byte[] recodedArtifact =
        artifactWithEndOfCentralDirectoryComment(
            readZipBytes(submission, AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY));
    Path tampered =
        writeTamperedArtifactSubmission(
            submission, created, recodedArtifact, "tampered-artifact-comment.zip");

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("artifact.zip-metadata-invalid"));
  }

  @Test
  void verify_whenSubmissionZipContainsEndOfCentralDirectoryComment_expectBlocker()
      throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("tampered-submission-comment.zip");
    writeSubmissionWithAuthorizationHeaderComment(submission, tampered);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppSubmissionPackageVerifier.verify(tampered));

    assertTrue(exception.getMessage().contains("redaction.zip-envelope"));
    assertFalse(exception.getMessage().contains("Bearer"));
  }

  @Test
  void inspect_whenMetadataParseFails_expectRedactedFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("tampered-invalid-metadata.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            "{\"schemaVersion\":1,\"submissionType\":\"not-a-real-type\"}\n"
                .getBytes(StandardCharsets.UTF_8)));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertNull(verification.submission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("metadata.parse-invalid")));
    assertFalse(verification.findings().toString().contains("not-a-real-type"));
  }

  @Test
  void inspect_whenInvalidMetadataContainsBearerToken_expectRedactedFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("tampered-secret-metadata.zip");
    String token = "Bearer abcdefghijklmnop";
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            ("{\"schemaVersion\":1,\"submissionType\":\"" + token + "\"}\n")
                .getBytes(StandardCharsets.UTF_8)));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("redaction.bearer-token")));
    assertFalse(verification.findings().toString().contains(token));
  }

  @Test
  void inspect_whenSubmissionMetadataEntryIsMissing_expectRequiredEntryFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("missing-metadata.zip");
    writeSubmissionWithoutEntries(
        submission, tampered, AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY);

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    AppSubmissionFinding finding =
        verification.findings().stream()
            .filter(candidate -> candidate.id().equals("package.required-entry-missing"))
            .findFirst()
            .orElseThrow();
    assertTrue(finding.details().get("path").toString().startsWith("entry:"));
    assertTrue(finding.details().containsKey("pathDigestSha256"));
    assertFalse(verification.findings().toString().contains("crypta-app-submission.json"));
  }

  @Test
  void inspect_whenEmbeddedManifestEntryIsMissing_expectRequiredEntryFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("missing-manifest.zip");
    writeSubmissionWithoutEntries(
        submission,
        tampered,
        AppSubmissionPackageVerifier.BUNDLE_PREFIX + AppBundleDigest.MANIFEST_FILE_NAME);

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("package.required-entry-missing")));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
        AppSubmissionPackageVerifier.BUNDLE_PREFIX + AppBundleDigest.MANIFEST_FILE_NAME,
        AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY
      })
  void inspect_whenRequiredEntryIsEmpty_expectRequiredEntryEmptyFinding(String entryName)
      throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("empty-required-entry.zip");
    writeSubmissionWithReplacements(submission, tampered, Map.of(entryName, new byte[0]));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("package.required-entry-empty")));
  }

  @Test
  void inspect_whenRequiredMetadataEntryExceedsSizeCap_expectEntrySizeFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("oversized-metadata.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY, new byte[8 * 1024 * 1024 + 1]));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("package.entry-size-limit")));
    assertFalse(verification.findings().toString().contains("crypta-app-submission.json"));
  }

  @Test
  void inspect_whenEmbeddedManifestEntryExceedsSizeCap_expectEntrySizeFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("oversized-manifest.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_PREFIX + AppBundleDigest.MANIFEST_FILE_NAME,
            new byte[8 * 1024 * 1024 + 1]));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("package.entry-size-limit")));
  }

  @Test
  void inspect_whenNonRequiredEntryExceedsSizeCap_expectEntrySizeFinding() throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("oversized-evidence-entry.zip");
    writeSubmissionWithReplacements(
        submission, tampered, Map.of("metadata/large-evidence.txt", new byte[8 * 1024 * 1024 + 1]));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertFalse(verification.hasParsedSubmission());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("package.entry-size-limit")));
  }

  @Test
  void inspect_whenBundleSignatureSidecarOnlyDeclaresKeyId_expectSignatureFinding()
      throws Exception {
    Path bundle = createBundle();
    Path permissionRationale = writePermissionRationale("queue.read: lists queues.\n");
    Path submission = tempDir.resolve("submission.zip");
    AppSubmissionPackageWriter.create(createRequest(bundle, permissionRationale, submission));
    Path tampered = tempDir.resolve("malformed-signature-sidecar.zip");
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_PREFIX + AppBundleSignature.SIGNATURE_FILE_NAME,
            "signature.key.id=reviewer-dev\n".getBytes(StandardCharsets.UTF_8)));

    AppSubmissionVerification verification = AppSubmissionPackageVerifier.inspect(tampered);

    assertTrue(verification.hasBlockers());
    assertTrue(
        verification.findings().stream()
            .anyMatch(finding -> finding.id().equals("signature.sidecar-invalid")));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "review/..",
        "../leak!note.txt",
        "bundle/static/./app.js",
        "bundle/static//app.js"
      })
  void scanEntry_whenPathIsUnsafe_expectUnsafePathFinding(String entryName) {
    var findings = AppSubmissionRedactionScanner.scanEntry(entryName, new byte[0]);

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.unsafe-path")));
  }

  @Test
  void scanEntry_whenNestedZipPathContainsDotComponent_expectUnsafePathFinding() throws Exception {
    var findings =
        AppSubmissionRedactionScanner.scanEntry(
            "review/evidence.zip", zipWithText("bundle/static/./app.js", "ordinary evidence\n"));

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.unsafe-path")));
  }

  @Test
  void scanEntry_whenMacAbsolutePathsArePresent_expectLocalPathFinding() {
    byte[] payload =
        """
        build scratch: /private/var/folders/aa/bb/crypta
        mounted workspace: /Volumes/Crypta/Submissions/sample
        """
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/security-notes.md", payload);

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.local-path")));
  }

  @Test
  void scanEntry_whenUriFormLocalPathsArePresent_expectLocalPathFinding() {
    byte[] payload =
        """
        key=file:///home/alice/key
        singleSlash=file:/home/alice/key
        scratch=file:/tmp/build.log
        source=https:///home/alice/repo
        """
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("metadata/source.json", payload);

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.local-path")));
    assertFalse(findings.toString().contains("/home/alice"));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "See (/home/alice/secret.txt) before review.",
        "Markdown link: [local](file:///home/alice/key)",
        "Windows note: (C:\\Users\\Alice\\secret.txt)",
        "Windows metadata: path:C:\\Users\\Alice\\secret.txt"
      })
  void scanEntry_whenLocalPathIsDelimitedByPunctuation_expectLocalPathFinding(String evidenceText) {
    var findings =
        AppSubmissionRedactionScanner.scanEntry(
            "review/security-notes.md", evidenceText.getBytes(StandardCharsets.UTF_8));

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.local-path")));
    assertFalse(findings.toString().contains("alice"));
  }

  @Test
  void scanEntry_whenNestedZipEntryExceedsScanCap_expectSizeFinding() throws Exception {
    var findings =
        AppSubmissionRedactionScanner.scanEntry("artifacts/evidence.zip", oversizedNestedZip());

    assertTrue(
        findings.stream()
            .anyMatch(finding -> finding.id().equals("redaction.nested-zip-entry-too-large")));
  }

  @Test
  void scanEntry_whenOversizedTextEvidenceContainsSecret_expectSecretAndSizeFindings() {
    byte[] payload = new byte[2 * 1024 * 1024 + 1];
    byte[] secret = "-----BEGIN PRIVATE KEY-----\n".getBytes(StandardCharsets.UTF_8);
    System.arraycopy(secret, 0, payload, 0, secret.length);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/security-notes.md", payload);

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-key")));
    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.entry-too-large")));
  }

  @Test
  void scanEntry_whenUppercaseZipEvidenceContainsSecret_expectNestedSecretFinding()
      throws Exception {
    var findings =
        AppSubmissionRedactionScanner.scanEntry(
            "review/evidence.ZIP", zipWithText("secret.txt", AUTHORIZATION_HEADER + "\n"));

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.bearer-token")));
  }

  @Test
  void scanEntry_whenExtensionlessZipEvidenceContainsSecret_expectNestedSecretFinding()
      throws Exception {
    var findings =
        AppSubmissionRedactionScanner.scanEntry(
            "review/evidence", zipWithText("secret.txt", "-----BEGIN PRIVATE KEY-----\n"));

    assertTrue(findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-key")));
  }

  @Test
  void scanEntry_whenNestedZipContainsSecret_expectNestedSecretFinding() throws Exception {
    byte[] innerZip = zipWithText("secret.txt", AUTHORIZATION_HEADER + "\n");
    byte[] outerZip = zipWithBytes("lib/inner.jar", innerZip);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/evidence.zip", outerZip);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.bearer-token")));
  }

  @Test
  void scanEntry_whenNestedZipFilenameContainsBearerToken_expectNestedSecretFinding()
      throws Exception {
    String token = "Bearer abcdefghijklmnop";
    byte[] evidenceZip = zipWithText("Authorization: " + token + ".txt", "ordinary evidence\n");

    var findings = AppSubmissionRedactionScanner.scanEntry("review/evidence.zip", evidenceZip);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.bearer-token")));
    assertFalse(findings.toString().contains(token));
  }

  @Test
  void scanEntry_whenNestedZipFilenameContainsPrivateInsertUri_expectNestedSecretFinding()
      throws Exception {
    String privateInsertUri =
        "crypta:USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,"
            + "ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE";
    byte[] evidenceZip = zipWithText(privateInsertUri, "ordinary evidence\n");

    var findings = AppSubmissionRedactionScanner.scanEntry("review/evidence.zip", evidenceZip);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-insert-uri")));
    assertFalse(findings.toString().contains(privateInsertUri));
  }

  @Test
  void scanEntry_whenUnsafePathContainsSecret_expectFindingPathDetailsAreRedacted() {
    String token = "Bearer abcdefghijklmnop";

    var findings =
        AppSubmissionRedactionScanner.scanEntry("../Authorization: " + token, new byte[0]);

    AppSubmissionFinding finding =
        findings.stream()
            .filter(candidate -> candidate.id().equals("redaction.unsafe-path"))
            .findFirst()
            .orElseThrow();
    assertTrue(finding.details().get("path").toString().startsWith("entry:"));
    assertTrue(finding.details().containsKey("pathDigestSha256"));
    assertFalse(findings.toString().contains(token));
  }

  @Test
  void scanEntry_whenSdkBrowserSessionStatusTextIsPresent_expectNoSessionTokenFinding() {
    byte[] content =
        """
        throw new Error("App browser session is unavailable; reload the app UI.");
        const header = "X-Crypta-App-Session";
        const code = "invalid_app_browser_session";
        """
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("static/crypta-platform.js", content);

    assertFalse(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.session-token")));
  }

  @Test
  void scanEntry_whenBrowserSessionTokenValueIsPresent_expectSessionTokenFinding() {
    byte[] content =
        "{\"browserSessionToken\":\"abcdefghijklmnopqrstuvwxyz\"}\n"
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("metadata/session.json", content);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.session-token")));
  }

  @Test
  void scanEntry_whenAppLaunchTokenNameIsPresent_expectNoSessionTokenFinding() {
    byte[] content = "CRYPTAD_APP_TOKEN\n".getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/security-notes.md", content);

    assertFalse(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.session-token")));
  }

  @Test
  void scanEntry_whenAppLaunchTokenAssignmentContainsValue_expectSessionTokenFinding() {
    byte[] content =
        "CRYPTAD_APP_TOKEN=abcdefghijklmnopqrstuvwxyz\n".getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/security-notes.md", content);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.session-token")));
  }

  @Test
  void scanEntry_whenPublicCryptaReferencesArePresent_expectNoPrivateInsertFinding() {
    byte[] content =
        """
        source=crypta:USK@PUBLIC/repo/42/source.tar
        fetch example: SSK@PUBLIC/content/index.html
        signed site: USK@gjw6StjZOZ4OAG-pqOxIp5Nk11udQZOrozD4jld42Ac,BYyqgAtc9p0JGbJ~18XU6mtO9ChnBZdf~ttCn48FV7s,AQACAAE/flog/16/
        """
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("metadata/source.json", content);

    assertFalse(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-insert-uri")));
  }

  @Test
  void scanEntry_whenSourceMetadataUrlContainsPrivateCryptaInsertUri_expectPrivateInsertFinding() {
    byte[] content =
        """
        {"url":"crypta:USK@PRIVATE-insert-material/repo/42/source.tar"}
        """
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("metadata/source.json", content);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-insert-uri")));
  }

  @Test
  void scanEntry_whenGeneratedPrivateInsertUriIsUnlabeled_expectPrivateInsertFinding() {
    byte[] content =
        """
        {"url":"crypta:USK@ZTeIa1g4T3OYCdUFfHrFSlRnt5coeFFDCIZxWSb7abs,ZP4aASnyZax8nYOvCOlUebegsmbGQIXfVzw7iyOsXEc,AQECAAE/catalog/42"}
        """
            .getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("metadata/source.json", content);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-insert-uri")));
  }

  @Test
  void scanEntry_whenPrivateInsertUriContextContainsUsk_expectPrivateInsertFinding() {
    byte[] content = "privateInsertUri=USK@PRIVATE/catalog/42\n".getBytes(StandardCharsets.UTF_8);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/security-notes.md", content);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.private-insert-uri")));
  }

  @Test
  void scanEntry_whenZipEvidenceContainsEndOfCentralDirectoryComment_expectEnvelopeFinding()
      throws Exception {
    var findings =
        AppSubmissionRedactionScanner.scanEntry(
            "review/evidence.zip", zipWithAuthorizationHeaderComment());

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.zip-envelope")));
  }

  @Test
  void scanEntry_whenZipEvidenceContainsAppendedSecret_expectEnvelopeFinding() throws Exception {
    byte[] zip = zipWithText("note.txt", "ordinary evidence\n");
    byte[] withTrailingBytes =
        insertBytes(
            zip, zip.length, "-----BEGIN PRIVATE KEY-----\n".getBytes(StandardCharsets.UTF_8));

    var findings =
        AppSubmissionRedactionScanner.scanEntry("review/evidence.zip", withTrailingBytes);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.zip-envelope")));
  }

  @Test
  void scanEntry_whenZipEvidenceContainsPrependedSecret_expectEnvelopeFinding() throws Exception {
    byte[] zip = zipWithText("note.txt", "ordinary evidence\n");
    byte[] withPrependedBytes =
        insertBytes(zip, 0, (AUTHORIZATION_HEADER + "\n").getBytes(StandardCharsets.UTF_8));

    var findings =
        AppSubmissionRedactionScanner.scanEntry("review/evidence.zip", withPrependedBytes);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.zip-envelope")));
  }

  @Test
  void scanEntry_whenZipEvidenceContainsGapBeforeCentralDirectory_expectEnvelopeFinding()
      throws Exception {
    byte[] zip = zipWithText("note.txt", "ordinary evidence\n");
    int eocdOffset = endOfCentralDirectoryOffset(zip);
    int centralDirectoryOffset = getIntLe(zip, eocdOffset + 16);
    byte[] gap = (AUTHORIZATION_HEADER + "\n").getBytes(StandardCharsets.UTF_8);
    byte[] withGap = insertBytes(zip, centralDirectoryOffset, gap);
    putIntLe(withGap, eocdOffset + gap.length + 16, centralDirectoryOffset + gap.length);

    var findings = AppSubmissionRedactionScanner.scanEntry("review/evidence.zip", withGap);

    assertTrue(
        findings.stream().anyMatch(finding -> finding.id().equals("redaction.zip-envelope")));
  }

  @Test
  void finding_whenDetailMapHasCallerOrder_expectDetailsSortedByKey() {
    LinkedHashMap<String, Object> details = new LinkedHashMap<>();
    details.put("zeta", "last");
    details.put("alpha", "first");

    AppSubmissionFinding finding =
        new AppSubmissionFinding(
            "review.test", AppSubmissionFindingSeverity.INFO, "summary", details);

    assertEquals("[alpha, zeta]", finding.details().keySet().toString());
  }

  private AppSubmissionPackageWriter.CreateRequest createRequest(
      Path bundle, Path permissionRationale, Path output) {
    return createRequest(
        bundle, permissionRationale, output, URI.create("https://example.invalid/repo"));
  }

  private AppSubmissionPackageWriter.CreateRequest createRequest(
      Path bundle, Path permissionRationale, Path output, URI sourceUri) {
    return new AppSubmissionPackageWriter.CreateRequest(
        bundle,
        output,
        AppSubmissionType.NEW_APP,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.of(permissionRationale),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        new AppSubmissionMaintainer("Example Maintainer", "mailto:maintainer@example.invalid"),
        new AppSubmissionSourceReference(sourceUri, Optional.empty()),
        true,
        false);
  }

  private AppSubmissionPackageWriter.CreateRequest createRequestWithReviewDocs(
      Path bundle,
      Path output,
      Path permissionRationale,
      Path sandboxRationale,
      Path dataSchema,
      Path backupRestore) {
    return new AppSubmissionPackageWriter.CreateRequest(
        bundle,
        output,
        AppSubmissionType.NEW_APP,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.of(permissionRationale),
        Optional.of(sandboxRationale),
        Optional.of(dataSchema),
        Optional.of(backupRestore),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        new AppSubmissionMaintainer("Example Maintainer", "mailto:maintainer@example.invalid"),
        new AppSubmissionSourceReference(
            URI.create("https://example.invalid/repo"), Optional.empty()),
        true,
        false);
  }

  @SuppressWarnings("UnusedReturnValue")
  private AppSubmissionPackage createSubmissionWithSourceReference(
      Path bundle, Path permissionRationale, Path output, URI sourceUri) throws IOException {
    return AppSubmissionPackageWriter.create(
        createRequest(bundle, permissionRationale, output, sourceUri));
  }

  private Path createBundle() throws Exception {
    return createBundle("#!/bin/sh\necho sample\n");
  }

  private Path createBundleWithoutPermissions() throws Exception {
    return createBundle("bin/start.sh", "#!/bin/sh\necho sample\n", false, "");
  }

  private Path createBundle(String script) throws Exception {
    return createBundle("bin/start.sh", script, false);
  }

  private Path createBundle(String execPath, String executableContent, boolean executable)
      throws Exception {
    return createBundle(execPath, executableContent, executable, "queue.read");
  }

  private Path createBundle(
      String execPath, String executableContent, boolean executable, String permissions)
      throws Exception {
    return createBundle(execPath, executableContent, executable, permissions, "");
  }

  private Path createBundle(
      String execPath,
      String executableContent,
      boolean executable,
      String permissions,
      String additionalManifestLines)
      throws Exception {
    Path bundleRoot = Files.createDirectory(tempDir.resolve("bundle-" + System.nanoTime()));
    Path executablePath = bundleRoot.resolve(execPath);
    Files.createDirectories(executablePath.getParent());
    Files.createDirectories(bundleRoot.resolve("bin"));
    String permissionsLine =
        permissions == null || permissions.isBlank() ? "" : "app.permissions=" + permissions + "\n";
    Files.writeString(
        bundleRoot.resolve(AppBundleDigest.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=sample-app
        app.name=Sample App
        app.version=1.0.0
        app.exec=%s
        %s\
        %s\
        api.minimumVersion=1
        api.maximumTestedVersion=1
        api.targetStability=stable
        api.experimentalCapabilitiesAccepted=false
        """
            .formatted(execPath, permissionsLine, additionalManifestLines),
        StandardCharsets.UTF_8);
    Files.writeString(executablePath, executableContent, StandardCharsets.UTF_8);
    if (executable) {
      Files.setPosixFilePermissions(executablePath, PosixFilePermissions.fromString("rwxr-xr-x"));
    }
    return bundleRoot;
  }

  private Path writeTamperedArtifactSubmission(
      Path submission, AppSubmissionPackage created, byte[] recodedArtifact, String fileName)
      throws Exception {
    Path tampered = tempDir.resolve(fileName);
    writeSubmissionWithReplacements(
        submission,
        tampered,
        Map.of(
            AppSubmissionPackageVerifier.BUNDLE_ARTIFACT_ENTRY,
            recodedArtifact,
            AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY,
            readSubmissionMetadataText(submission)
                .replace(created.metadata().bundleDigest(), sha256(recodedArtifact))
                .getBytes(StandardCharsets.UTF_8)));
    return tampered;
  }

  private static void writeSubmissionWithReplacements(
      Path source, Path target, Map<String, byte[]> replacements) throws Exception {
    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    try (ZipFile zip = new ZipFile(source.toFile())) {
      var enumeration = zip.entries();
      while (enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        if (!entry.isDirectory()) {
          try (var input = zip.getInputStream(entry)) {
            entries.put(entry.getName(), input.readAllBytes());
          }
        }
      }
    }
    entries.putAll(replacements);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        zip.putNextEntry(new ZipEntry(entry.getKey()));
        zip.write(entry.getValue());
        zip.closeEntry();
      }
    }
  }

  private static void writeSubmissionWithoutEntries(Path source, Path target, String... removed)
      throws Exception {
    Set<String> removedEntries = Set.of(removed);
    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    try (ZipFile zip = new ZipFile(source.toFile())) {
      var enumeration = zip.entries();
      while (enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        if (!entry.isDirectory() && !removedEntries.contains(entry.getName())) {
          try (var input = zip.getInputStream(entry)) {
            entries.put(entry.getName(), input.readAllBytes());
          }
        }
      }
    }
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        zip.putNextEntry(new ZipEntry(entry.getKey()));
        zip.write(entry.getValue());
        zip.closeEntry();
      }
    }
  }

  private static void writeSubmissionWithAuthorizationHeaderComment(Path source, Path target)
      throws Exception {
    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    try (ZipFile zip = new ZipFile(source.toFile())) {
      var enumeration = zip.entries();
      while (enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        if (!entry.isDirectory()) {
          try (var input = zip.getInputStream(entry)) {
            entries.put(entry.getName(), input.readAllBytes());
          }
        }
      }
    }
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
      zip.setComment(AUTHORIZATION_HEADER);
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        zip.putNextEntry(new ZipEntry(entry.getKey()));
        zip.write(entry.getValue());
        zip.closeEntry();
      }
    }
  }

  private static String readSubmissionMetadataText(Path source) throws Exception {
    return new String(
        readZipBytes(source, AppSubmissionPackageVerifier.SUBMISSION_METADATA_ENTRY),
        StandardCharsets.UTF_8);
  }

  private static byte[] readZipBytes(Path source, String entryName) throws Exception {
    try (ZipFile zip = new ZipFile(source.toFile())) {
      ZipEntry entry = zip.getEntry(entryName);
      try (var input = zip.getInputStream(entry)) {
        return input.readAllBytes();
      }
    }
  }

  private static byte[] recodeArtifactWithNonCanonicalZipMetadata(byte[] artifactBytes)
      throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipInputStream input = new ZipInputStream(new ByteArrayInputStream(artifactBytes));
        ZipOutputStream zip = new ZipOutputStream(output)) {
      ZipEntry entry;
      while ((entry = input.getNextEntry()) != null) {
        ZipEntry recoded = new ZipEntry(entry.getName());
        recoded.setTime(1_234_567_890L);
        zip.putNextEntry(recoded);
        zip.write(input.readAllBytes());
        zip.closeEntry();
        input.closeEntry();
      }
    }
    return output.toByteArray();
  }

  private static byte[] artifactWithEmptyCentralDirectoryMetadata(byte[] artifactBytes) {
    byte[] altered = artifactBytes.clone();
    int eocdOffset = lastIndexOf(altered, new byte[] {0x50, 0x4b, 0x05, 0x06});
    if (eocdOffset < 0) {
      throw new IllegalArgumentException("missing EOCD");
    }
    putShortLe(altered, eocdOffset + 8, 0);
    putShortLe(altered, eocdOffset + 10, 0);
    putIntLe(altered, eocdOffset + 12, 0);
    putIntLe(altered, eocdOffset + 16, eocdOffset);
    return altered;
  }

  private static byte[] artifactWithGapBeforeEndOfCentralDirectory(byte[] artifactBytes) {
    int eocdOffset = endOfCentralDirectoryOffset(artifactBytes);
    return insertBytes(
        artifactBytes, eocdOffset, "hidden-redaction-gap".getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] artifactWithEndOfCentralDirectoryComment(byte[] artifactBytes) {
    int eocdOffset = endOfCentralDirectoryOffset(artifactBytes);
    byte[] comment = "hidden-redaction-comment".getBytes(StandardCharsets.UTF_8);
    byte[] altered = Arrays.copyOf(artifactBytes, artifactBytes.length + comment.length);
    System.arraycopy(comment, 0, altered, artifactBytes.length, comment.length);
    putShortLe(altered, eocdOffset + 20, comment.length);
    return altered;
  }

  private static int endOfCentralDirectoryOffset(byte[] artifactBytes) {
    int eocdOffset = lastIndexOf(artifactBytes, new byte[] {0x50, 0x4b, 0x05, 0x06});
    if (eocdOffset < 0) {
      throw new IllegalArgumentException("missing EOCD");
    }
    return eocdOffset;
  }

  private static byte[] insertBytes(byte[] source, int offset, byte[] inserted) {
    byte[] altered = new byte[source.length + inserted.length];
    System.arraycopy(source, 0, altered, 0, offset);
    System.arraycopy(inserted, 0, altered, offset, inserted.length);
    System.arraycopy(source, offset, altered, offset + inserted.length, source.length - offset);
    return altered;
  }

  private static byte[] oversizedNestedZip() throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      zip.putNextEntry(new ZipEntry("large.txt"));
      zip.write(new byte[2 * 1024 * 1024 + 2]);
      zip.closeEntry();
    }
    return output.toByteArray();
  }

  private static byte[] zipWithText(String entryName, String content) throws Exception {
    return zipWithBytes(entryName, content.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] zipWithBytes(String entryName, byte[] content) throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      zip.putNextEntry(new ZipEntry(entryName));
      zip.write(content);
      zip.closeEntry();
    }
    return output.toByteArray();
  }

  private static byte[] zipWithAuthorizationHeaderComment() throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      zip.setComment(AUTHORIZATION_HEADER);
      zip.putNextEntry(new ZipEntry("note.txt"));
      zip.write("ordinary evidence\n".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return output.toByteArray();
  }

  private static int lastIndexOf(byte[] bytes, byte[] pattern) {
    for (int index = bytes.length - pattern.length; index >= 0; index--) {
      boolean matches = true;
      for (int patternIndex = 0; patternIndex < pattern.length; patternIndex++) {
        if (bytes[index + patternIndex] != pattern[patternIndex]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        return index;
      }
    }
    return -1;
  }

  private static void putShortLe(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) (value & 0xFF);
    bytes[offset + 1] = (byte) ((value >>> 8) & 0xFF);
  }

  private static int getIntLe(byte[] bytes, int offset) {
    return (bytes[offset] & 0xFF)
        | ((bytes[offset + 1] & 0xFF) << 8)
        | ((bytes[offset + 2] & 0xFF) << 16)
        | ((bytes[offset + 3] & 0xFF) << 24);
  }

  private static void putIntLe(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) (value & 0xFF);
    bytes[offset + 1] = (byte) ((value >>> 8) & 0xFF);
    bytes[offset + 2] = (byte) ((value >>> 16) & 0xFF);
    bytes[offset + 3] = (byte) ((value >>> 24) & 0xFF);
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (UnsupportedOperationException | IOException | SecurityException _) {
      return false;
    }
  }

  private static Set<PosixFilePermission> originalPosixPermissions(Path directory)
      throws IOException {
    try {
      return Files.getPosixFilePermissions(directory);
    } catch (UnsupportedOperationException _) {
      assumeTrue(false);
      return Set.of();
    }
  }

  private static boolean canCreateFile(Path file) {
    boolean created = false;
    try {
      Files.createFile(file);
      created = true;
      return true;
    } catch (IOException | SecurityException _) {
      return false;
    } finally {
      if (created) {
        try {
          Files.deleteIfExists(file);
        } catch (IOException _) {
          // Best-effort cleanup for a permission probe in a temporary directory.
        }
      }
    }
  }

  private Path writePermissionRationale(String content) throws Exception {
    return writeReviewDoc(PERMISSION_RATIONALE_FILE, content);
  }

  private Path writeReviewDoc(String name, String content) throws Exception {
    Path file = tempDir.resolve(name);
    Files.writeString(file, content, StandardCharsets.UTF_8);
    return file;
  }

  private static String sha256(Path file) throws Exception {
    return sha256(Files.readAllBytes(file));
  }

  private static String sha256(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
}
