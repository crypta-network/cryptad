package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PilotPublisherApprovalReaderTest {
  private static final String NORMAL_DIGEST =
      "sha256:1111111111111111111111111111111111111111111111111111111111111111";
  private static final String CATALOG_DIGEST =
      "sha256:3333333333333333333333333333333333333333333333333333333333333333";
  private static final String PILOT_DIGEST =
      "sha256:2222222222222222222222222222222222222222222222222222222222222222";

  @TempDir Path tempDir;

  @BeforeEach
  void prepareOwnedFixtureRoot() throws Exception {
    tempDir = tempDir.toRealPath();
  }

  @Test
  void read_whenExactClosedApprovalDigestMatches_expectRuntimeProjection() throws Exception {
    Path approvalFile = tempDir.resolve("publisher-approval.json");
    Files.writeString(approvalFile, approvalJson(""), StandardCharsets.UTF_8);

    PilotPublisherVerificationPolicy.Approval approval =
        PilotPublisherApprovalReader.read(approvalFile, sha256(Files.readAllBytes(approvalFile)));

    assertEquals("pilot-294", approval.pilotId());
    assertEquals("node-294", approval.pilotNodeId());
    assertEquals(NORMAL_DIGEST, approval.normalStableRegistryDigest());
    assertEquals(CATALOG_DIGEST, approval.catalogRegistryDigest());
    assertEquals(PILOT_DIGEST, approval.pilotRegistryDigest());
    assertEquals(3, approval.subjects().size());
  }

  @Test
  void read_whenApprovalBytesDifferFromAuthenticatedDigest_expectRejected() throws Exception {
    Path approvalFile = tempDir.resolve("publisher-approval.json");
    Files.writeString(approvalFile, approvalJson(""), StandardCharsets.UTF_8);
    String authenticatedDigest = sha256(Files.readAllBytes(approvalFile));
    Files.writeString(approvalFile, approvalJson(" "), StandardCharsets.UTF_8);

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () -> PilotPublisherApprovalReader.read(approvalFile, authenticatedDigest));

    assertTrue(exception.getMessage().contains("digest differs"));
  }

  @Test
  void read_whenApprovalContainsUnknownField_expectRejected() throws Exception {
    Path approvalFile = tempDir.resolve("publisher-approval.json");
    String json =
        approvalJson("").replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"external\":true");
    Files.writeString(approvalFile, json, StandardCharsets.UTF_8);

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () ->
                PilotPublisherApprovalReader.read(
                    approvalFile, sha256(Files.readAllBytes(approvalFile))));

    assertTrue(exception.getMessage().contains("missing or unsupported fields"));
  }

  @Test
  void read_whenApprovalParentDirectoryIsSymlink_expectRejected() throws Exception {
    Path actualDirectory = Files.createDirectory(tempDir.resolve("actual"));
    Path approvalFile = actualDirectory.resolve("publisher-approval.json");
    Files.writeString(approvalFile, approvalJson(""), StandardCharsets.UTF_8);
    Path symlinkDirectory = tempDir.resolve("linked");
    createFixtureAlias(symlinkDirectory, actualDirectory);
    Path linkedApproval = symlinkDirectory.resolve(approvalFile.getFileName());

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () ->
                PilotPublisherApprovalReader.read(
                    linkedApproval, sha256(Files.readAllBytes(approvalFile))));

    assertTrue(exception.getMessage().contains("must not use symbolic links"));
  }

  @Test
  void read_whenFixtureOwnsTempAlias_expectResolvedRootAcceptedAndRawAliasRejected()
      throws Exception {
    Path ownedDirectory = Files.createDirectory(tempDir.resolve("owned approval é"));
    Path aliasDirectory = createFixtureAlias(tempDir.resolve("fixture-alias"), ownedDirectory);
    Path realFixtureRoot = aliasDirectory.toRealPath();
    Path approvalFile = realFixtureRoot.resolve("publisher-approval.json");
    Files.writeString(approvalFile, approvalJson(""), StandardCharsets.UTF_8);
    String authenticatedDigest = sha256(Files.readAllBytes(approvalFile));

    PilotPublisherVerificationPolicy.Approval approval =
        PilotPublisherApprovalReader.read(approvalFile, authenticatedDigest);

    assertEquals("pilot-294", approval.pilotId());
    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () ->
                PilotPublisherApprovalReader.read(
                    aliasDirectory.resolve("publisher-approval.json"), authenticatedDigest));
    assertTrue(exception.getMessage().contains("must not use symbolic links"));
  }

  private static Path createFixtureAlias(Path alias, Path target) throws IOException {
    try {
      return Files.createSymbolicLink(alias, target);
    } catch (UnsupportedOperationException _) {
      return Assumptions.abort("filesystem-provider-symbolic-links-unsupported");
    }
  }

  private static String approvalJson(String trailingWhitespace) {
    return """
    {
      "schemaVersion":1,
      "kind":"stable-1.0-pilot-publisher-key-approval",
      "pilotId":"pilot-294",
      "appId":"org.external.pilot",
      "provenance":{},
      "publisherKeyId":"external-publisher-294",
      "publisherFingerprint":"sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "sourceRepositoryIdentity":"github.com/external/pilot",
      "handoffDigest":"sha256:4444444444444444444444444444444444444444444444444444444444444444",
      "pilotNodeId":"node-294",
      "nodeAttestationFingerprint":"sha256:5555555555555555555555555555555555555555555555555555555555555555",
      "normalStableRegistryDigest":"%s",
      "catalogRegistryDigest":"%s",
      "pilotRegistryDigest":"%s",
      "permittedSubjects":[
        {"version":"1.0.0","bundleDigest":"sha256:6666666666666666666666666666666666666666666666666666666666666666","bundleSignatureDigest":"sha256:7777777777777777777777777777777777777777777777777777777777777777"},
        {"version":"2.0.0","bundleDigest":"sha256:8888888888888888888888888888888888888888888888888888888888888888","bundleSignatureDigest":"sha256:9999999999999999999999999999999999999999999999999999999999999999"},
        {"version":"3.0.0","bundleDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bundleSignatureDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
      ],
      "allowedOperations":["install","update","caution-update","rollback","cleanup"],
      "validFrom":"2026-08-24T00:00:00Z",
      "validUntil":"2026-08-25T00:00:00Z",
      "revoked":false,
      "cleanupRequired":true,
      "approvalAuthorityKeyId":"reviewer-294",
      "receiptDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "signatureBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    }%s
    """
        .formatted(NORMAL_DIGEST, CATALOG_DIGEST, PILOT_DIGEST, trailingWhitespace);
  }

  private static String sha256(byte[] bytes) throws Exception {
    return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
}
