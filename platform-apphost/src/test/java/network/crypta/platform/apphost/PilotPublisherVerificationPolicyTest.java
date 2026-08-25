package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PilotPublisherVerificationPolicyTest {
  private static final String PILOT_ID = "external-pilot-294";
  private static final String NODE_ID = "isolated-node-294";
  private static final String APP_ID = "org.external.pilot";
  private static final String KEY_ID = "external-publisher-294";
  private static final String VERSION = "1.0.0";
  private static final String SIGNATURE_ALGORITHM = "Ed25519";
  private static final String OVERLAP_MESSAGE_FRAGMENT = "overlap";
  private static final String NORMAL_REGISTRY_DIGEST =
      "sha256:1111111111111111111111111111111111111111111111111111111111111111";
  private static final String CATALOG_REGISTRY_DIGEST =
      "sha256:3333333333333333333333333333333333333333333333333333333333333333";
  private static final String PILOT_REGISTRY_DIGEST =
      "sha256:2222222222222222222222222222222222222222222222222222222222222222";
  private static final Instant NOW = Instant.parse("2026-08-23T12:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

  @TempDir Path tempDir;

  private KeyPair publisherKeyPair;
  private TrustedAppKeys pilotKeys;

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException {
    publisherKeyPair = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM).generateKeyPair();
    pilotKeys =
        TrustedAppKeys.of(
            new TrustedAppKey(KEY_ID, SIGNATURE_ALGORITHM, publisherKeyPair.getPublic()));
  }

  @Test
  void verifyCopiedBundle_whenExactPilotSubjectIsSigned_expectInstallAndRollbackAccepted()
      throws Exception {
    Path bundle = signedBundle("exact", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    AppInstallVerificationPolicy policy = policy(approval(bundle, false, NODE_ID));

    assertDoesNotThrow(() -> policy.verifyCopiedBundle(bundle));
    assertDoesNotThrow(() -> policy.verifyHistoricalCopiedBundle(bundle));
  }

  @Test
  void verifyCopiedBundle_whenNormalStablePublisherSignsBundle_expectStableTrustPreserved()
      throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM).generateKeyPair();
    Path approved = signedBundle("approved-external", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    Path stableBundle =
        signedBundle("stable", "org.crypta.first-party", VERSION, stableKeyPair, "stable-app");
    TrustedAppKeys stableKeys =
        TrustedAppKeys.of(
            new TrustedAppKey("stable-app", SIGNATURE_ALGORITHM, stableKeyPair.getPublic()));
    AppInstallVerificationPolicy policy =
        PilotPublisherVerificationPolicy.create(
            PILOT_ID,
            NODE_ID,
            approval(approved, false, NODE_ID),
            new PilotPublisherVerificationPolicy.Registries(
                stableKeys,
                NORMAL_REGISTRY_DIGEST,
                TrustedAppKeys.empty(),
                CATALOG_REGISTRY_DIGEST,
                pilotKeys,
                PILOT_REGISTRY_DIGEST),
            CLOCK);

    assertDoesNotThrow(() -> policy.verifyCopiedBundle(stableBundle));
    assertDoesNotThrow(() -> policy.verifyHistoricalCopiedBundle(stableBundle));
  }

  @Test
  void verifyCopiedBundle_whenSamePublisherSignsUnrelatedApp_expectRejected() throws Exception {
    Path approved = signedBundle("approved", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    Path unrelated =
        signedBundle("unrelated", "org.external.unrelated", VERSION, publisherKeyPair, KEY_ID);
    AppInstallVerificationPolicy policy = policy(approval(approved, false, NODE_ID));

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class, () -> policy.verifyCopiedBundle(unrelated));

    assertTrue(exception.getMessage().contains("does not authorize this app id"));
  }

  @Test
  void verifyCopiedBundle_whenVersionIsOutsideApproval_expectRejected() throws Exception {
    Path approved = signedBundle("approved", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    Path otherVersion = signedBundle("other-version", APP_ID, "2.0.0", publisherKeyPair, KEY_ID);
    AppInstallVerificationPolicy policy = policy(approval(approved, false, NODE_ID));

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class, () -> policy.verifyCopiedBundle(otherVersion));

    assertTrue(exception.getMessage().contains("does not authorize this app version"));
  }

  @Test
  void verifyCopiedBundle_whenSignatureSidecarSubjectDrifts_expectRejected() throws Exception {
    Path bundle = signedBundle("drift", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    PilotPublisherVerificationPolicy.Approval approval =
        new PilotPublisherVerificationPolicy.Approval(
            PILOT_ID,
            NODE_ID,
            APP_ID,
            KEY_ID,
            sha256(publisherKeyPair.getPublic().getEncoded()),
            NORMAL_REGISTRY_DIGEST,
            CATALOG_REGISTRY_DIGEST,
            PILOT_REGISTRY_DIGEST,
            NOW.minusSeconds(60),
            NOW.plusSeconds(60),
            false,
            List.of(
                new PilotPublisherVerificationPolicy.Subject(
                    VERSION,
                    sha256("another-signature-sidecar".getBytes(StandardCharsets.UTF_8)))));
    AppInstallVerificationPolicy policy = policy(approval);

    AppBundleVerificationException exception =
        assertThrows(AppBundleVerificationException.class, () -> policy.verifyCopiedBundle(bundle));

    assertTrue(exception.getMessage().contains("signature sidecar differs"));
  }

  @Test
  void create_whenApprovalIsBoundToAnotherNode_expectRejected() throws Exception {
    Path bundle = signedBundle("wrong-node", APP_ID, VERSION, publisherKeyPair, KEY_ID);

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () -> policy(approval(bundle, false, "another-node")));

    assertTrue(exception.getMessage().contains("another pilot node"));
  }

  @Test
  void create_whenApprovalIsBoundToAnotherPilot_expectRejected() throws Exception {
    Path bundle = signedBundle("wrong-pilot", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    PilotPublisherVerificationPolicy.Approval approved = approval(bundle, false, NODE_ID);
    PilotPublisherVerificationPolicy.Approval anotherPilot =
        new PilotPublisherVerificationPolicy.Approval(
            "another-pilot",
            approved.pilotNodeId(),
            approved.appId(),
            approved.publisherKeyId(),
            approved.publisherFingerprintSha256(),
            approved.normalStableRegistryDigest(),
            approved.catalogRegistryDigest(),
            approved.pilotRegistryDigest(),
            approved.validFrom(),
            approved.validUntil(),
            false,
            approved.subjects());

    AppHostConfigurationException exception =
        assertThrows(AppHostConfigurationException.class, () -> policy(anotherPilot));

    assertTrue(exception.getMessage().contains("another pilot"));
  }

  @Test
  void create_whenApprovalIsExpired_expectRejected() throws Exception {
    Path bundle = signedBundle("expired", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    PilotPublisherVerificationPolicy.Approval approved = approval(bundle, false, NODE_ID);
    PilotPublisherVerificationPolicy.Approval expired =
        new PilotPublisherVerificationPolicy.Approval(
            approved.pilotId(),
            approved.pilotNodeId(),
            approved.appId(),
            approved.publisherKeyId(),
            approved.publisherFingerprintSha256(),
            approved.normalStableRegistryDigest(),
            approved.catalogRegistryDigest(),
            approved.pilotRegistryDigest(),
            NOW.minusSeconds(120),
            NOW.minusSeconds(60),
            false,
            approved.subjects());

    AppHostConfigurationException exception =
        assertThrows(AppHostConfigurationException.class, () -> policy(expired));

    assertTrue(exception.getMessage().contains("validity window"));
  }

  @Test
  void create_whenApprovalIsRevoked_expectRejected() throws Exception {
    Path bundle = signedBundle("revoked", APP_ID, VERSION, publisherKeyPair, KEY_ID);

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class, () -> policy(approval(bundle, true, NODE_ID)));

    assertTrue(exception.getMessage().contains("revoked"));
  }

  @Test
  void create_whenPublisherFingerprintDiffers_expectRejected() throws Exception {
    Path bundle = signedBundle("fingerprint", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    PilotPublisherVerificationPolicy.Approval approved = approval(bundle, false, NODE_ID);
    PilotPublisherVerificationPolicy.Approval substituted =
        new PilotPublisherVerificationPolicy.Approval(
            approved.pilotId(),
            approved.pilotNodeId(),
            approved.appId(),
            approved.publisherKeyId(),
            sha256("wrong-key".getBytes(StandardCharsets.UTF_8)),
            approved.normalStableRegistryDigest(),
            approved.catalogRegistryDigest(),
            approved.pilotRegistryDigest(),
            approved.validFrom(),
            approved.validUntil(),
            false,
            approved.subjects());

    AppHostConfigurationException exception =
        assertThrows(AppHostConfigurationException.class, () -> policy(substituted));

    assertTrue(exception.getMessage().contains("fingerprint differs"));
  }

  @Test
  void create_whenExternalKeyIsInNormalStableRegistry_expectRejected() throws Exception {
    Path bundle = signedBundle(OVERLAP_MESSAGE_FRAGMENT, APP_ID, VERSION, publisherKeyPair, KEY_ID);
    PilotPublisherVerificationPolicy.Approval approval = approval(bundle, false, NODE_ID);
    PilotPublisherVerificationPolicy.Registries registries =
        new PilotPublisherVerificationPolicy.Registries(
            pilotKeys,
            NORMAL_REGISTRY_DIGEST,
            TrustedAppKeys.empty(),
            CATALOG_REGISTRY_DIGEST,
            pilotKeys,
            PILOT_REGISTRY_DIGEST);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                PilotPublisherVerificationPolicy.create(
                    PILOT_ID, NODE_ID, approval, registries, CLOCK));

    assertTrue(exception.getMessage().contains(OVERLAP_MESSAGE_FRAGMENT));
  }

  @Test
  void create_whenPilotRegistryContainsAnotherPublisher_expectRejected() throws Exception {
    Path bundle = signedBundle("extra-publisher", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    KeyPair extraKeyPair = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM).generateKeyPair();
    TrustedAppKeys expandedPilotKeys =
        pilotKeys.plus(
            new TrustedAppKey("another-publisher", SIGNATURE_ALGORITHM, extraKeyPair.getPublic()));

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () ->
                PilotPublisherVerificationPolicy.create(
                    PILOT_ID,
                    NODE_ID,
                    approval(bundle, false, NODE_ID),
                    new PilotPublisherVerificationPolicy.Registries(
                        TrustedAppKeys.empty(),
                        NORMAL_REGISTRY_DIGEST,
                        TrustedAppKeys.empty(),
                        CATALOG_REGISTRY_DIGEST,
                        expandedPilotKeys,
                        PILOT_REGISTRY_DIGEST),
                    CLOCK));

    assertTrue(exception.getMessage().contains("only the approved"));
  }

  @Test
  void create_whenRegistryDigestDiffersFromApproval_expectRejected() throws Exception {
    Path bundle = signedBundle("registry-digest", APP_ID, VERSION, publisherKeyPair, KEY_ID);

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () ->
                PilotPublisherVerificationPolicy.create(
                    PILOT_ID,
                    NODE_ID,
                    approval(bundle, false, NODE_ID),
                    new PilotPublisherVerificationPolicy.Registries(
                        TrustedAppKeys.empty(),
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        TrustedAppKeys.empty(),
                        CATALOG_REGISTRY_DIGEST,
                        pilotKeys,
                        PILOT_REGISTRY_DIGEST),
                    CLOCK));

    assertTrue(exception.getMessage().contains("normal Stable registry digest differs"));
  }

  @Test
  void create_whenCatalogRegistryDigestDiffersFromApproval_expectRejected() throws Exception {
    Path bundle = signedBundle("catalog-digest", APP_ID, VERSION, publisherKeyPair, KEY_ID);

    AppHostConfigurationException exception =
        assertThrows(
            AppHostConfigurationException.class,
            () ->
                PilotPublisherVerificationPolicy.create(
                    PILOT_ID,
                    NODE_ID,
                    approval(bundle, false, NODE_ID),
                    new PilotPublisherVerificationPolicy.Registries(
                        TrustedAppKeys.empty(),
                        NORMAL_REGISTRY_DIGEST,
                        TrustedAppKeys.empty(),
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        pilotKeys,
                        PILOT_REGISTRY_DIGEST),
                    CLOCK));

    assertTrue(exception.getMessage().contains("catalog registry digest differs"));
  }

  @Test
  void create_whenExternalKeyIsInCatalogRegistry_expectRejected() throws Exception {
    Path bundle = signedBundle("catalog-overlap", APP_ID, VERSION, publisherKeyPair, KEY_ID);
    PilotPublisherVerificationPolicy.Approval approval = approval(bundle, false, NODE_ID);
    PilotPublisherVerificationPolicy.Registries registries =
        new PilotPublisherVerificationPolicy.Registries(
            TrustedAppKeys.empty(),
            NORMAL_REGISTRY_DIGEST,
            pilotKeys,
            CATALOG_REGISTRY_DIGEST,
            pilotKeys,
            PILOT_REGISTRY_DIGEST);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                PilotPublisherVerificationPolicy.create(
                    PILOT_ID, NODE_ID, approval, registries, CLOCK));

    assertTrue(exception.getMessage().contains(OVERLAP_MESSAGE_FRAGMENT));
  }

  @Test
  void approval_whenVersionIsDuplicated_expectRejected() {
    PilotPublisherVerificationPolicy.Subject subject =
        new PilotPublisherVerificationPolicy.Subject(
            VERSION, sha256("signature".getBytes(StandardCharsets.UTF_8)));
    String publisherFingerprint = sha256(publisherKeyPair.getPublic().getEncoded());
    Instant validFrom = NOW.minusSeconds(60);
    Instant validUntil = NOW.plusSeconds(60);
    List<PilotPublisherVerificationPolicy.Subject> subjects = List.of(subject, subject);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new PilotPublisherVerificationPolicy.Approval(
                    PILOT_ID,
                    NODE_ID,
                    APP_ID,
                    KEY_ID,
                    publisherFingerprint,
                    NORMAL_REGISTRY_DIGEST,
                    CATALOG_REGISTRY_DIGEST,
                    PILOT_REGISTRY_DIGEST,
                    validFrom,
                    validUntil,
                    false,
                    subjects));

    assertTrue(exception.getMessage().contains("duplicate pilot approval app version"));
  }

  private AppInstallVerificationPolicy policy(PilotPublisherVerificationPolicy.Approval approval)
      throws IOException {
    return PilotPublisherVerificationPolicy.create(
        PILOT_ID,
        NODE_ID,
        approval,
        new PilotPublisherVerificationPolicy.Registries(
            TrustedAppKeys.empty(),
            NORMAL_REGISTRY_DIGEST,
            TrustedAppKeys.empty(),
            CATALOG_REGISTRY_DIGEST,
            pilotKeys,
            PILOT_REGISTRY_DIGEST),
        CLOCK);
  }

  private PilotPublisherVerificationPolicy.Approval approval(
      Path bundle, boolean revoked, String nodeId) throws IOException {
    return new PilotPublisherVerificationPolicy.Approval(
        PILOT_ID,
        nodeId,
        APP_ID,
        KEY_ID,
        sha256(publisherKeyPair.getPublic().getEncoded()),
        NORMAL_REGISTRY_DIGEST,
        CATALOG_REGISTRY_DIGEST,
        PILOT_REGISTRY_DIGEST,
        NOW.minusSeconds(60),
        NOW.plusSeconds(60),
        revoked,
        List.of(
            new PilotPublisherVerificationPolicy.Subject(
                VERSION,
                sha256(
                    Files.readAllBytes(bundle.resolve(AppBundleSignature.SIGNATURE_FILE_NAME))))));
  }

  private Path signedBundle(
      String directory, String appId, String version, KeyPair keyPair, String keyId)
      throws IOException {
    Path bundle = Files.createDirectories(tempDir.resolve(directory));
    Files.writeString(
        bundle.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=Pilot App
        app.version=%s
        app.exec=bin/start.sh
        """
            .formatted(appId, version),
        StandardCharsets.UTF_8);
    Path bin = Files.createDirectories(bundle.resolve("bin"));
    Files.writeString(bin.resolve("start.sh"), "echo pilot\n", StandardCharsets.UTF_8);
    AppBundleSigner.sign(bundle, keyId, keyPair.getPrivate());
    return bundle;
  }

  private static String sha256(byte[] value) {
    try {
      return "sha256:"
          + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    } catch (Exception exception) {
      throw new AssertionError(exception);
    }
  }
}
