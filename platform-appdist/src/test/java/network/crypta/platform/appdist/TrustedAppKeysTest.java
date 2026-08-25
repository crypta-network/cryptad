package network.crypta.platform.appdist;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustedAppKeysTest {
  @TempDir Path tempDir;

  @Test
  void load_whenTrustedKeysFileStartsWithUtf8Bom_expectTrustedKeyParsed() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys.properties");
    Files.writeString(
        trustedKeysFile,
        "\uFEFF"
            + """
            trusted.keys.version=1
            key.0.id=local-dev
            key.0.algorithm=Ed25519
            key.0.public.key.base64=%s
            """
                .formatted(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())),
        StandardCharsets.UTF_8);

    TrustedAppKeys trustedKeys = TrustedAppKeys.load(trustedKeysFile);

    assertTrue(trustedKeys.find("local-dev").isPresent());
  }

  @Test
  void load_whenCapturedBytesOutlivePathReplacement_expectCapturedRegistryParsed()
      throws Exception {
    KeyPair originalKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair replacementKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("captured-trusted-keys.properties");
    Files.writeString(
        trustedKeysFile,
        versionOneRegistry("original-key", originalKeyPair),
        StandardCharsets.UTF_8);
    byte[] capturedBytes = Files.readAllBytes(trustedKeysFile);
    Files.writeString(
        trustedKeysFile,
        versionOneRegistry("replacement-key", replacementKeyPair),
        StandardCharsets.UTF_8);

    TrustedAppKeys capturedKeys = TrustedAppKeys.load(capturedBytes);
    TrustedAppKeys replacementKeys = TrustedAppKeys.load(trustedKeysFile);

    assertTrue(capturedKeys.find("original-key").isPresent());
    assertFalse(capturedKeys.find("replacement-key").isPresent());
    assertTrue(replacementKeys.find("replacement-key").isPresent());
    assertFalse(replacementKeys.find("original-key").isPresent());
  }

  @Test
  void load_whenVersionTwoLifecycleIsComplete_expectPolicyParsed() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys-v2.properties");
    Files.writeString(
        trustedKeysFile,
        """
        trusted.keys.version=2
        key.0.id=retired-app-key
        key.0.algorithm=Ed25519
        key.0.public.key.base64=%s
        key.0.status=retired
        key.0.valid.from=2025-01-01T00:00:00Z
        key.0.valid.until=2030-01-01T00:00:00Z
        """
            .formatted(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())),
        StandardCharsets.UTF_8);

    TrustedAppKeyPolicy policy =
        TrustedAppKeys.load(trustedKeysFile).findPolicy("retired-app-key").orElseThrow();

    assertEquals(TrustedAppKeyLifecycle.RETIRED, policy.lifecycle());
    assertEquals(Instant.parse("2025-01-01T00:00:00Z"), policy.validFrom());
    assertEquals(Instant.parse("2030-01-01T00:00:00Z"), policy.validUntil());
    assertFalse(policy.allowsNewBundleVerification(Instant.parse("2026-01-01T00:00:00Z")));
    assertTrue(policy.allowsHistoricalBundleVerification(Instant.parse("2026-01-01T00:00:00Z")));
  }

  @ParameterizedTest(name = "{index}: keyId={0}")
  @CsvSource(
      delimiter = '|',
      nullValues = "<missing>",
      textBlock =
          """
          incomplete-app-key     | <missing> | 2025-01-01T00:00:00Z | 2030-01-01T00:00:00Z | trusted key 0 is incomplete
          unknown-status-app-key | staged    | 2025-01-01T00:00:00Z | 2030-01-01T00:00:00Z | unsupported trusted app key status: staged
          reversed-app-key       | active    | 2030-01-01T00:00:00Z | 2025-01-01T00:00:00Z | trusted key 0 has an invalid validity window
          """)
  void load_whenVersionTwoPolicyIsInvalid_expectRegistryRejected(
      String keyId, String lifecycle, String validFrom, String validUntil, String expectedMessage)
      throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys-v2-" + keyId + ".properties");
    String lifecycleProperty = lifecycle == null ? "" : "key.0.status=" + lifecycle;
    Files.writeString(
        trustedKeysFile,
        """
        trusted.keys.version=2
        key.0.id=%s
        key.0.algorithm=Ed25519
        key.0.public.key.base64=%s
        %s
        key.0.valid.from=%s
        key.0.valid.until=%s
        """
            .formatted(
                keyId,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                lifecycleProperty,
                validFrom,
                validUntil),
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, () -> TrustedAppKeys.load(trustedKeysFile));

    assertEquals(expectedMessage, exception.getMessage());
  }

  @Test
  void load_whenVersionTwoPublicKeyHasActiveAndRevokedAliases_expectRegistryRejected()
      throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    Path trustedKeysFile = tempDir.resolve("trusted-keys-v2-aliased.properties");
    Files.writeString(
        trustedKeysFile,
        """
        trusted.keys.version=2
        key.0.id=revoked-app-key
        key.0.algorithm=Ed25519
        key.0.public.key.base64=%s
        key.0.status=revoked
        key.0.valid.from=2025-01-01T00:00:00Z
        key.0.valid.until=2030-01-01T00:00:00Z
        key.1.id=active-app-key-alias
        key.1.algorithm=Ed25519
        key.1.public.key.base64=%s
        key.1.status=active
        key.1.valid.from=2025-01-01T00:00:00Z
        key.1.valid.until=2030-01-01T00:00:00Z
        """
            .formatted(publicKey, publicKey),
        StandardCharsets.UTF_8);

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, () -> TrustedAppKeys.load(trustedKeysFile));

    assertEquals(
        "trusted keys file is ambiguous: duplicate trusted public-key fingerprint for key ids: "
            + "revoked-app-key and active-app-key-alias",
        exception.getMessage());
  }

  @Test
  void load_whenVersionOneRegistryUsed_expectActiveCompatibilityPolicy() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys-v1.properties");
    Files.writeString(
        trustedKeysFile,
        """
        trusted.keys.version=1
        key.0.id=legacy-app-key
        key.0.algorithm=Ed25519
        key.0.public.key.base64=%s
        """
            .formatted(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())),
        StandardCharsets.UTF_8);

    TrustedAppKeyPolicy policy =
        TrustedAppKeys.load(trustedKeysFile).findPolicy("legacy-app-key").orElseThrow();

    assertEquals(TrustedAppKeyLifecycle.ACTIVE, policy.lifecycle());
    assertTrue(policy.allowsNewBundleVerification(Instant.now()));
  }

  @Test
  void requireDisjointFrom_whenKeyIdsAndPublicKeysDiffer_expectAccepted() throws Exception {
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair appKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustedAppKeys catalogKeys =
        TrustedAppKeys.of(new TrustedAppKey("catalog-key", "Ed25519", catalogKeyPair.getPublic()));
    TrustedAppKeys appKeys =
        TrustedAppKeys.of(new TrustedAppKey("app-key", "Ed25519", appKeyPair.getPublic()));

    assertDoesNotThrow(() -> catalogKeys.requireDisjointFrom(appKeys));
  }

  @Test
  void requireDisjointFrom_whenKeyIdIsReusedWithDifferentPublicKey_expectRejected()
      throws Exception {
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair appKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustedAppKeys catalogKeys =
        TrustedAppKeys.of(
            new TrustedAppKey("shared-key-id", "Ed25519", catalogKeyPair.getPublic()));
    TrustedAppKeys appKeys =
        TrustedAppKeys.of(new TrustedAppKey("shared-key-id", "Ed25519", appKeyPair.getPublic()));

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> catalogKeys.requireDisjointFrom(appKeys));

    assertEquals("trusted key registries overlap on key id: shared-key-id", exception.getMessage());
  }

  @Test
  void requireDisjointFrom_whenPublicKeyIsReusedWithDifferentKeyId_expectRejected()
      throws Exception {
    KeyPair sharedKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustedAppKeys catalogKeys =
        TrustedAppKeys.of(new TrustedAppKey("catalog-key", "Ed25519", sharedKeyPair.getPublic()));
    TrustedAppKeys appKeys =
        TrustedAppKeys.of(new TrustedAppKey("app-key", "Ed25519", sharedKeyPair.getPublic()));

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class, () -> catalogKeys.requireDisjointFrom(appKeys));

    assertEquals(
        "trusted key registries overlap on public-key fingerprint", exception.getMessage());
  }

  @Test
  void requireDisjointFrom_whenRevokedPublicKeyIsReusedAcrossRoles_expectRejected()
      throws Exception {
    KeyPair sharedKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustedAppKey appKey = new TrustedAppKey("app-key", "Ed25519", sharedKeyPair.getPublic());
    TrustedAppKeys catalogKeys =
        TrustedAppKeys.of(new TrustedAppKey("catalog-key", "Ed25519", sharedKeyPair.getPublic()));
    TrustedAppKeys appKeys =
        TrustedAppKeys.ofPolicies(
            new TrustedAppKeyPolicy(
                appKey,
                TrustedAppKeyLifecycle.REVOKED,
                Instant.parse("2025-01-01T00:00:00Z"),
                Instant.parse("2030-01-01T00:00:00Z")));

    assertThrows(IllegalArgumentException.class, () -> catalogKeys.requireDisjointFrom(appKeys));
  }

  @Test
  void ofPolicies_whenPublicKeyHasDifferentLifecycleAliases_expectRejected() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustedAppKey activeKey = new TrustedAppKey("active-app-key", "Ed25519", keyPair.getPublic());
    TrustedAppKey revokedAlias =
        new TrustedAppKey("revoked-app-key-alias", "Ed25519", keyPair.getPublic());
    Instant validFrom = Instant.parse("2025-01-01T00:00:00Z");
    Instant validUntil = Instant.parse("2030-01-01T00:00:00Z");
    TrustedAppKeyPolicy activePolicy =
        new TrustedAppKeyPolicy(activeKey, TrustedAppKeyLifecycle.ACTIVE, validFrom, validUntil);
    TrustedAppKeyPolicy revokedPolicy =
        new TrustedAppKeyPolicy(
            revokedAlias, TrustedAppKeyLifecycle.REVOKED, validFrom, validUntil);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> TrustedAppKeys.ofPolicies(activePolicy, revokedPolicy));

    assertEquals(
        "duplicate trusted public-key fingerprint for key ids: active-app-key and "
            + "revoked-app-key-alias",
        exception.getMessage());
  }

  @Test
  void plus_whenDirectKeyAliasesExistingPublicKey_expectRejected() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(new TrustedAppKey("configured-app-key", "Ed25519", keyPair.getPublic()));
    TrustedAppKey alias = new TrustedAppKey("direct-app-key-alias", "Ed25519", keyPair.getPublic());

    IllegalArgumentException exception =
        assertThrows(IllegalArgumentException.class, () -> trustedKeys.plus(alias));

    assertEquals(
        "duplicate trusted public-key fingerprint for key ids: configured-app-key and "
            + "direct-app-key-alias",
        exception.getMessage());
  }

  private static String versionOneRegistry(String keyId, KeyPair keyPair) {
    return """
    trusted.keys.version=1
    key.0.id=%s
    key.0.algorithm=Ed25519
    key.0.public.key.base64=%s
    """
        .formatted(keyId, Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
  }
}
