package network.crypta.platform.appvault;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppVaultServiceTest {
  private static final String ALGORITHM_ED25519 = "Ed25519";
  private static final String APP_ID = "demo.app";
  private static final String APP_SIGNING_KEY_LABEL = "App signing key";
  private static final String COPIED_IDENTITY_ID = "id-copy";
  private static final String ERROR_CORRUPT_VAULT_RECORD = "corrupt_vault_record";
  private static final String ERROR_VAULT_STORAGE_FAILED = "vault_storage_failed";
  private static final String EXPIRED_APP_ID = "expired.app";
  private static final String GRANT_REASON_SIGNING = "signing";
  private static final String GRANTED_BY_OPERATOR = "operator";
  private static final String MALFORMED_TIMESTAMP = "not-an-instant";
  private static final String METADATA_KEY_LABEL = "label";
  private static final String METADATA_PROPERTIES = "metadata.properties";
  private static final String MODE_MISSING = "missing";
  private static final String OPERATOR_PUBLISHER_LABEL = "Operator publisher";
  private static final String OTHER_APP_ID = "other.app";
  private static final String OTHER_SECRET_NAME = "other-token";
  private static final String PAYLOAD = "payload";
  private static final String PROPERTY_CREATED_AT = "createdAt";
  private static final String PROPERTY_UPDATED_AT = "updatedAt";
  private static final String PURPOSE_FEED_PUBLISH = "feed.publish";
  private static final String SECRET_KIND_API_TOKEN_PLACEHOLDER = "api-token-placeholder";
  private static final String SECRET_KIND_GENERIC = "generic";
  private static final String SECRET_NAME = "api-token";
  private static final String SECRET_VALUE = "value";
  private static final String VISIBLE_LABEL_VALUE = "visible";

  @TempDir private Path tempDir;

  @Test
  void normalizeSecretName_whenUnsafeOrReservedName_expectRejected() {
    assertEquals("api-token_1", AppVaultPaths.normalizeSecretName("  API-Token_1  "));

    String[] unsafeNames = {
      "../token",
      "token/../other",
      "token\\other",
      ".",
      "..",
      "a..b",
      "con",
      "nul.txt",
      "api token",
      "api-token."
    };
    for (String unsafeName : unsafeNames) {
      assertThrows(AppVaultException.class, () -> AppVaultPaths.normalizeSecretName(unsafeName));
    }
  }

  @Test
  void readSecretValue_whenStoredBySameAppAndName_expectRoundTrip() throws IOException {
    AppVaultService service = service();
    byte[] secret = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

    AppSecretRecord secretRecord =
        service.putSecret(
            APP_ID,
            SECRET_NAME,
            SECRET_KIND_API_TOKEN_PLACEHOLDER,
            secret,
            Map.of(METADATA_KEY_LABEL, "primary", "token", "do-not-leak"));

    assertEquals("small", secretRecord.sizeClass());
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("token"));
    assertArrayEquals(secret, service.readSecretValue(APP_ID, SECRET_NAME));
  }

  @Test
  void listSecrets_whenSecretExists_expectNoSecretValueInPublicMetadata() throws IOException {
    AppVaultService service = service();
    String rawSecret = "raw-secret-value";

    service.putSecret(
        APP_ID,
        SECRET_NAME,
        SECRET_KIND_API_TOKEN_PLACEHOLDER,
        rawSecret.getBytes(StandardCharsets.UTF_8),
        Map.of(METADATA_KEY_LABEL, VISIBLE_LABEL_VALUE, "accessToken", rawSecret));

    String publicStatus = service.listSecrets(APP_ID).toString() + service.appStatus(APP_ID);

    assertFalse(publicStatus.contains(rawSecret));
    assertTrue(publicStatus.contains(AppVaultMetadata.REDACTED_VALUE));
  }

  @Test
  void putSecret_whenMetadataContainsAuthorizationHeaders_expectCredentialValuesRedactedOnDisk()
      throws IOException {
    AppVaultService service = service();
    String authorization = "Bearer raw-authorization-value";
    String proxyAuthorization = "Basic raw-proxy-authorization-value";
    String cookie = "sid=raw-cookie-value";
    String setCookie = "session=raw-set-cookie-value";

    AppSecretRecord secretRecord =
        service.putSecret(
            APP_ID,
            SECRET_NAME,
            SECRET_KIND_API_TOKEN_PLACEHOLDER,
            bytes(SECRET_VALUE),
            Map.of(
                "authorization",
                authorization,
                "proxy-authorization",
                proxyAuthorization,
                "cookie",
                cookie,
                "set-cookie",
                setCookie,
                METADATA_KEY_LABEL,
                VISIBLE_LABEL_VALUE));

    String persisted =
        Files.readString(paths().secretMetadataPath(APP_ID, SECRET_NAME), StandardCharsets.UTF_8);
    String publicStatus =
        secretRecord + service.listSecrets(APP_ID).toString() + service.appStatus(APP_ID);

    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("authorization"));
    assertEquals(
        AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("proxy-authorization"));
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("cookie"));
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("set-cookie"));
    assertEquals(VISIBLE_LABEL_VALUE, secretRecord.metadata().get(METADATA_KEY_LABEL));
    assertFalse(persisted.contains(authorization));
    assertFalse(persisted.contains(proxyAuthorization));
    assertFalse(persisted.contains(cookie));
    assertFalse(persisted.contains(setCookie));
    assertFalse(publicStatus.contains(authorization));
    assertFalse(publicStatus.contains(proxyAuthorization));
    assertFalse(publicStatus.contains(cookie));
    assertFalse(publicStatus.contains(setCookie));
  }

  @Test
  void putSecret_whenMetadataContainsSeedRecoveryMnemonic_expectValuesRedactedOnDisk()
      throws IOException {
    AppVaultService service = service();
    String identitySeed = "identity-seed-raw-value";
    String seedPhrase = "seed phrase raw value";
    String recoveryPhrase = "recovery phrase raw value";
    String mnemonicPhrase = "mnemonic phrase raw value";
    String accountMnemonic = "account mnemonic raw value";

    AppSecretRecord secretRecord =
        service.putSecret(
            APP_ID,
            SECRET_NAME,
            "app-settings-encrypted-blob",
            bytes(SECRET_VALUE),
            Map.of(
                "identitySeed",
                identitySeed,
                "seedPhrase",
                seedPhrase,
                "recoveryPhrase",
                recoveryPhrase,
                "mnemonicPhrase",
                mnemonicPhrase,
                "accountMnemonic",
                accountMnemonic,
                METADATA_KEY_LABEL,
                VISIBLE_LABEL_VALUE));

    String persisted =
        Files.readString(paths().secretMetadataPath(APP_ID, SECRET_NAME), StandardCharsets.UTF_8);
    String publicStatus =
        secretRecord + service.listSecrets(APP_ID).toString() + service.appStatus(APP_ID);

    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("identitySeed"));
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("seedPhrase"));
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("recoveryPhrase"));
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("mnemonicPhrase"));
    assertEquals(AppVaultMetadata.REDACTED_VALUE, secretRecord.metadata().get("accountMnemonic"));
    assertEquals(VISIBLE_LABEL_VALUE, secretRecord.metadata().get(METADATA_KEY_LABEL));
    for (String forbidden :
        List.of(identitySeed, seedPhrase, recoveryPhrase, mnemonicPhrase, accountMnemonic)) {
      assertFalse(persisted.contains(forbidden), persisted);
      assertFalse(publicStatus.contains(forbidden), publicStatus);
    }
  }

  @Test
  void appStatus_whenActiveVaultMaterialExists_expectNotRetainedUntilAccessBlocked()
      throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    service.grantIdentity(
        identity.identityId(),
        APP_ID,
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        GRANTED_BY_OPERATOR,
        "test grant",
        null,
        null);

    Map<String, Object> activeStatus = service.appStatus(APP_ID);

    assertFalse((Boolean) activeStatus.get("retainedAfterUninstall"));
    assertFalse((Boolean) activeStatus.get("appAccessDisabled"));

    service.disableAppAccess(APP_ID, "app_uninstall_cleanup");
    Map<String, Object> blockedStatus = service.appStatus(APP_ID);

    assertTrue((Boolean) blockedStatus.get("retainedAfterUninstall"));
    assertTrue((Boolean) blockedStatus.get("appAccessDisabled"));
  }

  @Test
  void deleteSecretsForApp_whenSecretsExist_expectValuesPurged() throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());

    assertTrue(service.deleteSecretsForApp(APP_ID));

    assertTrue(service.listSecrets(APP_ID).isEmpty());
    assertEquals(
        "secret_not_found",
        assertThrows(AppVaultException.class, () -> service.readSecretValue(APP_ID, SECRET_NAME))
            .errorCode());
  }

  @Test
  void requireAppAccessAllowed_whenDisabledAfterUninstallCleanup_expectAppOperationsDenied()
      throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());

    service.disableAppAccess(APP_ID, "app_uninstall_cleanup");

    assertTrue(service.appAccessBlocked(APP_ID));
    assertEquals(
        "app_vault_access_disabled",
        assertThrows(AppVaultException.class, () -> service.readSecretValue(APP_ID, SECRET_NAME))
            .errorCode());
    assertEquals(
        "app_vault_access_disabled",
        assertThrows(
                AppVaultException.class,
                () ->
                    service.createAppOwnedIdentity(
                        APP_ID, AppIdentityKind.LOCAL_ED25519_SIGNING, APP_SIGNING_KEY_LABEL, null))
            .errorCode());

    assertTrue(service.clearAppAccessBlock(APP_ID));
    assertFalse(service.appAccessBlocked(APP_ID));
    assertArrayEquals(bytes(SECRET_VALUE), service.readSecretValue(APP_ID, SECRET_NAME));
  }

  @Test
  void putSecret_whenKeyProviderFails_expectNoMetadataCommitted() throws IOException {
    AppVaultService service = serviceWithFailingKeyProvider();
    byte[] secretValue = bytes(SECRET_VALUE);
    Map<String, String> metadata = Map.of();

    AppVaultException exception =
        assertThrows(
            AppVaultException.class,
            () ->
                service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, secretValue, metadata));

    assertEquals(ERROR_VAULT_STORAGE_FAILED, exception.errorCode());
    assertTrue(service.listSecrets(APP_ID).isEmpty());
    assertFalse(Files.exists(paths().secretMetadataPath(APP_ID, SECRET_NAME)));
  }

  @Test
  void writeSecret_whenMetadataCommitFailsAfterMove_expectPreviousRecordAndEnvelopeRestored()
      throws IOException {
    AppVaultPaths paths = paths();
    Path metadataPath = paths.secretMetadataPath(APP_ID, SECRET_NAME);
    AtomicBoolean failMetadataCommit = new AtomicBoolean(false);
    AtomicBoolean failedOnce = new AtomicBoolean(false);
    AppVaultStore store =
        new AppVaultStore(
            paths,
            target -> {
              if (failMetadataCommit.get()
                  && metadataPath.equals(target)
                  && failedOnce.compareAndSet(false, true)) {
                throw new IOException("metadata commit failed");
              }
            });
    store.initialize();
    AppSecretRecord oldRecord =
        secretRecord(SECRET_KIND_GENERIC, Map.of(METADATA_KEY_LABEL, "old"));
    AppVaultEnvelope oldEnvelope = envelope("old-ciphertext");
    store.writeSecret(oldRecord, oldEnvelope);

    failMetadataCommit.set(true);
    IOException exception =
        assertThrows(
            IOException.class,
            () ->
                store.writeSecret(
                    secretRecord("changed-kind", Map.of(METADATA_KEY_LABEL, "new")),
                    envelope("new-ciphertext")));

    assertEquals("metadata commit failed", exception.getMessage());
    AppSecretRecord restoredRecord = store.readSecretRecord(APP_ID, SECRET_NAME);
    assertNotNull(restoredRecord);
    assertEquals(SECRET_KIND_GENERIC, restoredRecord.secretKind());
    assertEquals("old", restoredRecord.metadata().get(METADATA_KEY_LABEL));
    assertEquals(oldEnvelope.toJson(), store.readSecretEnvelope(APP_ID, SECRET_NAME).toJson());
  }

  @Test
  void writeIdentity_whenPrivateEnvelopeCannotBeWritten_expectMetadataNotCommitted()
      throws IOException {
    AppVaultPaths paths = paths();
    AppVaultStore store = new AppVaultStore(paths);
    store.initialize();
    AppIdentityRecord identityRecord = identityRecord("id-private-write-fails");
    Files.createDirectories(paths.identityPrivateEnvelopePath(identityRecord.identityId()));

    assertThrows(IOException.class, () -> store.writeIdentity(identityRecord, envelope()));

    assertFalse(Files.exists(paths.identityMetadataPath(identityRecord.identityId())));
    assertTrue(store.listIdentities().isEmpty());
  }

  @Test
  void writeIdentity_whenMetadataCannotBeWritten_expectPrivateEnvelopeRolledBack()
      throws IOException {
    AppVaultPaths paths = paths();
    AppVaultStore store = new AppVaultStore(paths);
    store.initialize();
    AppIdentityRecord identityRecord = identityRecord("id-metadata-write-fails");
    Files.createDirectories(paths.identityMetadataPath(identityRecord.identityId()));

    assertThrows(IOException.class, () -> store.writeIdentity(identityRecord, envelope()));

    assertFalse(
        Files.isRegularFile(paths.identityPrivateEnvelopePath(identityRecord.identityId())));
    assertTrue(store.listIdentities().isEmpty());
  }

  @Test
  void putSecret_whenReplacingAndKeyProviderFails_expectExistingRecordAndValuePreserved()
      throws IOException {
    AppVaultService service = service();
    byte[] originalValue = bytes("old-value");
    service.putSecret(
        APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, originalValue, Map.of(METADATA_KEY_LABEL, "old"));

    AppVaultService failingService = serviceWithFailingKeyProvider();
    byte[] newValue = bytes("new-value");
    Map<String, String> metadata = Map.of();
    AppVaultException exception =
        assertThrows(
            AppVaultException.class,
            () ->
                failingService.putSecret(APP_ID, SECRET_NAME, "changed-kind", newValue, metadata));

    assertEquals(ERROR_VAULT_STORAGE_FAILED, exception.errorCode());
    assertEquals(SECRET_KIND_GENERIC, service.getSecretRecord(APP_ID, SECRET_NAME).secretKind());
    assertArrayEquals(originalValue, service.readSecretValue(APP_ID, SECRET_NAME));
  }

  @Test
  void readSecretValue_whenMetadataAadChanges_expectAuthenticationFailure() throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());
    AppVaultPaths paths = paths();
    Path metadata = paths.secretMetadataPath(APP_ID, SECRET_NAME);

    Files.writeString(
        metadata,
        Files.readString(metadata, StandardCharsets.UTF_8)
            .replace("secretKind=generic", "secretKind=changed"),
        StandardCharsets.UTF_8);

    AppVaultException exception =
        assertThrows(AppVaultException.class, () -> service.readSecretValue(APP_ID, SECRET_NAME));
    assertEquals("vault_aad_mismatch", exception.errorCode());
  }

  @Test
  void readSecretValue_whenRecordIsCopiedToWrongAppOrName_expectMetadataMismatch()
      throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());
    AppVaultPaths paths = paths();

    copyDefaultSecretDirectory(paths, OTHER_APP_ID, SECRET_NAME);
    copyDefaultSecretDirectory(paths, APP_ID, OTHER_SECRET_NAME);

    assertEquals(
        ERROR_CORRUPT_VAULT_RECORD,
        assertThrows(
                AppVaultException.class, () -> service.readSecretValue(OTHER_APP_ID, SECRET_NAME))
            .errorCode());
    assertEquals(
        ERROR_CORRUPT_VAULT_RECORD,
        assertThrows(
                AppVaultException.class, () -> service.readSecretValue(APP_ID, OTHER_SECRET_NAME))
            .errorCode());
  }

  @Test
  void listSecrets_whenRecordIsCopiedToWrongAppOrName_expectMetadataMismatch() throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());
    AppVaultPaths paths = paths();

    copyDefaultSecretDirectory(paths, OTHER_APP_ID, SECRET_NAME);
    copyDefaultSecretDirectory(paths, APP_ID, OTHER_SECRET_NAME);

    assertEquals(
        ERROR_CORRUPT_VAULT_RECORD,
        assertThrows(AppVaultException.class, () -> service.listSecrets(OTHER_APP_ID)).errorCode());
    assertEquals(
        ERROR_CORRUPT_VAULT_RECORD,
        assertThrows(AppVaultException.class, () -> service.listSecrets(APP_ID)).errorCode());
  }

  @Test
  void getSecretRecord_whenRequiredTimestampMissingOrMalformed_expectCorruptVaultRecord()
      throws IOException {
    for (String field : List.of(PROPERTY_CREATED_AT, PROPERTY_UPDATED_AT)) {
      for (String mode : List.of(MODE_MISSING, "malformed")) {
        AppVaultPaths paths = new AppVaultPaths(tempDir.resolve("secret-" + field + "-" + mode));
        AppVaultService service = AppVaultService.open(paths.root());
        service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());
        Path metadata = paths.secretMetadataPath(APP_ID, SECRET_NAME);
        if (MODE_MISSING.equals(mode)) {
          removeProperty(metadata, field);
        } else {
          replacePropertyWithMalformedTimestamp(metadata, field);
        }

        AppVaultException exception =
            assertThrows(
                AppVaultException.class, () -> service.getSecretRecord(APP_ID, SECRET_NAME));

        assertEquals(ERROR_CORRUPT_VAULT_RECORD, exception.errorCode());
      }
    }
  }

  @Test
  void readSecretValue_whenEnvelopeIsCorrupt_expectSafeFailure() throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());

    Files.writeString(
        paths().secretEnvelopePath(APP_ID, SECRET_NAME), "not-json", StandardCharsets.UTF_8);

    assertEquals(
        "invalid_vault_envelope",
        assertThrows(AppVaultException.class, () -> service.readSecretValue(APP_ID, SECRET_NAME))
            .errorCode());
  }

  @Test
  void readSecretValue_whenEnvelopeTimestampMalformed_expectSafeFailure() throws IOException {
    AppVaultService service = service();
    service.putSecret(APP_ID, SECRET_NAME, SECRET_KIND_GENERIC, bytes(SECRET_VALUE), Map.of());
    Path envelopePath = paths().secretEnvelopePath(APP_ID, SECRET_NAME);
    String envelopeJson = Files.readString(envelopePath, StandardCharsets.UTF_8);
    Files.writeString(
        envelopePath,
        envelopeJson.replaceFirst("\"createdAt\":\"[^\"]+\"", "\"createdAt\":\"not-an-instant\""),
        StandardCharsets.UTF_8);

    assertEquals(
        "invalid_vault_envelope",
        assertThrows(AppVaultException.class, () -> service.readSecretValue(APP_ID, SECRET_NAME))
            .errorCode());
  }

  @Test
  void useIdentity_whenGrantAllowsSigning_expectDomainSeparatedEd25519Signature()
      throws IOException, GeneralSecurityException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    service.grantIdentity(
        identity.identityId(),
        APP_ID,
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        GRANTED_BY_OPERATOR,
        "test grant",
        null,
        null);

    AppIdentityUsageResult result =
        service.useIdentity(
            new AppIdentityUsageRequest(
                APP_ID,
                identity.identityId(),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
                PURPOSE_FEED_PUBLISH,
                bytes(PAYLOAD)));

    assertTrue(verify(result, result.domainSeparatedPayload()));
    assertFalse(
        verify(result, result.domainSeparatedPayload().replace(PURPOSE_FEED_PUBLISH, "profile")));
    assertFalse(identity.toString().contains(result.publicKeyBase64()));
    assertFalse(result.toString().contains(result.signatureBase64()));
  }

  @Test
  void signDomainSeparatedPayload_whenGrantAllowsSigning_expectExactPayloadSigned()
      throws IOException, GeneralSecurityException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    service.grantIdentity(
        identity.identityId(),
        APP_ID,
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        GRANTED_BY_OPERATOR,
        "test grant",
        null,
        null);
    byte[] canonicalTrustPayload =
        bytes("crypta.trust.statement.v1\n{\"context\":\"profile\",\"score\":50}");

    AppIdentityUsageResult result =
        service.signDomainSeparatedPayload(
            new AppIdentityUsageRequest(
                APP_ID,
                identity.identityId(),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
                "crypta.trust.statement.v1",
                canonicalTrustPayload));

    assertEquals(
        new String(canonicalTrustPayload, StandardCharsets.UTF_8), result.domainSeparatedPayload());
    assertTrue(verify(result, result.domainSeparatedPayload()));
    assertFalse(
        verify(
            result,
            "CryptaAppVault:v1:"
                + APP_ID
                + ":"
                + identity.identityId()
                + ":crypta.trust.statement.v1:"
                + result.payloadSha256()));
    assertFalse(result.toString().contains(result.signatureBase64()));
  }

  @Test
  void createLocalSigningIdentity_whenReservedScopeRequested_expectRejectedBeforeStorage()
      throws IOException {
    AppVaultService service = service();
    Set<AppIdentityGrantScope> publishContentScope = Set.of(AppIdentityGrantScope.PUBLISH_CONTENT);
    Set<AppIdentityGrantScope> externalReferenceScope =
        Set.of(AppIdentityGrantScope.USE_EXTERNAL_REFERENCE);

    assertEquals(
        "unsupported_grant_scope",
        assertThrows(
                AppVaultException.class,
                () ->
                    service.createOperatorIdentity(
                        AppIdentityKind.LOCAL_ED25519_SIGNING,
                        OPERATOR_PUBLISHER_LABEL,
                        null,
                        publishContentScope))
            .errorCode());
    assertEquals(
        "unsupported_grant_scope",
        assertThrows(
                AppVaultException.class,
                () ->
                    service.createAppOwnedIdentity(
                        APP_ID,
                        AppIdentityKind.LOCAL_ED25519_SIGNING,
                        APP_SIGNING_KEY_LABEL,
                        externalReferenceScope))
            .errorCode());

    assertTrue(service.listIdentities().isEmpty());
    assertTrue(service.listGrantsForApp(APP_ID).isEmpty());
    assertTrue(directoryEmpty(paths().identitiesRoot()));
  }

  @Test
  void createOperatorIdentity_whenOwnerAppIdIsBlank_expectSharedIdentityStored()
      throws IOException {
    AppVaultService service = service();

    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            " ",
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    assertNull(identity.ownerAppId());
    assertEquals(identity.identityId(), service.listIdentities().getFirst().identityId());
  }

  @Test
  void useIdentity_whenAppOwnedGrantRevoked_expectDeniedAndMetadataHidden() throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createAppOwnedIdentity(
            APP_ID, AppIdentityKind.LOCAL_ED25519_SIGNING, APP_SIGNING_KEY_LABEL, null);
    AppIdentityGrant grant = service.listGrantsForApp(APP_ID).getFirst();

    service.revokeGrant(grant.grantId());

    String identityId = identity.identityId();
    assertTrue(service.listIdentitiesForApp(APP_ID).isEmpty());
    assertEquals(
        "identity_not_found",
        assertThrows(AppVaultException.class, () -> service.getIdentityForApp(APP_ID, identityId))
            .errorCode());
    assertDenied(service, identity);
  }

  @Test
  void createAppOwnedIdentity_whenGrantCommitFails_expectIdentityRolledBack() throws IOException {
    AppVaultPaths paths = paths();
    AppVaultService service = serviceWithFailingNextGrantCommit(paths);

    AppVaultException exception =
        assertThrows(
            AppVaultException.class,
            () ->
                service.createAppOwnedIdentity(
                    APP_ID, AppIdentityKind.LOCAL_ED25519_SIGNING, APP_SIGNING_KEY_LABEL, null));

    assertEquals(ERROR_VAULT_STORAGE_FAILED, exception.errorCode());
    assertTrue(service.listIdentities().isEmpty());
    assertTrue(directoryEmpty(paths.identitiesRoot()));
    assertFalse(service.listGrantsForApp(APP_ID).isEmpty());
    assertTrue(
        service.listGrantsForApp(APP_ID).stream()
            .allMatch(grant -> grant.status() == AppIdentityGrantStatus.REVOKED));
    assertFalse(service.hasRetainedAppState(APP_ID));
  }

  @Test
  void useIdentity_whenExistingOrMissingIdentityHasNoGrant_expectSameDeniedCode()
      throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    assertUseDeniedForIdentity(service, identity.identityId());
    assertUseDeniedForIdentity(service, "id-00000000000000000000000000000000");
  }

  @Test
  void revokeGrantsForApp_whenAppIsUninstalled_expectAllRetainedGrantsRevoked() throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant activeGrant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "active",
            null,
            null);
    AppIdentityGrant inactiveGrant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "inactive",
            null,
            null);
    service.updateGrantStatus(inactiveGrant.grantId(), AppIdentityGrantStatus.INACTIVE);
    AppIdentityGrant otherAppGrant =
        service.grantIdentity(
            identity.identityId(),
            OTHER_APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "other",
            null,
            null);

    service.revokeGrantsForApp(APP_ID);

    Map<String, AppIdentityGrantStatus> statuses =
        service.listGrants().stream()
            .collect(
                java.util.stream.Collectors.toMap(
                    AppIdentityGrant::grantId, AppIdentityGrant::status));
    assertEquals(AppIdentityGrantStatus.REVOKED, statuses.get(activeGrant.grantId()));
    assertEquals(AppIdentityGrantStatus.REVOKED, statuses.get(inactiveGrant.grantId()));
    assertEquals(AppIdentityGrantStatus.ACTIVE, statuses.get(otherAppGrant.grantId()));
  }

  @Test
  void listAppVisibleGrantsForApp_whenGrantRevokedAfterUninstall_expectRetainedGrantHidden()
      throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.METADATA_READ),
            GRANTED_BY_OPERATOR,
            "metadata",
            null,
            null);

    assertEquals(List.of(grant), service.listAppVisibleGrantsForApp(APP_ID));

    service.revokeGrantsForApp(APP_ID);

    assertTrue(service.listAppVisibleGrantsForApp(APP_ID).isEmpty());
    assertEquals(
        List.of(grant.grantId()),
        service.listGrantsForApp(APP_ID).stream().map(AppIdentityGrant::grantId).toList());
  }

  @Test
  void useIdentity_whenCopiedGrantFileNameMismatchesRecord_expectCorruptGrantRejected()
      throws IOException {
    AppVaultService service = service();
    AppVaultPaths paths = paths();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            GRANT_REASON_SIGNING,
            null,
            null);
    Files.copy(
        paths.grantPath(grant.grantId()), paths.grantsRoot().resolve("grant-copy.properties"));

    service.revokeGrant(grant.grantId());

    AppIdentityUsageRequest request = signingUsageRequest(APP_ID, identity.identityId());
    AppVaultException exception =
        assertThrows(AppVaultException.class, () -> service.useIdentity(request));
    assertEquals(ERROR_CORRUPT_VAULT_RECORD, exception.errorCode());
  }

  @Test
  void revokeGrantsForApp_whenGrantTimestampMalformed_expectCorruptVaultRecord()
      throws IOException {
    for (String timestampField : List.of(PROPERTY_CREATED_AT, PROPERTY_UPDATED_AT, "expiresAt")) {
      AppVaultPaths paths = new AppVaultPaths(tempDir.resolve("vault-" + timestampField));
      AppVaultService service = AppVaultService.open(paths.root());
      AppIdentityRecord identity =
          service.createOperatorIdentity(
              AppIdentityKind.LOCAL_ED25519_SIGNING,
              OPERATOR_PUBLISHER_LABEL,
              null,
              Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
      AppIdentityGrant grant =
          service.grantIdentity(
              identity.identityId(),
              APP_ID,
              Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
              GRANTED_BY_OPERATOR,
              GRANT_REASON_SIGNING,
              null,
              null);
      writeGrantWithMalformedTimestamp(paths, grant, timestampField);

      AppVaultException exception =
          assertThrows(AppVaultException.class, () -> service.revokeGrantsForApp(APP_ID));

      assertEquals(ERROR_CORRUPT_VAULT_RECORD, exception.errorCode());
    }
  }

  @Test
  void listIdentities_whenRecordIsCopiedToWrongDirectory_expectMetadataMismatch()
      throws IOException {
    AppVaultService service = service();
    AppVaultPaths paths = paths();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    copyIdentityDirectory(paths, identity.identityId());

    assertEquals(
        ERROR_CORRUPT_VAULT_RECORD,
        assertThrows(AppVaultException.class, service::listIdentities).errorCode());
  }

  @Test
  void getIdentity_whenRequiredTimestampMissingOrMalformed_expectCorruptVaultRecord()
      throws IOException {
    for (String field : List.of(PROPERTY_CREATED_AT, PROPERTY_UPDATED_AT)) {
      for (String mode : List.of(MODE_MISSING, "malformed")) {
        AppVaultPaths paths = new AppVaultPaths(tempDir.resolve("identity-" + field + "-" + mode));
        AppVaultService service = AppVaultService.open(paths.root());
        AppIdentityRecord identity =
            service.createOperatorIdentity(
                AppIdentityKind.LOCAL_ED25519_SIGNING,
                OPERATOR_PUBLISHER_LABEL,
                null,
                Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
        Path metadata = paths.identityMetadataPath(identity.identityId());
        if (MODE_MISSING.equals(mode)) {
          removeProperty(metadata, field);
        } else {
          replacePropertyWithMalformedTimestamp(metadata, field);
        }

        String identityId = identity.identityId();
        AppVaultException exception =
            assertThrows(AppVaultException.class, () -> service.getIdentity(identityId));

        assertEquals(ERROR_CORRUPT_VAULT_RECORD, exception.errorCode());
      }
    }
  }

  @Test
  void deleteAppOwnedIdentitiesForApp_whenAppUninstalled_expectPrivateMaterialPurged()
      throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createAppOwnedIdentity(
            APP_ID, AppIdentityKind.LOCAL_ED25519_SIGNING, APP_SIGNING_KEY_LABEL, null);
    AppIdentityGrant ownerGrant = service.listGrantsForApp(APP_ID).getFirst();
    AppIdentityGrant otherAppGrant =
        service.grantIdentity(
            identity.identityId(),
            OTHER_APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "shared app-owned identity",
            null,
            null);

    assertTrue(service.hasRetainedAppState(APP_ID));
    List<AppIdentityRecord> deleted = service.deleteAppOwnedIdentitiesForApp(APP_ID);

    assertEquals(
        List.of(identity.identityId()),
        deleted.stream().map(AppIdentityRecord::identityId).toList());
    String identityId = identity.identityId();
    assertEquals(
        "identity_not_found",
        assertThrows(AppVaultException.class, () -> service.getIdentity(identityId)).errorCode());
    Map<String, AppIdentityGrantStatus> statuses =
        service.listGrants().stream()
            .collect(
                java.util.stream.Collectors.toMap(
                    AppIdentityGrant::grantId, AppIdentityGrant::status));
    assertEquals(AppIdentityGrantStatus.REVOKED, statuses.get(ownerGrant.grantId()));
    assertEquals(AppIdentityGrantStatus.REVOKED, statuses.get(otherAppGrant.grantId()));
    assertFalse(service.hasRetainedAppState(APP_ID));
  }

  @Test
  void deleteAppOwnedIdentitiesForApp_whenGrantRevokeFails_expectIdentityRetainedForRetry()
      throws IOException {
    AppVaultPaths paths = paths();
    AtomicBoolean failGrantCommit = new AtomicBoolean(false);
    AppVaultStore store =
        new AppVaultStore(
            paths,
            target -> {
              if (failGrantCommit.get() && target.startsWith(paths.grantsRoot())) {
                throw new IOException("grant revoke failed");
              }
            });
    store.initialize();
    AppVaultService service = serviceWithStore(paths, store);
    AppIdentityRecord identity =
        service.createAppOwnedIdentity(
            APP_ID, AppIdentityKind.LOCAL_ED25519_SIGNING, APP_SIGNING_KEY_LABEL, null);
    AppIdentityGrant ownerGrant = service.listGrantsForApp(APP_ID).getFirst();
    AppIdentityGrant otherAppGrant =
        service.grantIdentity(
            identity.identityId(),
            OTHER_APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "shared app-owned identity",
            null,
            null);

    failGrantCommit.set(true);
    AppVaultException exception =
        assertThrows(AppVaultException.class, () -> service.deleteAppOwnedIdentitiesForApp(APP_ID));

    assertEquals(ERROR_VAULT_STORAGE_FAILED, exception.errorCode());
    assertEquals(identity.identityId(), service.getIdentity(identity.identityId()).identityId());
    assertTrue(Files.isRegularFile(paths.identityPrivateEnvelopePath(identity.identityId())));

    failGrantCommit.set(false);
    assertEquals(
        List.of(identity.identityId()),
        service.deleteAppOwnedIdentitiesForApp(APP_ID).stream()
            .map(AppIdentityRecord::identityId)
            .toList());
    Map<String, AppIdentityGrantStatus> statuses =
        service.listGrants().stream()
            .collect(
                java.util.stream.Collectors.toMap(
                    AppIdentityGrant::grantId, AppIdentityGrant::status));
    assertEquals(AppIdentityGrantStatus.REVOKED, statuses.get(ownerGrant.grantId()));
    assertEquals(AppIdentityGrantStatus.REVOKED, statuses.get(otherAppGrant.grantId()));
  }

  @Test
  void useIdentity_whenGrantScopeInactiveOrExpired_expectDenied() throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));

    service.grantIdentity(
        identity.identityId(),
        APP_ID,
        Set.of(AppIdentityGrantScope.METADATA_READ),
        GRANTED_BY_OPERATOR,
        "metadata only",
        null,
        null);
    assertDenied(service, identity);

    AppIdentityGrant signGrant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            GRANT_REASON_SIGNING,
            null,
            null);
    service.updateGrantStatus(signGrant.grantId(), AppIdentityGrantStatus.INACTIVE);
    assertDenied(service, identity);

    service.grantIdentity(
        identity.identityId(),
        EXPIRED_APP_ID,
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        GRANTED_BY_OPERATOR,
        "expired",
        Instant.now().minusSeconds(60),
        null);
    AppIdentityUsageRequest expiredRequest =
        signingUsageRequest(EXPIRED_APP_ID, identity.identityId());
    AppVaultException expired =
        assertThrows(AppVaultException.class, () -> service.useIdentity(expiredRequest));
    assertEquals("identity_grant_denied", expired.errorCode());
  }

  @Test
  void disableGrantsForRemovedVaultPermissions_whenUsePermissionRemoved_expectInactiveGrant()
      throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            GRANT_REASON_SIGNING,
            null,
            null);

    service.disableGrantsForRemovedVaultPermissions(APP_ID, Set.of("vault.identities.read"));

    assertEquals(
        AppIdentityGrantStatus.INACTIVE,
        service.listGrantsForApp(APP_ID).stream()
            .filter(candidate -> candidate.grantId().equals(grant.grantId()))
            .findFirst()
            .orElseThrow()
            .status());
  }

  @Test
  void updateCleanup_whenUseRemovedFromMixedGrant_expectReadScopePreserved() throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "metadata and signing",
            null,
            null);

    service.disableGrantsForRemovedVaultPermissions(APP_ID, Set.of("vault.identities.read"));

    AppIdentityGrant updated =
        service.listGrantsForApp(APP_ID).stream()
            .filter(candidate -> candidate.grantId().equals(grant.grantId()))
            .findFirst()
            .orElseThrow();
    assertEquals(AppIdentityGrantStatus.ACTIVE, updated.status());
    assertEquals(Set.of(AppIdentityGrantScope.METADATA_READ), updated.scopes());
    assertEquals(
        List.of(identity.identityId()),
        service.listIdentitiesForApp(APP_ID).stream().map(AppIdentityRecord::identityId).toList());
    assertDenied(service, identity);
  }

  @Test
  void updateCleanup_whenReadRemovedFromMixedGrant_expectUseScopePreserved() throws IOException {
    AppVaultService service = service();
    AppIdentityRecord identity =
        service.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            OPERATOR_PUBLISHER_LABEL,
            null,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        service.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(
                AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            GRANTED_BY_OPERATOR,
            "metadata and signing",
            null,
            null);

    service.disableGrantsForRemovedVaultPermissions(APP_ID, Set.of("vault.identities.use"));

    AppIdentityGrant updated =
        service.listGrantsForApp(APP_ID).stream()
            .filter(candidate -> candidate.grantId().equals(grant.grantId()))
            .findFirst()
            .orElseThrow();
    assertEquals(AppIdentityGrantStatus.ACTIVE, updated.status());
    assertEquals(Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED), updated.scopes());
    assertTrue(service.listIdentitiesForApp(APP_ID).isEmpty());
    AppIdentityUsageResult result =
        service.useIdentity(
            new AppIdentityUsageRequest(
                APP_ID,
                identity.identityId(),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
                PURPOSE_FEED_PUBLISH,
                bytes(PAYLOAD)));
    assertEquals(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED, result.scope());
  }

  private AppVaultService service() throws IOException {
    return AppVaultService.open(tempDir.resolve("vault"));
  }

  private AppVaultService serviceWithFailingKeyProvider() throws IOException {
    AppVaultPaths paths = paths();
    AppVaultStore store = new AppVaultStore(paths);
    store.initialize();
    return new AppVaultService(
        store,
        () -> {
          throw new IOException("key unavailable");
        },
        new SecureRandom());
  }

  private static AppVaultService serviceWithFailingNextGrantCommit(AppVaultPaths paths)
      throws IOException {
    AtomicBoolean failNextGrantCommit = new AtomicBoolean(true);
    AppVaultStore store =
        new AppVaultStore(
            paths,
            target -> {
              if (target.startsWith(paths.grantsRoot())
                  && failNextGrantCommit.compareAndSet(true, false)) {
                throw new IOException("grant commit failed");
              }
            });
    store.initialize();
    return serviceWithStore(paths, store);
  }

  private static AppVaultService serviceWithStore(AppVaultPaths paths, AppVaultStore store) {
    return new AppVaultService(
        store,
        new LocalAppVaultKeyProvider(paths.keyFile(), new SecureRandom()),
        new SecureRandom());
  }

  private AppVaultPaths paths() {
    return new AppVaultPaths(tempDir.resolve("vault"));
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static AppVaultEnvelope envelope() {
    return envelope("ciphertext");
  }

  private static AppVaultEnvelope envelope(String ciphertext) {
    return new AppVaultEnvelope(
        AppVaultEnvelope.FORMAT_VERSION,
        AppVaultEnvelope.FORMAT_ALGORITHM,
        "local-vault-key-v1",
        new byte[12],
        bytes("aad"),
        bytes(ciphertext),
        Instant.now());
  }

  private static AppSecretRecord secretRecord(String secretKind, Map<String, String> metadata) {
    Instant now = Instant.now();
    return new AppSecretRecord(APP_ID, SECRET_NAME, secretKind, now, now, null, "small", metadata);
  }

  private static AppIdentityRecord identityRecord(String identityId) {
    Instant now = Instant.now();
    return new AppIdentityRecord(
        identityId,
        AppIdentityKind.LOCAL_ED25519_SIGNING,
        OPERATOR_PUBLISHER_LABEL,
        null,
        now,
        now,
        Map.of("algorithm", ALGORITHM_ED25519),
        "fingerprint",
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
  }

  private static void assertDenied(AppVaultService service, AppIdentityRecord identity) {
    assertUseDeniedForIdentity(service, identity.identityId());
  }

  private static void assertUseDeniedForIdentity(AppVaultService service, String identityId) {
    AppIdentityUsageRequest request = signingUsageRequest(APP_ID, identityId);
    AppVaultException exception =
        assertThrows(AppVaultException.class, () -> service.useIdentity(request));
    assertEquals("identity_grant_denied", exception.errorCode());
  }

  private static AppIdentityUsageRequest signingUsageRequest(String appId, String identityId) {
    return new AppIdentityUsageRequest(
        appId,
        identityId,
        AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
        PURPOSE_FEED_PUBLISH,
        bytes(PAYLOAD));
  }

  private static boolean verify(AppIdentityUsageResult result, String signedText)
      throws GeneralSecurityException {
    PublicKey publicKey =
        KeyFactory.getInstance(ALGORITHM_ED25519)
            .generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(result.publicKeyBase64())));
    Signature verifier = Signature.getInstance(ALGORITHM_ED25519);
    verifier.initVerify(publicKey);
    verifier.update(signedText.getBytes(StandardCharsets.UTF_8));
    return verifier.verify(Base64.getDecoder().decode(result.signatureBase64()));
  }

  private static void copyDefaultSecretDirectory(
      AppVaultPaths paths, String targetAppId, String targetName) throws IOException {
    Path source = paths.secretMetadataPath(APP_ID, SECRET_NAME).getParent();
    Path target = paths.secretMetadataPath(targetAppId, targetName).getParent();
    Files.createDirectories(target);
    Files.copy(source.resolve(METADATA_PROPERTIES), target.resolve(METADATA_PROPERTIES));
    Files.copy(source.resolve("value.envelope.json"), target.resolve("value.envelope.json"));
  }

  private static void copyIdentityDirectory(AppVaultPaths paths, String sourceIdentityId)
      throws IOException {
    Path source = paths.identityMetadataPath(sourceIdentityId).getParent();
    Path target = paths.identityMetadataPath(COPIED_IDENTITY_ID).getParent();
    Files.createDirectories(target);
    Files.copy(source.resolve(METADATA_PROPERTIES), target.resolve(METADATA_PROPERTIES));
    Files.copy(source.resolve("private.envelope.json"), target.resolve("private.envelope.json"));
  }

  private static void writeGrantWithMalformedTimestamp(
      AppVaultPaths paths, AppIdentityGrant grant, String timestampField) throws IOException {
    Files.writeString(
        paths.grantPath(grant.grantId()),
        """
        grantId=%s
        identityId=%s
        appId=%s
        scopes=sign.domain-separated
        status=active
        createdAt=%s
        updatedAt=%s
        %s
        """
            .formatted(
                grant.grantId(),
                grant.identityId(),
                grant.appId(),
                timestampForField(grant, timestampField, PROPERTY_CREATED_AT),
                timestampForField(grant, timestampField, PROPERTY_UPDATED_AT),
                "expiresAt".equals(timestampField) ? "expiresAt=" + MALFORMED_TIMESTAMP : ""),
        StandardCharsets.UTF_8);
  }

  private static String timestampForField(
      AppIdentityGrant grant, String timestampField, String currentField) {
    if (currentField.equals(timestampField)) {
      return MALFORMED_TIMESTAMP;
    }
    if (PROPERTY_CREATED_AT.equals(currentField)) {
      return grant.createdAt().toString();
    }
    return grant.updatedAt().toString();
  }

  private static void replacePropertyWithMalformedTimestamp(Path path, String propertyName)
      throws IOException {
    String updated =
        Files.readString(path, StandardCharsets.UTF_8)
            .lines()
            .map(
                line ->
                    line.startsWith(propertyName + "=")
                        ? propertyName + "=" + MALFORMED_TIMESTAMP
                        : line)
            .collect(java.util.stream.Collectors.joining("\n", "", "\n"));
    Files.writeString(path, updated, StandardCharsets.UTF_8);
  }

  private static void removeProperty(Path path, String propertyName) throws IOException {
    String updated =
        Files.readString(path, StandardCharsets.UTF_8)
            .lines()
            .filter(line -> !line.startsWith(propertyName + "="))
            .collect(java.util.stream.Collectors.joining("\n", "", "\n"));
    Files.writeString(path, updated, StandardCharsets.UTF_8);
  }

  private static boolean directoryEmpty(Path directory) throws IOException {
    if (!Files.isDirectory(directory)) {
      return true;
    }
    try (var stream = Files.list(directory)) {
      return stream.findAny().isEmpty();
    }
  }
}
