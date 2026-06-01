package network.crypta.platform.appcatalog;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogManagerTest {
  private static final String KEY_ID = "catalog-test";
  private static final String ROTATED_KEY_ID = "catalog-rotated";
  private static final String CATALOG_ID = "core";
  private static final String STAGING_CATALOG_ID = "staging";
  private static final String APP_ID = "queue-manager";
  private static final String APP_VERSION = "1.0.0";
  private static final String APP_NAME = "Queue Manager";
  private static final String APP_SUMMARY = "Manage local Crypta transfer queues.";
  private static final String ARTIFACT_ZIP = "queue-manager.zip";
  private static final String EXECUTABLE_PATH = "bin/tool";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String QUEUE_WRITE_PERMISSION = "queue.write";
  private static final String CRYPTA_CATALOG_KEY =
      "USK@example/catalog/cryptad-app-catalog.properties";
  private static final String CRYPTA_SIGNATURE_KEY =
      "USK@example/catalog/cryptad-app-catalog.signature";
  private static final String CRYPTA_CATALOG_SOURCE = "crypta:" + CRYPTA_CATALOG_KEY;
  private static final String CRYPTA_ARTIFACT_KEY = "CHK@artifact-key";
  private static final URI CRYPTA_ARTIFACT_URI = URI.create("crypta:" + CRYPTA_ARTIFACT_KEY);
  private static final String BASIC_CATALOG_PROPERTIES = "catalog.version=1\n";
  private static final String BASIC_CATALOG_SIGNATURE = "catalog.signature.version=1\n";
  private static final String MALFORMED_KEY_VALUE_LINE = "not-a-key-value-line\n";
  private static final String CATALOG_SOURCE_STORE_DIRECTORY = "store";
  private static final String FINDER_METADATA = "finder metadata";
  private static final String UNEXPECTED_HTTP_FETCH = "unexpected HTTP fetch";
  private static final int LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50;
  private static final int CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
  private static final int END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50;
  private static final int END_OF_CENTRAL_DIRECTORY_MIN_BYTES = 22;
  private static final int UNIX_REGULAR_FILE_MODE = 32768;
  private static final int UNIX_EXECUTABLE_FILE_MODE = UNIX_REGULAR_FILE_MODE | 448;
  private static final Instant GENERATED_AT = Instant.parse("2026-04-21T18:22:40Z");

  @TempDir private Path tempDir;

  @Test
  void addSource_whenLocalSignedCatalogIsValid_expectListAndInstallPlan() throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys);

    AppCatalogSourceSnapshot snapshot = manager.addSource(catalog.toString());
    List<AppCatalogEntry> entries = manager.listApps(CATALOG_ID);

    assertEquals(CATALOG_ID, snapshot.catalogId());
    assertEquals(1, snapshot.appCount());
    assertEquals(APP_ID, entries.getFirst().appId());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isDirectory(plan.stagedBundleDirectory()));
      assertTrue(
          Files.isRegularFile(
              plan.stagedBundleDirectory().resolve(AppBundleManifestParser.MANIFEST_FILE_NAME)));
    }
  }

  @Test
  void addSource_whenCatalogIsSigned_expectSnapshotIncludesSignatureKeyId() throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys);

    AppCatalogSourceSnapshot snapshot = manager.addSource(catalog.toString());
    AppCatalogSourceSnapshot listedSnapshot = manager.listCatalogs().getFirst();

    assertEquals(Optional.of(KEY_ID), snapshot.signatureKeyId());
    assertEquals(Optional.of(KEY_ID), listedSnapshot.signatureKeyId());
  }

  @Test
  void addSource_whenCatalogBytesAreTampered_expectInvalidCatalogSignature() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    Files.writeString(
        catalog, "\n# tampered\n", StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(catalogSource));

    assertEquals("invalid_catalog_signature", exception.errorCode());
  }

  @Test
  void addSource_whenSignerIsUnknown_expectInvalidCatalogSignature() throws Exception {
    KeyPair signingKeyPair = keyPair();
    KeyPair trustedKeyPair = keyPair();
    Path bundle = signedBundle(signingKeyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, signingKeyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(trustedKeyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(catalogSource));

    assertEquals("invalid_catalog_signature", exception.errorCode());
  }

  @Test
  void addSource_whenSignatureSidecarIsMalformed_expectInvalidCatalogSignature() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    Files.writeString(
        catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME),
        MALFORMED_KEY_VALUE_LINE,
        StandardCharsets.UTF_8);
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(catalogSource));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenArtifactDigestMismatches_expectArtifactDigestMismatch()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, "0".repeat(64), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals("artifact_digest_mismatch", exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipContainsTraversal_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = traversalZip(tempDir.resolve("unsafe.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
    assertFalse(Files.exists(tempDir.resolve("evil.txt")));
  }

  @Test
  void prepareInstallPlan_whenZipContainsAppleDoubleEntries_expectMetadataIgnored()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectoryWithAppleDouble(bundle, tempDir.resolve("appledouble.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve("._cryptad-app.properties")));
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve("__MACOSX")));
      assertFalse(Files.exists(plan.stagedBundleDirectory().resolve("bin").resolve("._launch.sh")));
    }
  }

  @Test
  void prepareInstallPlan_whenZipParentIsFile_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = parentConflictZip(tempDir.resolve("parent-conflict.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipDirectoryParentIsFile_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = directoryParentConflictZip(tempDir.resolve("directory-parent-conflict.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipPayloadIsCorrupt_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("corrupt-payload.zip"));
    corruptManifestZipEntryPayload(artifact);
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipEntryNameIsPathInvalid_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = invalidPathNameZip(tempDir.resolve("invalid-path-name.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenZipContainsTooManyEntries_expectInvalidAppBundle() throws Exception {
    KeyPair keyPair = keyPair();
    Path artifact = manyEntriesZip(tempDir.resolve("too-many.zip"));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    //noinspection resource
    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.prepareInstallPlan(CATALOG_ID, APP_ID));

    assertEquals(AppCatalogSidecars.INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenSignedBundleRequiresExecutableBit_expectExecutableModePreserved()
      throws Exception {
    Assumptions.assumeTrue(
        Files.getFileStore(tempDir).supportsFileAttributeView("posix"),
        "POSIX executable mode preservation requires POSIX file attributes");
    KeyPair keyPair = keyPair();
    Path bundle = signedExecutableBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve("executable.zip"));
    setExecutableZipUnixMode(artifact);
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    manager.addSource(catalog.toString());

    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isExecutable(plan.stagedBundleDirectory().resolve(EXECUTABLE_PATH)));
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https:/cryptad-app-catalog.properties",
        "file:cryptad-app-catalog.properties",
        "file://localhost/tmp/cryptad-app-catalog.properties"
      })
  void requireSafeCatalogSourceUri_whenUriIsUnsafe_expectInvalidCatalogSource(String sourceValue) {
    URI source = URI.create(sourceValue);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogSidecars.requireSafeCatalogSourceUri(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://127.example.com/cryptad-app-catalog.properties",
        "ftp://example.invalid/cryptad-app-catalog.properties"
      })
  void requireSafeCatalogSourceUri_whenSchemeIsUnsupported_expectUnsupportedCatalogSource(
      String sourceValue) {
    URI source = URI.create(sourceValue);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> AppCatalogSidecars.requireSafeCatalogSourceUri(source));

    assertEquals(AppCatalogSidecars.UNSUPPORTED_CATALOG_SOURCE, exception.errorCode());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://127.example.com/queue-manager.zip",
        "ftp://example.invalid/queue-manager.zip",
        "https:queue-manager.zip",
        "file:///tmp/queue-manager.zip?download=1"
      })
  void requireSafeArtifactUri_whenUriIsUnsafe_expectInvalidCatalogEntry(String artifactValue) {
    URI artifact = URI.create(artifactValue);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> AppCatalogSidecars.requireSafeArtifactUri(artifact));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void requireSafeArtifactUri_whenHttpHostIsNumeric127Loopback_expectAllowed() {
    URI artifact = URI.create("http://127.0.0.2/queue-manager.zip");

    assertEquals(artifact, AppCatalogSidecars.requireSafeArtifactUri(artifact));
  }

  @Test
  void parse_whenWindowsDriveLetterCatalogPath_expectLocalFileSource() {
    AppCatalogSource source =
        AppCatalogSource.parse("C:/Cryptad/catalog/cryptad-app-catalog.properties");

    assertEquals("file", source.uri().getScheme());
  }

  @ParameterizedTest
  @CsvSource(
      delimiter = '|',
      textBlock =
          """
          crypta:USK@example/catalog/cryptad-app-catalog.properties | USK@example/catalog/cryptad-app-catalog.properties | crypta:USK@example/catalog/cryptad-app-catalog.signature
          crypta:SSK@example/catalog/cryptad-app-catalog.properties | SSK@example/catalog/cryptad-app-catalog.properties | crypta:SSK@example/catalog/cryptad-app-catalog.signature
          crypta:CHK@catalog-key?signature=CHK@signature-key | CHK@catalog-key | crypta:CHK@signature-key
          """)
  void parse_whenCryptaCatalogSourceIsValid_expectRuntimeKeyAndSignature(
      String sourceValue, String expectedFetchUri, String expectedSignatureUri) {
    AppCatalogSource source = AppCatalogSource.parse(sourceValue);

    assertEquals(AppCatalogSourceKind.CRYPTA, source.kind());
    assertEquals(expectedFetchUri, source.resolvedCatalogFetchUri());
    assertEquals(URI.create(expectedSignatureUri), source.signatureUri());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "crypta:CHK@catalog-key",
        "crypta:USK@example",
        "crypta:USK@example/catalog bad/cryptad-app-catalog.properties",
        "crypta:USK@example/catalog/cryptad-app-catalog.properties#fragment",
        "crypta:SSK@example/catalog/cryptad-app-catalog.properties?signature=CHK@signature-key",
        "crypta:CHK@catalog-key?signature=CHK@signature-key&extra=1"
      })
  void parse_whenCryptaCatalogSourceIsInvalid_expectInvalidCatalogSource(String sourceValue) {
    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogSource.parse(sourceValue));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaSourceUsesContentFetchPort_expectCatalogAndSignatureBytes()
      throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    FetchedCatalog fetched = fetcher.fetch(source);

    assertEquals(
        List.of(CRYPTA_CATALOG_KEY, CRYPTA_SIGNATURE_KEY), contentFetchPort.requestedKeys());
    org.junit.jupiter.api.Assertions.assertArrayEquals(catalogBytes, fetched.catalogBytes());
    org.junit.jupiter.api.Assertions.assertArrayEquals(signatureBytes, fetched.signatureBytes());
  }

  @Test
  void fetch_whenCryptaCatalogResolvesToUskEdition_expectSignatureFetchedFromResolvedEdition()
      throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    String requestedCatalogKey = "USK@example/catalog/41/cryptad-app-catalog.properties";
    String resolvedCatalogKey = "USK@example/catalog/42/cryptad-app-catalog.properties";
    String resolvedSignatureKey = "USK@example/catalog/42/cryptad-app-catalog.signature";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(requestedCatalogKey, catalogBytes, resolvedSignatureKey, signatureBytes),
            Map.of(requestedCatalogKey, resolvedCatalogKey));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse("crypta:" + requestedCatalogKey);

    FetchedCatalog fetched = fetcher.fetch(source);

    assertEquals(
        List.of(requestedCatalogKey, resolvedSignatureKey), contentFetchPort.requestedKeys());
    org.junit.jupiter.api.Assertions.assertArrayEquals(catalogBytes, fetched.catalogBytes());
    org.junit.jupiter.api.Assertions.assertArrayEquals(signatureBytes, fetched.signatureBytes());
    assertEquals(Optional.of(resolvedCatalogKey), fetched.resolvedCatalogUri());
  }

  @Test
  void fetch_whenCryptaResolvedCatalogHasSchemePrefix_expectSignatureFetchedFromResolvedEdition()
      throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    String requestedCatalogKey = "USK@example/catalog/latest/cryptad-app-catalog.properties";
    String resolvedCatalogKey = "crypta:USK@example/catalog/42/cryptad-app-catalog.properties";
    String resolvedSignatureKey = "USK@example/catalog/42/cryptad-app-catalog.signature";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(requestedCatalogKey, catalogBytes, resolvedSignatureKey, signatureBytes),
            Map.of(requestedCatalogKey, resolvedCatalogKey));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse("crypta:" + requestedCatalogKey);

    FetchedCatalog fetched = fetcher.fetch(source);

    assertEquals(
        List.of(requestedCatalogKey, resolvedSignatureKey), contentFetchPort.requestedKeys());
    org.junit.jupiter.api.Assertions.assertArrayEquals(catalogBytes, fetched.catalogBytes());
    org.junit.jupiter.api.Assertions.assertArrayEquals(signatureBytes, fetched.signatureBytes());
    assertEquals(Optional.of(resolvedCatalogKey), fetched.resolvedCatalogUri());
  }

  @Test
  void fetch_whenCryptaResolvedCatalogChangesKeyKind_expectInvalidCatalogSource() {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    String requestedCatalogKey = "USK@example/catalog/latest/cryptad-app-catalog.properties";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(requestedCatalogKey, catalogBytes),
            Map.of(requestedCatalogKey, "SSK@example/catalog/42/cryptad-app-catalog.properties"));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse("crypta:" + requestedCatalogKey);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertEquals(List.of(requestedCatalogKey), contentFetchPort.requestedKeys());
  }

  @Test
  void fetch_whenCryptaSourceUsesContentFetchPort_expectBoundedRequests() throws Exception {
    byte[] catalogBytes = BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
    byte[] signatureBytes = BASIC_CATALOG_SIGNATURE.getBytes(StandardCharsets.UTF_8);
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, signatureBytes));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    fetcher.fetch(source);

    List<BoundedContentFetchRequest> requests = contentFetchPort.requests();
    assertEquals(2, requests.size());
    assertEquals("catalog properties", requests.getFirst().purpose());
    assertEquals(AppCatalogSidecars.MAX_CATALOG_BYTES, requests.get(0).maxBytes());
    assertTrue(requests.get(0).timeout().compareTo(Duration.ZERO) > 0);
    assertEquals("catalog signature", requests.get(1).purpose());
    assertEquals(AppCatalogSidecars.MAX_SIGNATURE_BYTES, requests.get(1).maxBytes());
    assertTrue(requests.get(1).timeout().compareTo(Duration.ZERO) > 0);
  }

  @Test
  void fetch_whenCryptaRuntimeIsUnavailable_expectCatalogFetchUnavailable() {
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), null);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_UNAVAILABLE, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaRuntimeRejectsSource_expectInvalidCatalogSource() {
    ContentFetchPort contentFetchPort =
        _ -> {
          throw new ContentFetchException(
              ContentFetchException.INVALID_CATALOG_SOURCE, "invalid runtime key");
        };
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaRuntimeReturnsOversizedSignature_expectCatalogFetchFailed() {
    ContentFetchPort contentFetchPort =
        request -> {
          byte[] bytes =
              "catalog signature".equals(request.purpose())
                  ? new byte[(int) AppCatalogSidecars.MAX_SIGNATURE_BYTES + 1]
                  : BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8);
          return new BoundedContentFetchResult(bytes, request.uri(), null, null);
        };
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_FAILED, exception.errorCode());
  }

  @Test
  void fetch_whenCryptaSignatureIsMissing_expectCatalogSignatureMissing() {
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, BASIC_CATALOG_PROPERTIES.getBytes(StandardCharsets.UTF_8)));
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    AppCatalogSource source = AppCatalogSource.parse(CRYPTA_CATALOG_SOURCE);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.CATALOG_SIGNATURE_MISSING, exception.errorCode());
  }

  @Test
  void addSource_whenCryptaSignatureIsInvalid_expectInvalidCatalogSignature() throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                MALFORMED_KEY_VALUE_LINE.getBytes(StandardCharsets.UTF_8)));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.addSource(CRYPTA_CATALOG_SOURCE));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
  }

  @Test
  void addSource_whenCryptaFetchReportsResolvedUri_expectSnapshotRecordsResolvedUri()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    String sourceKey = "USK@example/catalog/latest/cryptad-app-catalog.properties";
    String resolvedUri = "USK@example/catalog/42/cryptad-app-catalog.properties";
    String resolvedSignatureKey = "USK@example/catalog/42/cryptad-app-catalog.signature";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                sourceKey,
                Files.readAllBytes(catalog),
                resolvedSignatureKey,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))),
            Map.of(sourceKey, resolvedUri));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);

    AppCatalogSourceSnapshot snapshot =
        manager.addSource("crypta:USK@example/catalog/latest/cryptad-app-catalog.properties");

    assertEquals(Optional.of(resolvedUri), snapshot.lastResolvedUri());
    assertEquals(Optional.of(resolvedUri), manager.listCatalogs().getFirst().lastResolvedUri());
  }

  @Test
  void refresh_whenCryptaFetchFails_expectPreviousVerifiedCatalogPreservedAndMetadataUpdated()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(
                    catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME))));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.failWith(new IOException("content fetch failed"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    List<AppCatalogEntry> entries = manager.listApps(CATALOG_ID);
    AppCatalogSourceSnapshot snapshot = manager.listCatalogs().getFirst();

    assertEquals(AppCatalogSidecars.CATALOG_FETCH_FAILED, exception.errorCode());
    assertEquals(APP_ID, entries.getFirst().appId());
    assertEquals(AppCatalogFetchStatus.FAILED, snapshot.lastFetchStatus());
    assertEquals(
        Optional.of(AppCatalogSidecars.CATALOG_FETCH_FAILED), snapshot.lastFetchErrorCode());
    assertEquals(snapshot.refreshedAt(), snapshot.lastSuccessfulRefreshAt());
  }

  @Test
  void refresh_whenCatalogSignatureKeyRotates_expectSnapshotIncludesRefreshedSignatureKeyId()
      throws Exception {
    KeyPair initialKeyPair = keyPair();
    KeyPair rotatedKeyPair = keyPair();
    Path bundle = signedBundle(initialKeyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            initialKeyPair,
            KEY_ID,
            sha256(artifact),
            Files.size(artifact));
    byte[] initialCatalogBytes = Files.readAllBytes(catalog);
    byte[] initialSignatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    Path refreshedCatalog =
        signedCatalog(
            CATALOG_ID,
            artifact.toUri(),
            rotatedKeyPair,
            ROTATED_KEY_ID,
            sha256(artifact),
            Files.size(artifact));
    byte[] refreshedCatalogBytes = Files.readAllBytes(refreshedCatalog);
    byte[] refreshedSignatureBytes =
        Files.readAllBytes(
            refreshedCatalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                initialCatalogBytes,
                CRYPTA_SIGNATURE_KEY,
                initialSignatureBytes));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(
            trustedKey(KEY_ID, initialKeyPair), trustedKey(ROTATED_KEY_ID, rotatedKeyPair));
    AppCatalogManager manager = manager(trustedKeys, contentFetchPort);
    AppCatalogSourceSnapshot added = manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            refreshedCatalogBytes,
            CRYPTA_SIGNATURE_KEY,
            refreshedSignatureBytes),
        Map.of());

    AppCatalogSourceSnapshot refreshed = manager.refresh(CATALOG_ID);
    AppCatalogSourceSnapshot listedSnapshot = manager.listCatalogs().getFirst();

    assertEquals(Optional.of(KEY_ID), added.signatureKeyId());
    assertEquals(Optional.of(ROTATED_KEY_ID), refreshed.signatureKeyId());
    assertEquals(Optional.of(ROTATED_KEY_ID), listedSnapshot.signatureKeyId());
  }

  @Test
  void refresh_whenCryptaVerificationFailsAfterResolvedFetch_expectMetadataUsesResolvedUri()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    byte[] catalogBytes = Files.readAllBytes(catalog);
    byte[] validSignatureBytes =
        Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME));
    String resolvedCatalogKey = "USK@example/catalog/99/cryptad-app-catalog.properties";
    String resolvedSignatureKey = "USK@example/catalog/99/cryptad-app-catalog.signature";
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(CRYPTA_CATALOG_KEY, catalogBytes, CRYPTA_SIGNATURE_KEY, validSignatureBytes));
    AppCatalogManager manager = manager(trustedKeys(keyPair), contentFetchPort);
    manager.addSource(CRYPTA_CATALOG_SOURCE);
    contentFetchPort.replaceContent(
        Map.of(
            CRYPTA_CATALOG_KEY,
            catalogBytes,
            resolvedSignatureKey,
            MALFORMED_KEY_VALUE_LINE.getBytes(StandardCharsets.UTF_8)),
        Map.of(CRYPTA_CATALOG_KEY, resolvedCatalogKey));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> manager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot snapshot = manager.listCatalogs().getFirst();

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE, exception.errorCode());
    assertEquals(AppCatalogFetchStatus.FAILED, snapshot.lastFetchStatus());
    assertEquals(
        Optional.of(AppCatalogSidecars.INVALID_CATALOG_SIGNATURE), snapshot.lastFetchErrorCode());
    assertEquals(Optional.of(resolvedCatalogKey), snapshot.lastResolvedUri());
  }

  @Test
  void refresh_whenPersistenceWriteFails_expectIOExceptionAndNoFetchFailureMetadata()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = new AppCatalogManager(sourceStore, () -> trustedKeys);
    manager.addSource(catalog.toString());
    AppCatalogSourceSnapshot beforeRefresh = manager.listCatalogs().getFirst();
    AppCatalogSourceStore failingStore =
        new AppCatalogSourceStore(
            sourceStore.rootDirectory(),
            (_, _, _) -> {
              throw new IOException("metadata write failed");
            });
    AppCatalogManager failingManager = new AppCatalogManager(failingStore, () -> trustedKeys);

    IOException exception =
        assertThrows(IOException.class, () -> failingManager.refresh(CATALOG_ID));
    AppCatalogSourceSnapshot afterRefresh = manager.listCatalogs().getFirst();

    assertEquals("metadata write failed", exception.getMessage());
    assertEquals(beforeRefresh.refreshedAt(), afterRefresh.refreshedAt());
    assertEquals(AppCatalogFetchStatus.SUCCESS, afterRefresh.lastFetchStatus());
    assertTrue(afterRefresh.lastFetchErrorCode().isEmpty());
  }

  @Test
  void entry_whenArtifactUriIsCryptaChk_expectAccepted() {
    String artifactDigest = "0".repeat(64);
    List<String> permissions = List.of(QUEUE_READ_PERMISSION);

    AppCatalogEntry entry =
        new AppCatalogEntry(
            APP_ID,
            APP_NAME,
            APP_VERSION,
            APP_SUMMARY,
            CRYPTA_ARTIFACT_URI,
            artifactDigest,
            1L,
            AppCatalogEntry.ZIP_BUNDLE_TYPE,
            permissions);

    assertEquals(CRYPTA_ARTIFACT_URI, entry.bundleUri());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "crypta:USK@example/apps/queue-manager.zip",
        "crypta:SSK@example/apps/queue-manager.zip",
        "crypta:CHK@bundle-key?signature=CHK@signature-key"
      })
  void entry_whenArtifactUriIsUnsupportedCryptaForm_expectInvalidCatalogEntry(String uri) {
    String artifactDigest = "0".repeat(64);
    List<String> permissions = List.of(QUEUE_READ_PERMISSION);
    URI artifactUri = URI.create(uri);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                new AppCatalogEntry(
                    APP_ID,
                    APP_NAME,
                    APP_VERSION,
                    APP_SUMMARY,
                    artifactUri,
                    artifactDigest,
                    1L,
                    AppCatalogEntry.ZIP_BUNDLE_TYPE,
                    permissions));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  @Test
  void prepareInstallPlan_whenCryptaArtifactUsesContentFetchPort_expectVerifiedPlan()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        signedCatalog(
            CATALOG_ID, CRYPTA_ARTIFACT_URI, keyPair, sha256(artifact), Files.size(artifact));
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(
            Map.of(
                CRYPTA_CATALOG_KEY,
                Files.readAllBytes(catalog),
                CRYPTA_SIGNATURE_KEY,
                Files.readAllBytes(catalog.resolveSibling(AppCatalogSignature.SIGNATURE_FILE_NAME)),
                CRYPTA_ARTIFACT_KEY,
                Files.readAllBytes(artifact)));
    AppCatalogManager manager =
        new AppCatalogManager(
            new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
            () -> trustedKeys,
            contentFetchPort);

    manager.addSource(CRYPTA_CATALOG_SOURCE);
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(CATALOG_ID, APP_ID)) {
      assertTrue(Files.isDirectory(plan.stagedBundleDirectory()));
    }

    assertEquals(
        List.of(CRYPTA_CATALOG_KEY, CRYPTA_SIGNATURE_KEY, CRYPTA_ARTIFACT_KEY),
        contentFetchPort.requestedKeys());
  }

  @Test
  void download_whenCryptaArtifactUsesStreamingFetch_expectVerifiedArtifact() throws Exception {
    byte[] artifactBytes = new byte[] {1, 2, 3};
    List<String> streamedKeys = new java.util.ArrayList<>();
    ContentFetchPort contentFetchPort =
        new ContentFetchPort() {
          @Override
          public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
              throws ContentFetchException {
            throw new ContentFetchException(
                ContentFetchException.CATALOG_FETCH_FAILED,
                "materialized artifact fetch should not be used");
          }

          @Override
          public void fetchContent(BoundedContentFetchRequest request, OutputStream destination)
              throws IOException {
            streamedKeys.add(request.uri());
            destination.write(artifactBytes);
          }
        };
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-streaming");

    Path downloaded =
        downloader.download(
            cryptaEntry(sha256(artifactBytes), artifactBytes.length), scratchDirectory);

    assertEquals(List.of(CRYPTA_ARTIFACT_KEY), streamedKeys);
    assertEquals(artifactBytes.length, Files.size(downloaded));
    assertEquals(sha256(artifactBytes), sha256(downloaded));
  }

  @Test
  void addSource_whenExpectedCatalogIdDiffers_expectCatalogIdMismatchAndNoStoredSource()
      throws Exception {
    KeyPair keyPair = keyPair();
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog = signedCatalog(artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogManager manager = manager(trustedKeys(keyPair));
    String catalogSource = catalog.toString();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class, () -> manager.addSource(catalogSource, "other-catalog"));

    assertEquals(AppCatalogSidecars.CATALOG_ID_MISMATCH, exception.errorCode());
    assertTrue(manager.listCatalogs().isEmpty());
  }

  @Test
  void download_whenCryptaRuntimeIsUnavailable_expectArtifactFetchUnavailable() {
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)),
            (ContentFetchPort) null);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-unavailable");
    AppCatalogEntry entry = cryptaEntry("0".repeat(64), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_FETCH_UNAVAILABLE, exception.errorCode());
  }

  @Test
  void download_whenCryptaFetchFails_expectArtifactDownloadFailed() {
    ContentFetchPort contentFetchPort =
        _ -> {
          throw new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_FAILED, "content is unavailable");
        };
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-failed");
    AppCatalogEntry entry = cryptaEntry("0".repeat(64), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void download_whenCryptaArtifactDigestMismatches_expectArtifactDigestMismatch() {
    ContentFetchPort contentFetchPort =
        request -> new BoundedContentFetchResult(new byte[] {1}, request.uri(), null, null);
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-digest");
    AppCatalogEntry entry = cryptaEntry("0".repeat(64), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
  }

  @Test
  void download_whenCryptaArtifactByteCountMismatches_expectArtifactDigestMismatch()
      throws Exception {
    ContentFetchPort contentFetchPort =
        request -> new BoundedContentFetchResult(new byte[] {1}, request.uri(), null, null);
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-size");
    AppCatalogEntry entry = cryptaEntry(sha256(new byte[] {1}), 2L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
  }

  @Test
  void download_whenCryptaArtifactExceedsDeclaredByteCount_expectArtifactDownloadFailed()
      throws Exception {
    byte[] artifactBytes = new byte[] {1, 2};
    FakeContentFetchPort contentFetchPort =
        new FakeContentFetchPort(Map.of(CRYPTA_ARTIFACT_KEY, artifactBytes));
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort);
    Path scratchDirectory = tempDir.resolve("scratch-crypta-oversize");
    AppCatalogEntry entry = cryptaEntry(sha256(artifactBytes), 1L);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void fetch_whenRemoteStatusRejected_expectResponseBodyClosed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(new FixedResponseHttpClient(new InputStreamResponse(404, body)));
    AppCatalogSource source =
        new AppCatalogSource(URI.create("http://localhost/cryptad-app-catalog.properties"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void fetch_whenRemoteTransportFails_expectInvalidCatalogSource() {
    AppCatalogFetcher fetcher =
        new AppCatalogFetcher(new FixedResponseHttpClient(new IOException("connect failed")));
    AppCatalogSource source =
        new AppCatalogSource(URI.create("http://localhost/cryptad-app-catalog.properties"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> fetcher.fetch(source));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void download_whenRemoteStatusRejected_expectResponseBodyClosed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new InputStreamResponse(404, body)));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-status");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void download_whenRemoteTransportFails_expectArtifactDownloadFailed() {
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new IOException("connect failed")));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-transport");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void download_whenLocalArtifactIsMissing_expectArtifactDownloadFailed() {
    AppCatalogArtifactDownloader downloader = new AppCatalogArtifactDownloader();
    AppCatalogEntry entry = localEntry(tempDir.resolve("missing.zip"));
    Path scratchDirectory = tempDir.resolve("scratch-missing");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
  }

  @Test
  void download_whenRemoteContentLengthRejected_expectResponseBodyClosed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new InputStreamResponse(200, body, contentLength("2"))));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-length");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void download_whenArtifactValidationAndCleanupFail_expectCatalogErrorPreserved() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    IOException cleanupFailure = new IOException("delete failed");
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(new InputStreamResponse(200, body, contentLength("2"))),
            (AppCatalogArtifactDownloader.ArtifactCleaner)
                _ -> {
                  throw cleanupFailure;
                });
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-cleanup-failure");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DIGEST_MISMATCH, exception.errorCode());
    assertEquals(1, exception.getSuppressed().length);
    assertEquals(cleanupFailure, exception.getSuppressed()[0]);
    assertTrue(body.closed());
  }

  @Test
  void download_whenRemoteContentLengthIsMalformed_expectArtifactDownloadFailed() {
    CloseRecordingInputStream body = new CloseRecordingInputStream();
    AppCatalogArtifactDownloader downloader =
        new AppCatalogArtifactDownloader(
            new FixedResponseHttpClient(
                new InputStreamResponse(200, body, contentLength("not-a-number"))));
    AppCatalogEntry entry = remoteEntry();
    Path scratchDirectory = tempDir.resolve("scratch-bad-length");

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> downloader.download(entry, scratchDirectory));

    assertEquals(AppCatalogSidecars.ARTIFACT_DOWNLOAD_FAILED, exception.errorCode());
    assertTrue(body.closed());
  }

  @Test
  void addSource_whenCatalogIdIsStaging_expectCatalogIsListedAndScratchUsesHiddenDirectory()
      throws Exception {
    KeyPair keyPair = keyPair();
    TrustedAppKeys trustedKeys = trustedKeys(keyPair);
    Path bundle = signedBundle(keyPair);
    Path artifact = zipDirectory(bundle, tempDir.resolve(ARTIFACT_ZIP));
    Path catalog =
        signedCatalog(
            STAGING_CATALOG_ID, artifact, keyPair, sha256(artifact), Files.size(artifact));
    AppCatalogSourceStore sourceStore =
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY));
    AppCatalogManager manager = new AppCatalogManager(sourceStore, () -> trustedKeys);

    manager.addSource(catalog.toString());
    List<AppCatalogSourceSnapshot> catalogs = manager.listCatalogs();

    assertEquals(STAGING_CATALOG_ID, catalogs.getFirst().catalogId());
    assertEquals(sourceStore.rootDirectory().resolve(".staging"), sourceStore.stagingDirectory());
    try (AppCatalogInstallPlan plan = manager.prepareInstallPlan(STAGING_CATALOG_ID, APP_ID)) {
      assertTrue(plan.scratchDirectory().startsWith(sourceStore.stagingDirectory()));
    }
  }

  private AppCatalogManager manager(TrustedAppKeys trustedKeys) {
    return new AppCatalogManager(
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
        () -> trustedKeys);
  }

  private AppCatalogManager manager(
      TrustedAppKeys trustedKeys, FakeContentFetchPort contentFetchPort) {
    return new AppCatalogManager(
        new AppCatalogSourceStore(tempDir.resolve(CATALOG_SOURCE_STORE_DIRECTORY)),
        () -> trustedKeys,
        new AppCatalogFetcher(
            new FixedResponseHttpClient(new IOException(UNEXPECTED_HTTP_FETCH)), contentFetchPort),
        new AppCatalogArtifactDownloader(),
        new AppCatalogBundleExtractor());
  }

  private Path signedBundle(KeyPair keyPair) throws IOException {
    Path root = Files.createDirectories(tempDir.resolve("bundle").resolve(APP_ID));
    Path bin = Files.createDirectories(root.resolve("bin"));
    Files.writeString(bin.resolve("launch.sh"), "#!/bin/sh\nexit 0\n", StandardCharsets.UTF_8);
    Files.writeString(
        root.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s,%s
        """
            .formatted(
                APP_ID, APP_NAME, APP_VERSION, QUEUE_READ_PERMISSION, QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(root, KEY_ID, keyPair.getPrivate());
    return root;
  }

  private Path signedExecutableBundle(KeyPair keyPair) throws IOException {
    Path root = Files.createDirectories(tempDir.resolve("bundle").resolve(APP_ID));
    Files.createDirectories(root.resolve("bin"));
    Path executable = root.resolve(EXECUTABLE_PATH);
    Files.writeString(executable, "echo sample\n", StandardCharsets.UTF_8);
    Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));
    Files.writeString(
        root.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=%s
        app.permissions=%s,%s
        """
            .formatted(
                APP_ID,
                APP_NAME,
                APP_VERSION,
                EXECUTABLE_PATH,
                QUEUE_READ_PERMISSION,
                QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(root, KEY_ID, keyPair.getPrivate());
    return root;
  }

  private Path signedCatalog(
      Path artifact, KeyPair keyPair, String artifactSha256, long artifactSize) throws IOException {
    return signedCatalog(CATALOG_ID, artifact, keyPair, artifactSha256, artifactSize);
  }

  private Path signedCatalog(
      String catalogId, Path artifact, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    return signedCatalog(catalogId, artifact.toUri(), keyPair, artifactSha256, artifactSize);
  }

  private Path signedCatalog(
      String catalogId, URI artifactUri, KeyPair keyPair, String artifactSha256, long artifactSize)
      throws IOException {
    return signedCatalog(catalogId, artifactUri, keyPair, KEY_ID, artifactSha256, artifactSize);
  }

  private Path signedCatalog(
      String catalogId,
      URI artifactUri,
      KeyPair keyPair,
      String keyId,
      String artifactSha256,
      long artifactSize)
      throws IOException {
    Path catalogDir = Files.createDirectories(tempDir.resolve("catalog-" + catalogId));
    Path catalog = catalogDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    Files.writeString(
        catalog,
        """
        catalog.version=1
        catalog.id=%s
        catalog.name=Crypta Core Apps
        catalog.generatedAt=%s
        catalog.entries=%s
        app.%s.id=%s
        app.%s.name=%s
        app.%s.version=%s
        app.%s.summary=%s
        app.%s.bundle.uri=%s
        app.%s.bundle.sha256=%s
        app.%s.bundle.size.bytes=%d
        app.%s.bundle.type=zip
        app.%s.permissions=%s,%s
        """
            .formatted(
                catalogId,
                GENERATED_AT,
                APP_ID,
                APP_ID,
                APP_ID,
                APP_ID,
                APP_NAME,
                APP_ID,
                APP_VERSION,
                APP_ID,
                APP_SUMMARY,
                APP_ID,
                artifactUri,
                APP_ID,
                artifactSha256,
                APP_ID,
                artifactSize,
                APP_ID,
                APP_ID,
                QUEUE_READ_PERMISSION,
                QUEUE_WRITE_PERMISSION),
        StandardCharsets.UTF_8);
    AppCatalogSigner.sign(catalog, keyId, keyPair.getPrivate());
    return catalog;
  }

  private static Path zipDirectory(Path sourceRoot, Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip));
        var paths = Files.walk(sourceRoot)) {
      for (Path path : paths.sorted(Comparator.naturalOrder()).toList()) {
        if (Files.isDirectory(path)) {
          continue;
        }
        String relative = sourceRoot.relativize(path).toString().replace('\\', '/');
        zip.putNextEntry(new ZipEntry(relative));
        Files.copy(path, zip);
        zip.closeEntry();
      }
    }
    return targetZip;
  }

  private static Path zipDirectoryWithAppleDouble(Path sourceRoot, Path targetZip)
      throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip));
        var paths = Files.walk(sourceRoot)) {
      for (Path path : paths.sorted(Comparator.naturalOrder()).toList()) {
        if (Files.isDirectory(path)) {
          continue;
        }
        String relative = sourceRoot.relativize(path).toString().replace('\\', '/');
        zip.putNextEntry(new ZipEntry(relative));
        Files.copy(path, zip);
        zip.closeEntry();
      }
      zip.putNextEntry(new ZipEntry("._cryptad-app.properties"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("__MACOSX/"));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("__MACOSX/._cryptad-app.properties"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry("bin/._launch.sh"));
      zip.write(FINDER_METADATA.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path traversalZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("../evil.txt"));
      zip.write("evil".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path parentConflictZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("bin"));
      zip.write("not-a-directory".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry(EXECUTABLE_PATH));
      zip.write("echo sample\n".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path directoryParentConflictZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("bin"));
      zip.write("not-a-directory".getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
      zip.putNextEntry(new ZipEntry(EXECUTABLE_PATH + "/"));
      zip.closeEntry();
    }
    return targetZip;
  }

  private static Path manyEntriesZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      for (int i = 0; i < 4097; i++) {
        zip.putNextEntry(new ZipEntry("entry-" + i + ".txt"));
        zip.write('x');
        zip.closeEntry();
      }
    }
    return targetZip;
  }

  private static Path invalidPathNameZip(Path targetZip) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(targetZip))) {
      zip.putNextEntry(new ZipEntry("bad\0name"));
      zip.write('x');
      zip.closeEntry();
    }
    return targetZip;
  }

  private static void corruptManifestZipEntryPayload(Path targetZip) throws IOException {
    byte[] zipBytes = Files.readAllBytes(targetZip);
    ByteBuffer zip = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN);
    int centralDirectoryOffset = centralDirectoryOffset(zip);
    while (centralDirectoryOffset < zip.limit()
        && zip.getInt(centralDirectoryOffset) == CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      int nameLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 28));
      int extraLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 30));
      int commentLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 32));
      int nameOffset = centralDirectoryOffset + 46;
      String centralDirectoryName =
          new String(zipBytes, nameOffset, nameLength, StandardCharsets.UTF_8);
      if (AppBundleManifestParser.MANIFEST_FILE_NAME.equals(centralDirectoryName)) {
        int compressedSize = zip.getInt(centralDirectoryOffset + 20);
        int localHeaderOffset = zip.getInt(centralDirectoryOffset + 42);
        int dataOffset = zipEntryDataOffset(zip, localHeaderOffset);
        if (compressedSize <= 0 || dataOffset >= centralDirectoryOffset) {
          throw new IOException(
              "ZIP entry has no payload to corrupt: " + AppBundleManifestParser.MANIFEST_FILE_NAME);
        }
        zipBytes[dataOffset + Math.max(0, compressedSize / 2 - 1)] ^= 0x01;
        Files.write(targetZip, zipBytes);
        return;
      }
      centralDirectoryOffset = nameOffset + nameLength + extraLength + commentLength;
    }
    throw new IOException("ZIP entry not found: " + AppBundleManifestParser.MANIFEST_FILE_NAME);
  }

  private static int zipEntryDataOffset(ByteBuffer zip, int localHeaderOffset) throws IOException {
    if (zip.getInt(localHeaderOffset) != LOCAL_FILE_HEADER_SIGNATURE) {
      throw new IOException("ZIP local file header not found");
    }
    int nameLength = Short.toUnsignedInt(zip.getShort(localHeaderOffset + 26));
    int extraLength = Short.toUnsignedInt(zip.getShort(localHeaderOffset + 28));
    return localHeaderOffset + 30 + nameLength + extraLength;
  }

  private static void setExecutableZipUnixMode(Path targetZip) throws IOException {
    byte[] zipBytes = Files.readAllBytes(targetZip);
    ByteBuffer zip = ByteBuffer.wrap(zipBytes).order(ByteOrder.LITTLE_ENDIAN);
    int centralDirectoryOffset = centralDirectoryOffset(zip);
    while (centralDirectoryOffset < zip.limit()
        && zip.getInt(centralDirectoryOffset) == CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
      int nameLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 28));
      int extraLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 30));
      int commentLength = Short.toUnsignedInt(zip.getShort(centralDirectoryOffset + 32));
      int nameOffset = centralDirectoryOffset + 46;
      String centralDirectoryName =
          new String(zipBytes, nameOffset, nameLength, StandardCharsets.UTF_8);
      if (EXECUTABLE_PATH.equals(centralDirectoryName)) {
        zip.putShort(centralDirectoryOffset + 4, (short) 0x0314);
        zip.putInt(centralDirectoryOffset + 38, UNIX_EXECUTABLE_FILE_MODE << 16);
        Files.write(targetZip, zipBytes);
        return;
      }
      centralDirectoryOffset = nameOffset + nameLength + extraLength + commentLength;
    }
    throw new IOException("ZIP entry not found: " + EXECUTABLE_PATH);
  }

  private static int centralDirectoryOffset(ByteBuffer zip) throws IOException {
    for (int offset = zip.limit() - END_OF_CENTRAL_DIRECTORY_MIN_BYTES; offset >= 0; offset--) {
      if (zip.getInt(offset) == END_OF_CENTRAL_DIRECTORY_SIGNATURE) {
        return zip.getInt(offset + 16);
      }
    }
    throw new IOException("ZIP end-of-central-directory record not found");
  }

  private static AppCatalogEntry remoteEntry() {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        APP_SUMMARY,
        URI.create("http://localhost/queue-manager.zip"),
        "0".repeat(64),
        1L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  private static AppCatalogEntry localEntry(Path artifact) {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        APP_SUMMARY,
        artifact.toUri(),
        "0".repeat(64),
        1L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  private static AppCatalogEntry cryptaEntry(String artifactSha256, long artifactSizeBytes) {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        APP_VERSION,
        APP_SUMMARY,
        CRYPTA_ARTIFACT_URI,
        artifactSha256,
        artifactSizeBytes,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  private static HttpHeaders contentLength(String value) {
    return HttpHeaders.of(Map.of("content-length", List.of(value)), (_, _) -> true);
  }

  private static String sha256(Path path) throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(Files.readAllBytes(path));
    return HexFormat.of().formatHex(digest.digest());
  }

  private static String sha256(byte[] bytes) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(bytes);
    return HexFormat.of().formatHex(digest.digest());
  }

  private static KeyPair keyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  private static TrustedAppKeys trustedKeys(KeyPair keyPair) {
    return TrustedAppKeys.of(trustedKey(KEY_ID, keyPair));
  }

  private static TrustedAppKey trustedKey(String keyId, KeyPair keyPair) {
    return new TrustedAppKey(keyId, AppBundleSignature.SIGNATURE_ALGORITHM, keyPair.getPublic());
  }

  private static final class FakeContentFetchPort implements ContentFetchPort {
    private final Map<String, byte[]> content = new java.util.LinkedHashMap<>();
    private final Map<String, String> resolvedUris = new java.util.LinkedHashMap<>();
    private final java.util.ArrayList<String> requestedKeys = new java.util.ArrayList<>();
    private final java.util.ArrayList<BoundedContentFetchRequest> requests =
        new java.util.ArrayList<>();
    private ContentFetchException failure;

    private FakeContentFetchPort(Map<String, byte[]> content) {
      this(content, Map.of());
    }

    private FakeContentFetchPort(Map<String, byte[]> content, Map<String, String> resolvedUris) {
      replaceContent(content, resolvedUris);
    }

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
        throws ContentFetchException {
      requests.add(request);
      requestedKeys.add(request.uri());
      if (failure != null) {
        throw failure;
      }
      byte[] bytes = content.get(request.uri());
      if (bytes == null) {
        throw new ContentFetchException(
            "catalog signature".equals(request.purpose())
                ? AppCatalogSidecars.CATALOG_SIGNATURE_MISSING
                : ContentFetchException.CATALOG_FETCH_FAILED,
            "content is unavailable");
      }
      if (bytes.length > request.maxBytes()) {
        throw new ContentFetchException(
            ContentFetchException.CATALOG_FETCH_FAILED, "content exceeds the allowed size");
      }
      return new BoundedContentFetchResult(
          bytes, request.uri(), resolvedUris.get(request.uri()), null);
    }

    private void failWith(IOException failure) {
      this.failure =
          new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_FAILED, "content fetch failed", failure);
    }

    private void replaceContent(Map<String, byte[]> content, Map<String, String> resolvedUris) {
      this.content.clear();
      this.content.putAll(content);
      this.resolvedUris.clear();
      this.resolvedUris.putAll(resolvedUris);
      failure = null;
      requestedKeys.clear();
      requests.clear();
    }

    private List<String> requestedKeys() {
      return List.copyOf(requestedKeys);
    }

    private List<BoundedContentFetchRequest> requests() {
      return List.copyOf(requests);
    }
  }

  private static final class CloseRecordingInputStream extends ByteArrayInputStream {
    private boolean closed;

    private CloseRecordingInputStream() {
      super(new byte[0]);
    }

    @Override
    public void close() {
      closed = true;
    }

    boolean closed() {
      return closed;
    }
  }

  private static final class FixedResponseHttpClient extends HttpClient {
    private final HttpResponse<InputStream> response;
    private final IOException sendFailure;

    private FixedResponseHttpClient(HttpResponse<InputStream> response) {
      this.response = response;
      sendFailure = null;
    }

    private FixedResponseHttpClient(IOException sendFailure) {
      response = null;
      this.sendFailure = sendFailure;
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
      return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
      return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
      return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
      return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
      try {
        return SSLContext.getDefault();
      } catch (NoSuchAlgorithmException exception) {
        throw new IllegalStateException(exception);
      }
    }

    @Override
    public SSLParameters sslParameters() {
      return new SSLParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
      return Optional.empty();
    }

    @Override
    public Version version() {
      return Version.HTTP_1_1;
    }

    @Override
    public Optional<Executor> executor() {
      return Optional.empty();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> HttpResponse<T> send(
        HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException {
      if (sendFailure != null) {
        throw sendFailure;
      }
      return (HttpResponse<T>) response;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
      return CompletableFuture.failedFuture(new UnsupportedOperationException());
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request,
        HttpResponse.BodyHandler<T> responseBodyHandler,
        HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
      return CompletableFuture.failedFuture(new UnsupportedOperationException());
    }
  }

  private record InputStreamResponse(int statusCode, InputStream body, HttpHeaders headers)
      implements HttpResponse<InputStream> {
    private InputStreamResponse(int statusCode, InputStream body) {
      this(statusCode, body, HttpHeaders.of(Collections.emptyMap(), (_, _) -> true));
    }

    @Override
    public HttpRequest request() {
      return HttpRequest.newBuilder(uri()).GET().build();
    }

    @Override
    public Optional<HttpResponse<InputStream>> previousResponse() {
      return Optional.empty();
    }

    @Override
    public Optional<SSLSession> sslSession() {
      return Optional.empty();
    }

    @Override
    public URI uri() {
      return URI.create("http://localhost/test");
    }

    @Override
    public HttpClient.Version version() {
      return HttpClient.Version.HTTP_1_1;
    }
  }
}
