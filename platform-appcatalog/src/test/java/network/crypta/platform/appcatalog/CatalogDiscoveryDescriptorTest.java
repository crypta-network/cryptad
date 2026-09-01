package network.crypta.platform.appcatalog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import network.crypta.platform.appdist.TrustedAppKeyLifecycle;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class CatalogDiscoveryDescriptorTest {
  private static final String CATALOG_ID = "independent-beta";
  private static final String CATALOG_SOURCE_PATH = "/catalog.properties";

  @Test
  void verifyForImport_whenDescriptorIsAuthentic_expectPendingWithoutTrustOrSourceConfiguration()
      throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);

    CatalogDiscoveryImportResult result =
        CatalogDiscoveryVerifier.verifyForImport(
            descriptor.canonicalDocumentBytes(),
            TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair)),
            CatalogSignedDocumentTestSupport.NOW);

    assertEquals(CatalogDiscoveryImportResult.Status.PENDING, result.status());
    assertEquals(CATALOG_ID, result.descriptor().catalogId());
    assertFalse(CatalogDiscoveryImportResult.TRUST_GRANTED);
    assertFalse(CatalogDiscoveryImportResult.SOURCE_CONFIGURED);
    assertFalse(CatalogDiscoveryImportResult.TRANSITIVE);
    assertArrayEquals(
        descriptor.canonicalDocumentBytes(), result.descriptor().canonicalDocumentBytes());
  }

  @Test
  void verifyForImport_whenSelfDigestIsSubstituted_expectFailsClosed() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    CatalogDiscoveryDescriptor substituted =
        new CatalogDiscoveryDescriptor(
            descriptor.content(),
            new CatalogDiscoveryDescriptor.Authentication(
                "f".repeat(64),
                descriptor.authentication().signatureAlgorithm(),
                descriptor.authentication().signatureValueBase64()));
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                CatalogDiscoveryVerifier.verifyForImport(
                    substituted, trustedKeys, CatalogSignedDocumentTestSupport.NOW));

    assertEquals(CatalogSignedDocumentSupport.INVALID_DESCRIPTOR, exception.errorCode());
  }

  @Test
  void verifyForImport_whenDescriptorIsExpired_expectFailsClosed() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    TrustedAppKeys trustedKeys =
        TrustedAppKeys.of(CatalogSignedDocumentTestSupport.trustedKey(keyPair));
    Instant expiredAt = CatalogSignedDocumentTestSupport.NOW.plusSeconds(7200);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> CatalogDiscoveryVerifier.verifyForImport(descriptor, trustedKeys, expiredAt));

    assertEquals(CatalogSignedDocumentSupport.INVALID_DESCRIPTOR, exception.errorCode());
  }

  @Test
  void verifyForImport_whenIssuerIsRevoked_expectFailsClosed() throws Exception {
    KeyPair keyPair = CatalogSignedDocumentTestSupport.keyPair();
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(keyPair);
    TrustedAppKeyPolicy revokedPolicy =
        new TrustedAppKeyPolicy(
            CatalogSignedDocumentTestSupport.trustedKey(keyPair),
            TrustedAppKeyLifecycle.REVOKED,
            Instant.MIN,
            Instant.MAX);
    TrustedAppKeys trustedKeys = TrustedAppKeys.ofPolicies(revokedPolicy);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                CatalogDiscoveryVerifier.verifyForImport(
                    descriptor, trustedKeys, CatalogSignedDocumentTestSupport.NOW));

    assertEquals(CatalogSignedDocumentSupport.INVALID_SIGNATURE, exception.errorCode());
  }

  @Test
  void subject_whenSourceHintLeaksLocalOrCredentialMaterial_expectRejectsEveryHint() {
    List<String> unsafeHints =
        List.of(
            "file:///tmp/catalog.properties",
            credentialHttpsSource(),
            httpsSource(ipv4(127, 0, 0, 1)),
            httpsSource(ipv4MappedIpv6(127, 0, 0, 1)),
            httpsSource(ipv4MappedIpv6(10, 0, 0, 1)),
            httpsSource(ipv6("ff02", "1")),
            httpsSource(ipv6("fec0", "1")),
            httpsSource(ipv6("fc00", "1")),
            httpsSource(ipv6("2001:db8", "1")),
            httpsSource(ipv6("100", "1")),
            httpsSource(ipv4(100, 64, 0, 1)),
            httpsSource(ipv4(192, 0, 2, 1)),
            httpsSource(ipv4(198, 18, 0, 1)),
            httpsSource("127.1"),
            httpsSource("2130706433"),
            httpsSource("node.local"),
            httpsSource("node.local."),
            "crypta:USK@private,AQECAAE/catalog/1/catalog.properties");

    for (String unsafeHint : unsafeHints) {
      List<URI> sourceHints = List.of(URI.create(unsafeHint));
      List<String> channels = List.of("beta");

      assertThrows(
          AppCatalogException.class,
          () ->
              new CatalogDiscoveryDescriptor.Subject(
                  CATALOG_ID,
                  "catalog-signer",
                  CatalogSignedDocumentTestSupport.SHA256_ZERO,
                  sourceHints,
                  channels),
          unsafeHint);
    }
  }

  @Test
  void subject_whenSourceHintUsesPublicHost_expectAcceptsWithoutNameResolution() {
    List<String> publicHints =
        List.of(
            httpsSource(ipv4(8, 8, 8, 8)),
            httpsSource(ipv4(192, 0, 1, 1)),
            httpsSource(ipv6("2606:4700:4700", "1111")),
            httpsSource(ipv4MappedIpv6(8, 8, 8, 8)),
            httpsSource("catalogs.example"));

    for (String publicHint : publicHints) {
      CatalogDiscoveryDescriptor.Subject subject =
          new CatalogDiscoveryDescriptor.Subject(
              CATALOG_ID,
              "catalog-signer",
              CatalogSignedDocumentTestSupport.SHA256_ZERO,
              List.of(URI.create(publicHint)),
              List.of("beta"));

      assertEquals(List.of(URI.create(publicHint)), subject.sourceHints());
    }
  }

  @Test
  void parse_whenDocumentContainsUnknownFieldOrExceedsLimit_expectRejectsClosedInput()
      throws Exception {
    CatalogDiscoveryDescriptor descriptor =
        CatalogSignedDocumentTestSupport.signedDescriptor(
            CatalogSignedDocumentTestSupport.keyPair());
    String document = new String(descriptor.canonicalDocumentBytes(), StandardCharsets.UTF_8);
    byte[] unknownField =
        document.replaceFirst("\\{", "{\"unknown\":true,").getBytes(StandardCharsets.UTF_8);
    byte[] oversized = new byte[CatalogSignedDocumentSupport.MAX_DOCUMENT_BYTES + 1];
    Arrays.fill(oversized, (byte) ' ');

    assertThrows(AppCatalogException.class, () -> CatalogDiscoveryDescriptor.parse(unknownField));
    assertThrows(AppCatalogException.class, () -> CatalogDiscoveryDescriptor.parse(oversized));
  }

  private static String credentialHttpsSource() {
    String user = "operator";
    String credential = "secret";
    String host = "catalog.example";
    return "https://" + user + ':' + credential + '@' + host + CATALOG_SOURCE_PATH;
  }

  private static String httpsSource(String host) {
    return "https://" + host + CATALOG_SOURCE_PATH;
  }

  private static String ipv4(int first, int second, int third, int fourth) {
    return first + "." + second + "." + third + "." + fourth;
  }

  private static String ipv4MappedIpv6(int first, int second, int third, int fourth) {
    return "[::ffff:" + ipv4(first, second, third, fourth) + ']';
  }

  private static String ipv6(String prefix, String suffix) {
    return '[' + prefix + "::" + suffix + ']';
  }
}
