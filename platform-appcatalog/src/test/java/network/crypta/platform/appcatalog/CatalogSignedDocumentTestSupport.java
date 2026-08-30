package network.crypta.platform.appcatalog;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import network.crypta.platform.appdist.TrustedAppKey;

final class CatalogSignedDocumentTestSupport {
  static final String ISSUER_KEY_ID = "independent-catalog-operator";
  static final String SHA256_ZERO = "0".repeat(64);
  static final String PLACEHOLDER_SIGNATURE = Base64.getEncoder().encodeToString(new byte[64]);
  static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");

  private CatalogSignedDocumentTestSupport() {}

  static KeyPair keyPair() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance(CatalogSignedDocumentSupport.ED25519).generateKeyPair();
  }

  static TrustedAppKey trustedKey(KeyPair keyPair) {
    return new TrustedAppKey(
        ISSUER_KEY_ID, CatalogSignedDocumentSupport.ED25519, keyPair.getPublic());
  }

  static String fingerprint(KeyPair keyPair) {
    return CatalogSignedDocumentSupport.publicKeyFingerprint(keyPair.getPublic());
  }

  static CatalogDiscoveryDescriptor signedDescriptor(KeyPair keyPair)
      throws GeneralSecurityException {
    CatalogDiscoveryDescriptor.Content content =
        new CatalogDiscoveryDescriptor.Content(
            CatalogDiscoveryDescriptor.SCHEMA_VERSION,
            "descriptor-independent-beta",
            new CatalogDiscoveryDescriptor.Subject(
                "independent-beta",
                "independent-catalog-signer",
                SHA256_ZERO,
                List.of(java.net.URI.create("https://catalog.example/catalog.properties")),
                List.of("beta")),
            new CatalogDiscoveryDescriptor.Display(
                "Independent beta", "Public discovery metadata only", "independent-operator"),
            new CatalogDiscoveryDescriptor.Transparency(
                Optional.of("1".repeat(64)),
                Optional.of(java.net.URI.create("https://catalog.example/reviewers.json")),
                Optional.of("2".repeat(64)),
                Optional.empty()),
            new CatalogDiscoveryDescriptor.Validity(
                NOW.minusSeconds(60), NOW.plusSeconds(3600), Optional.empty(), Optional.empty()),
            new CatalogDiscoveryDescriptor.Issuer(
                "independent-operator", ISSUER_KEY_ID, fingerprint(keyPair)));
    String digest =
        CatalogSignedDocumentSupport.sha256(
            CatalogSignedDocumentSupport.jsonBytes(content.toJsonValue()));
    CatalogDiscoveryDescriptor unsigned =
        new CatalogDiscoveryDescriptor(
            content,
            new CatalogDiscoveryDescriptor.Authentication(
                digest, CatalogSignedDocumentSupport.ED25519, PLACEHOLDER_SIGNATURE));
    return new CatalogDiscoveryDescriptor(
        content,
        new CatalogDiscoveryDescriptor.Authentication(
            digest,
            CatalogSignedDocumentSupport.ED25519,
            sign(keyPair, unsigned.canonicalSignaturePayloadBytes())));
  }

  static CatalogEndorsement signedEndorsement(KeyPair keyPair) throws GeneralSecurityException {
    return signedEndorsement(
        keyPair, "independent-beta", SHA256_ZERO, "3".repeat(64), "endorsement-independent-beta");
  }

  static CatalogEndorsement signedEndorsement(
      KeyPair keyPair,
      String catalogId,
      String signerFingerprint,
      String descriptorDigest,
      String endorsementId)
      throws GeneralSecurityException {
    CatalogEndorsement.Content content =
        new CatalogEndorsement.Content(
            CatalogEndorsement.SCHEMA_VERSION,
            endorsementId,
            new CatalogEndorsement.Subject(catalogId, signerFingerprint, descriptorDigest),
            new CatalogEndorsement.Evidence(
                Optional.of("1".repeat(64)),
                Optional.empty(),
                List.of("independently-operated", "beta"),
                Optional.of("Direct signed recommendation")),
            new CatalogEndorsement.Validity(NOW.minusSeconds(60), NOW.plusSeconds(3600)),
            new CatalogEndorsement.Issuer(
                "independent-operator", ISSUER_KEY_ID, fingerprint(keyPair)));
    String digest =
        CatalogSignedDocumentSupport.sha256(
            CatalogSignedDocumentSupport.jsonBytes(content.toJsonValue()));
    CatalogEndorsement unsigned =
        new CatalogEndorsement(
            content,
            new CatalogEndorsement.Authentication(
                digest, CatalogSignedDocumentSupport.ED25519, PLACEHOLDER_SIGNATURE));
    return new CatalogEndorsement(
        content,
        new CatalogEndorsement.Authentication(
            digest,
            CatalogSignedDocumentSupport.ED25519,
            sign(keyPair, unsigned.canonicalSignaturePayloadBytes())));
  }

  static CatalogDiscoveryDescriptor signDescriptor(
      KeyPair keyPair, CatalogDiscoveryDescriptor.Content content) throws GeneralSecurityException {
    String digest =
        CatalogSignedDocumentSupport.sha256(
            CatalogSignedDocumentSupport.jsonBytes(content.toJsonValue()));
    CatalogDiscoveryDescriptor unsigned =
        new CatalogDiscoveryDescriptor(
            content,
            new CatalogDiscoveryDescriptor.Authentication(
                digest, CatalogSignedDocumentSupport.ED25519, PLACEHOLDER_SIGNATURE));
    return new CatalogDiscoveryDescriptor(
        content,
        new CatalogDiscoveryDescriptor.Authentication(
            digest,
            CatalogSignedDocumentSupport.ED25519,
            sign(keyPair, unsigned.canonicalSignaturePayloadBytes())));
  }

  private static String sign(KeyPair keyPair, byte[] payload) throws GeneralSecurityException {
    Signature signer = Signature.getInstance(CatalogSignedDocumentSupport.ED25519);
    signer.initSign(keyPair.getPrivate());
    signer.update(payload);
    return Base64.getEncoder().encodeToString(signer.sign());
  }
}
