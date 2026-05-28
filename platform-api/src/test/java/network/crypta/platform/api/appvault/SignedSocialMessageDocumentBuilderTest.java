package network.crypta.platform.api.appvault;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppIdentityUsageResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@SuppressWarnings("java:S100")
class SignedSocialMessageDocumentBuilderTest {
  @Test
  void build_whenGivenSignedRequest_expectPublicDocumentOnly() {
    SocialMessageRequest request =
        SocialMessageRequest.fromQuery(
            "social-inbox",
            "id-author",
            "fingerprint",
            Map.of("subject", List.of("Hello"), "body", List.of("Plain text body")),
            Clock.fixed(Instant.parse("2026-05-26T00:00:00Z"), ZoneOffset.UTC));

    Map<String, Object> document =
        SignedSocialMessageDocumentBuilder.build(request, identity(), usageResult());

    assertEquals("crypta.social.message.v1", document.get("type"));
    Map<?, ?> message = assertInstanceOf(Map.class, document.get("message"));
    assertEquals("social-inbox", message.get("appId"));
    assertEquals("id-author", message.get("identityId"));
    assertEquals("fingerprint", message.get("authorFingerprint"));
    assertEquals("Plain text body", message.get("body"));
    Map<?, ?> signature = assertInstanceOf(Map.class, document.get("signature"));
    assertEquals("Ed25519", signature.get("algorithm"));
    assertEquals("crypta.social.message.v1", signature.get("domain"));
    assertEquals("hash", signature.get("payloadHash"));
    assertEquals("fingerprint", signature.get("publicKeyFingerprint"));
    assertEquals("public", signature.get("publicKeyBase64"));
    assertEquals("signature", signature.get("signatureBase64"));
    assertFalse(document.toString().contains("privateKey"));
    assertFalse(document.toString().contains("private.envelope"));
    assertFalse(document.toString().contains("domainSeparatedPayload"));
    assertFalse(document.toString().contains("payloadBase64"));
  }

  private static AppIdentityRecord identity() {
    return new AppIdentityRecord(
        "id-author",
        AppIdentityKind.LOCAL_ED25519_SIGNING,
        "Author",
        "social-inbox",
        Instant.parse("2026-05-26T00:00:00Z"),
        Instant.parse("2026-05-26T00:00:00Z"),
        Map.of("publicKeyBase64", "public"),
        "fingerprint",
        java.util.Set.of(
            AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
  }

  private static AppIdentityUsageResult usageResult() {
    return new AppIdentityUsageResult(
        "id-author",
        AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
        "Ed25519",
        "fingerprint",
        "public",
        "hash",
        "crypta.social.message.v1\n{}",
        "signature");
  }
}
