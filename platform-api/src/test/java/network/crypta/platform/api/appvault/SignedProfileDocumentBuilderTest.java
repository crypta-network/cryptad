package network.crypta.platform.api.appvault;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppIdentityUsageResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@SuppressWarnings({"unchecked", "java:S100"})
class SignedProfileDocumentBuilderTest {
  @Test
  void build_whenGivenProfileAndUsageResult_expectPublicSignedDocumentShape() {
    ProfileDocumentRequest request =
        ProfileDocumentRequest.fromQuery(
            "profile-publisher",
            "identity-one",
            Map.of(
                "displayName", List.of("Ada Example"),
                "bio", List.of("Line one\nLine two"),
                "tags", List.of("crypta,profile")));
    AppIdentityRecord identity =
        new AppIdentityRecord(
            "identity-one",
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Profile identity",
            "profile-publisher",
            Instant.EPOCH,
            Instant.EPOCH.plusSeconds(1),
            Map.of("publicKeyBase64", "record-public-key"),
            "identity-fingerprint",
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityUsageResult usageResult =
        new AppIdentityUsageResult(
            "identity-one",
            AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
            "Ed25519",
            "identity-fingerprint",
            "usage-public-key",
            "payload-sha",
            "CryptaAppVault:v1:profile-publisher:identity-one:profile.publish.v1:payload-sha",
            "signature-base64");

    Map<String, Object> document =
        SignedProfileDocumentBuilder.build(request, identity, usageResult);

    assertEquals(ProfileDocumentRequest.SCHEMA, document.get("schema"));
    Map<String, Object> profile = (Map<String, Object>) document.get("profile");
    assertEquals("Ada Example", profile.get("displayName"));
    assertEquals("Line one\nLine two", profile.get("bio"));
    Map<String, Object> identityJson = (Map<String, Object>) document.get("identity");
    assertEquals("identity-one", identityJson.get("identityId"));
    assertEquals("identity-fingerprint", identityJson.get("fingerprint"));
    assertEquals("Ed25519", identityJson.get("algorithm"));
    assertEquals("usage-public-key", identityJson.get("publicKeyBase64"));
    Map<String, Object> signature = (Map<String, Object>) document.get("signature");
    assertEquals("sign.domain-separated", signature.get("scope"));
    assertEquals(ProfileDocumentRequest.SIGNING_PURPOSE, signature.get("purpose"));
    assertEquals("payload-sha", signature.get("payloadSha256"));
    assertEquals(
        "CryptaAppVault:v1:profile-publisher:identity-one:profile.publish.v1:payload-sha",
        signature.get("domainSeparatedPayload"));
    assertEquals("signature-base64", signature.get("signatureBase64"));
    assertFalse(document.toString().contains("privateKey"));
    assertFalse(document.toString().contains("envelope"));
  }
}
