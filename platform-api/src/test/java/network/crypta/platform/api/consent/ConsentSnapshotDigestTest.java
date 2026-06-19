package network.crypta.platform.api.consent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "unchecked"})
class ConsentSnapshotDigestTest {
  private static final Instant CREATED_AT = Instant.parse("2026-05-01T00:00:00Z");

  @Test
  void digest_whenRequestMetadataChanges_expectSameDigest() {
    ConsentSnapshot first = snapshot("request-1", CREATED_AT, "permission_required");
    ConsentSnapshot second =
        snapshot("request-2", CREATED_AT.plusSeconds(60), "permission_required");

    String firstDigest = first.snapshotDigest();
    String secondDigest = second.snapshotDigest();

    assertEquals(firstDigest, secondDigest);
  }

  @Test
  void digest_whenMaterialFindingChanges_expectDifferentDigest() {
    ConsentSnapshot first = snapshot("request-1", CREATED_AT, "permission_required");
    ConsentSnapshot second = snapshot("request-1", CREATED_AT, "review_trust_delta");

    String firstDigest = first.snapshotDigest();
    String secondDigest = second.snapshotDigest();

    assertNotEquals(firstDigest, secondDigest);
  }

  @Test
  void canonicalize_whenNestedValuesContainSensitiveStrings_expectSortedRedactedCopy() {
    Map<String, Object> canonical =
        (Map<String, Object>)
            ConsentJson.canonicalize(
                Map.of(
                    "zeta",
                    "token=secret-value",
                    "alpha",
                    List.of("CHK@private-material", "/tmp/local/secret/path", true)));

    List<String> keys = new ArrayList<>(canonical.keySet());
    List<Object> nested = (List<Object>) canonical.get("alpha");

    assertEquals(List.of("alpha", "zeta"), keys);
    assertEquals("[redacted-secret]", canonical.get("zeta"));
    assertTrue(nested.contains("[redacted-private-uri]"));
    assertTrue(nested.contains("[redacted-local-path]"));
    assertTrue(nested.contains(true));
    assertFalse(canonical.toString().contains("secret-value"));
    assertFalse(canonical.toString().contains("CHK@private"));
    assertFalse(canonical.toString().contains("/tmp/local/secret/path"));
  }

  private static ConsentSnapshot snapshot(String requestId, Instant createdAt, String findingCode) {
    ConsentFinding finding =
        new ConsentFinding(
            findingCode,
            "Permission",
            "Candidate permission changed",
            "candidate",
            ConsentRiskLevel.MATERIAL);
    ConsentSection section =
        new ConsentSection(
            "permissions", "Permissions", ConsentRiskLevel.MATERIAL, List.of(finding));
    return new ConsentSnapshot(
        requestId,
        ConsentActionType.UPDATE_APP,
        "example.app",
        "Example App",
        "1.0.0",
        "1.1.0",
        "sha256:installed",
        "sha256:candidate",
        "first-party",
        "first-party",
        ConsentRiskLevel.MATERIAL,
        true,
        true,
        List.of(findingCode),
        "review_before_update",
        List.of(section),
        createdAt);
  }
}
