package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FederatedCatalogConflictEngineTest {
  @Test
  void classify_whenSubjectsAreExactDuplicates_expectDeduplicableConflict() {
    var conflict =
        FederatedCatalogConflictEngine.classify(
                List.of(
                    subject("catalog-a", "1.0.0", "1", "5"),
                    subject("catalog-b", "1.0.0", "1", "5")))
            .orElseThrow();

    assertEquals(Set.of(FederatedCatalogConflictEngine.Type.EXACT_DUPLICATE), conflict.types());
    assertFalse(conflict.hard());
  }

  @Test
  void classify_whenSameVersionPayloadDiffers_expectHardConflictIndependentOfInputOrder() {
    var left = subject("catalog-a", "1.0.0", "1", "5");
    var right = subject("catalog-b", "1.0.0", "2", "5");

    var forward = FederatedCatalogConflictEngine.classify(List.of(left, right)).orElseThrow();
    var reverse = FederatedCatalogConflictEngine.classify(List.of(right, left)).orElseThrow();
    assertTrue(
        forward
            .types()
            .contains(FederatedCatalogConflictEngine.Type.SAME_VERSION_PAYLOAD_CONFLICT));
    assertTrue(forward.hard());
    assertEquals(forward.subjectSetDigest(), reverse.subjectSetDigest());
  }

  @Test
  void classify_whenPublisherDiffers_expectNamespaceConflict() {
    var conflict =
        FederatedCatalogConflictEngine.classify(
                List.of(
                    subject("catalog-a", "1.0.0", "1", "5"),
                    subject("catalog-b", "2.0.0", "1", "6")))
            .orElseThrow();

    assertTrue(
        conflict
            .types()
            .contains(FederatedCatalogConflictEngine.Type.PUBLISHER_NAMESPACE_CONFLICT));
    assertTrue(conflict.types().contains(FederatedCatalogConflictEngine.Type.COMPETING_VERSIONS));
    assertTrue(conflict.hard());
  }

  @Test
  void appliesTo_whenAnySubjectChanges_expectResolutionBecomesStale() {
    var original =
        FederatedCatalogConflictEngine.classify(
                List.of(
                    subject("catalog-a", "1.0.0", "1", "5"),
                    subject("catalog-b", "1.0.0", "2", "5")))
            .orElseThrow();
    var resolution =
        new FederatedCatalogConflictEngine.Resolution(
            original.conflictId(),
            original.subjectSetDigest(),
            FederatedCatalogConflictEngine.ResolutionKind.PIN_CATALOG,
            Optional.of("catalog-a"),
            Optional.empty(),
            Instant.EPOCH,
            "operator chose exact source",
            null);
    var changed =
        FederatedCatalogConflictEngine.classify(
                List.of(
                    subject("catalog-a", "1.0.0", "1", "5"),
                    subject("catalog-b", "1.0.0", "3", "5")))
            .orElseThrow();

    assertTrue(resolution.appliesTo(original));
    assertFalse(resolution.appliesTo(changed));
  }

  private static FederatedCatalogConflictEngine.Subject subject(
      String catalogId, String version, String bundleDigit, String publisherDigit) {
    return new FederatedCatalogConflictEngine.Subject(
        catalogId,
        "a".repeat(64),
        "example-app",
        version,
        bundleDigit.repeat(64),
        "zip",
        publisherDigit.repeat(64),
        publisherDigit.repeat(64),
        "b".repeat(64),
        "allow",
        "c".repeat(64));
  }
}
