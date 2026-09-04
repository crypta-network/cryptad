package network.crypta.platform.appdist;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppApiCompatibilityMetadataTest {
  @Test
  void constructor_whenLegacyConstructorUsed_expectExperimentalDefaultWithoutTargetDeclaration() {
    AppApiCompatibilityMetadata metadata = new AppApiCompatibilityMetadata(1, 2, List.of(), false);

    assertEquals(
        AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL, metadata.targetStability());
    assertFalse(metadata.targetStabilityDeclared());
    assertNull(metadata.targetBaseline());
    assertFalse(metadata.targetBaselineDeclared());
    assertTrue(metadata.declared());
  }

  @Test
  void constructor_whenExplicitStableTargetUsed_expectDeclaredStableTarget() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            null, null, List.of(), AppApiCompatibilityMetadata.TargetStability.STABLE, false);

    assertEquals(AppApiCompatibilityMetadata.TargetStability.STABLE, metadata.targetStability());
    assertTrue(metadata.targetStabilityDeclared());
    assertEquals(
        AppApiCompatibilityMetadata.DEFAULT_STABLE_TARGET_BASELINE, metadata.targetBaseline());
    assertFalse(metadata.targetBaselineDeclared());
    assertTrue(metadata.declared());
  }

  @Test
  void constructor_whenCanonicalTargetMissing_expectUndeclaredExperimentalDefault() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(null, null, List.of(), null, true, false);

    assertEquals(
        AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL, metadata.targetStability());
    assertFalse(metadata.targetStabilityDeclared());
    assertNull(metadata.targetBaseline());
    assertFalse(metadata.targetBaselineDeclared());
    assertFalse(metadata.declared());
  }

  @Test
  void constructor_whenTargetBaselineDeclared_expectExactDeclarationPreserved() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            23,
            24,
            List.of(),
            AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL,
            true,
            "1.1",
            true,
            true,
            true);

    assertEquals("1.1", metadata.targetBaseline());
    assertTrue(metadata.targetBaselineDeclared());
    assertTrue(metadata.declared());
  }

  @Test
  void constructor_whenEffectiveDefaultBaselineCopied_expectDeclarationStatePreserved() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19,
            23,
            List.of(),
            AppApiCompatibilityMetadata.TargetStability.STABLE,
            true,
            "1.0",
            false,
            false,
            false);

    assertEquals("1.0", metadata.targetBaseline());
    assertFalse(metadata.targetBaselineDeclared());
  }

  @Test
  void constructor_whenBaselineMarkedDeclaredWithoutValue_expectFailure() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new AppApiCompatibilityMetadata(
                19,
                23,
                List.of(),
                AppApiCompatibilityMetadata.TargetStability.STABLE,
                true,
                null,
                true,
                false,
                false));
  }

  @Test
  void constructor_whenTargetBaselineIsMalformedOrAliased_expectFailure() {
    for (String targetBaseline : List.of("01.0", "1.00", "1", "v1.0", "2.0", " 1.0", "1.0 ")) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new AppApiCompatibilityMetadata(
                  null,
                  null,
                  List.of(),
                  AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL,
                  true,
                  targetBaseline,
                  true,
                  false,
                  false));
    }
  }

  @Test
  void constructor_whenExperimentalAcceptanceFalseDeclared_expectDeclaredMetadata() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(null, null, List.of(), null, false, false, true);

    assertFalse(metadata.experimentalCapabilitiesAccepted());
    assertTrue(metadata.experimentalCapabilitiesAcceptedDeclared());
    assertTrue(metadata.declared());
  }

  @Test
  void parse_whenTargetStabilityUsesWhitespaceAndCase_expectNormalizedTarget() {
    assertEquals(
        AppApiCompatibilityMetadata.TargetStability.STABLE,
        AppApiCompatibilityMetadata.TargetStability.parse(" STABLE "));
    assertEquals(
        AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL,
        AppApiCompatibilityMetadata.TargetStability.parse("Experimental"));
  }
}
