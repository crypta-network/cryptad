package network.crypta.platform.appdist;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppApiCompatibilityMetadataTest {
  @Test
  void constructor_whenLegacyConstructorUsed_expectExperimentalDefaultWithoutTargetDeclaration() {
    AppApiCompatibilityMetadata metadata = new AppApiCompatibilityMetadata(1, 2, List.of(), false);

    assertEquals(
        AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL, metadata.targetStability());
    assertFalse(metadata.targetStabilityDeclared());
    assertTrue(metadata.declared());
  }

  @Test
  void constructor_whenExplicitStableTargetUsed_expectDeclaredStableTarget() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            null, null, List.of(), AppApiCompatibilityMetadata.TargetStability.STABLE, false);

    assertEquals(AppApiCompatibilityMetadata.TargetStability.STABLE, metadata.targetStability());
    assertTrue(metadata.targetStabilityDeclared());
    assertTrue(metadata.declared());
  }

  @Test
  void constructor_whenCanonicalTargetMissing_expectUndeclaredExperimentalDefault() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(null, null, List.of(), null, true, false);

    assertEquals(
        AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL, metadata.targetStability());
    assertFalse(metadata.targetStabilityDeclared());
    assertFalse(metadata.declared());
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
