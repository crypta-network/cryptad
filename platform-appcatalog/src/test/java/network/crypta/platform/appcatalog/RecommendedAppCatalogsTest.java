package network.crypta.platform.appcatalog;

import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RecommendedAppCatalogsTest {
  @Test
  void fromConfig_whenSourceIsMissing_expectVisibleUnconfiguredFirstPartyDescriptor() {
    RecommendedAppCatalog catalog =
        RecommendedAppCatalogs.fromConfig(
                Map.<String, String>of()::get, Map.<String, String>of()::get)
            .getFirst();

    assertEquals(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID, catalog.catalogId());
    assertEquals("Crypta First-Party Beta Catalog", catalog.name());
    assertEquals("beta", catalog.channel());
    assertFalse(catalog.configured());
    assertEquals(Optional.empty(), catalog.sourceKind());
    assertEquals(Optional.empty(), catalog.trustedCatalogKeyId());
  }

  @Test
  void fromConfig_whenSourceAndTrustedKeyAreConfigured_expectDescriptorReadyForAdd() {
    Map<String, String> properties =
        Map.of(
            RecommendedAppCatalogs.SOURCE_PROPERTY,
            "crypta:USK@example/catalog/cryptad-app-catalog.properties",
            RecommendedAppCatalogs.TRUSTED_CATALOG_KEY_ID_PROPERTY,
            "first-party-key",
            RecommendedAppCatalogs.REVIEWER_POLICY_HINT_PROPERTY,
            "first-party-review");

    RecommendedAppCatalog catalog =
        RecommendedAppCatalogs.fromConfig(properties::get, Map.<String, String>of()::get)
            .getFirst();

    assertTrue(catalog.configured());
    assertEquals(Optional.of("crypta"), catalog.sourceKind());
    assertEquals(
        Optional.of("crypta:USK@example/catalog/cryptad-app-catalog.properties"),
        catalog.sourceDisplayUri());
    assertEquals(Optional.of("first-party-key"), catalog.trustedCatalogKeyId());
    assertEquals(Optional.of("first-party-review"), catalog.reviewerPolicyHint());
  }

  @Test
  void fromConfig_whenDisabled_expectNoRecommendedCatalogs() {
    Map<String, String> properties = Map.of(RecommendedAppCatalogs.ENABLED_PROPERTY, "false");

    assertTrue(
        RecommendedAppCatalogs.fromConfig(properties::get, Map.<String, String>of()::get)
            .isEmpty());
  }

  @Test
  void fromConfig_whenEnvironmentProvidesSource_expectEnvironmentUsed() {
    Map<String, String> environment =
        Map.of(
            RecommendedAppCatalogs.SOURCE_ENV,
            "https://example.invalid/cryptad-app-catalog.properties");

    RecommendedAppCatalog catalog =
        RecommendedAppCatalogs.fromConfig(Map.<String, String>of()::get, environment::get)
            .getFirst();

    assertEquals(Optional.of("https"), catalog.sourceKind());
  }

  @Test
  void fromConfig_whenPropertyAndEnvironmentProvideSource_expectPropertyTakesPrecedence() {
    Map<String, String> properties =
        Map.of(
            RecommendedAppCatalogs.SOURCE_PROPERTY,
            "crypta:USK@example/catalog/cryptad-app-catalog.properties");
    Map<String, String> environment =
        Map.of(
            RecommendedAppCatalogs.SOURCE_ENV,
            "https://example.invalid/cryptad-app-catalog.properties");

    RecommendedAppCatalog catalog =
        RecommendedAppCatalogs.fromConfig(properties::get, environment::get).getFirst();

    assertEquals(Optional.of("crypta"), catalog.sourceKind());
    assertEquals(
        Optional.of("crypta:USK@example/catalog/cryptad-app-catalog.properties"),
        catalog.sourceDisplayUri());
  }

  @Test
  void fromConfig_whenFallbackTrustedKeyPropertyIsConfigured_expectTrustedKeyUsed() {
    Map<String, String> properties =
        Map.of(RecommendedAppCatalogs.TRUSTED_KEY_ID_PROPERTY, "first-party-short-key");

    RecommendedAppCatalog catalog =
        RecommendedAppCatalogs.fromConfig(properties::get, Map.<String, String>of()::get)
            .getFirst();

    assertEquals(Optional.of("first-party-short-key"), catalog.trustedCatalogKeyId());
  }

  @Test
  void fromConfig_whenSourceIsMalformed_expectInvalidCatalogSource() {
    Map<String, String> properties =
        Map.of(RecommendedAppCatalogs.SOURCE_PROPERTY, "crypta:USK@example");
    UnaryOperator<String> propertyReader = properties::get;
    UnaryOperator<String> environmentReader = Map.<String, String>of()::get;

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> RecommendedAppCatalogs.fromConfig(propertyReader, environmentReader));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }
}
