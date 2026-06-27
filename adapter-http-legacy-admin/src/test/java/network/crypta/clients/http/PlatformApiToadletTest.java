package network.crypta.clients.http;

import java.lang.reflect.Method;
import java.net.URI;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiToadletTest {
  private static final String BUNDLE_ID = "asb-111111111111111111111111";

  @Test
  void requiresFormPassword_whenPostingAppServiceGrantBundleCollection_expectProtected()
      throws Exception {
    assertTrue(requiresFormPassword("POST", "/api/v1/app-services/grant-bundles"));
  }

  @Test
  void requiresFormPassword_whenReadingAppServiceGrantBundleCollection_expectNotProtected()
      throws Exception {
    assertFalse(requiresFormPassword("GET", "/api/v1/app-services/grant-bundles"));
  }

  @Test
  void requiresFormPassword_whenPostingOperatorRecoveryPlanOrExecute_expectProtected()
      throws Exception {
    assertTrue(requiresFormPassword("POST", "/api/v1/operator/recovery/plan"));
    assertTrue(requiresFormPassword("POST", "/api/v1/operator/recovery/execute"));
  }

  @Test
  void requiresFormPassword_whenReadingOperatorRecoveryActions_expectNotProtected()
      throws Exception {
    assertFalse(requiresFormPassword("GET", "/api/v1/operator/recovery/actions"));
  }

  @Test
  void requiresFormPassword_whenPostingAppServiceGrantBundleActions_expectProtected()
      throws Exception {
    assertTrue(
        requiresFormPassword(
            "POST", "/api/v1/app-services/grant-bundles/" + BUNDLE_ID + "/approve"));
    assertTrue(
        requiresFormPassword(
            "POST", "/api/v1/app-services/grant-bundles/" + BUNDLE_ID + "/reject"));
    assertTrue(
        requiresFormPassword("POST", "/api/v1/app-services/grant-bundles/" + BUNDLE_ID + "/renew"));
  }

  @Test
  void requiresFormPassword_whenPostingConsentDecisionActions_expectProtected() throws Exception {
    assertTrue(requiresFormPassword("POST", "/api/v1/consent/approve"));
    assertTrue(requiresFormPassword("POST", "/api/v1/consent/reject"));
    assertTrue(requiresFormPassword("POST", "/api/v1/consent/defer"));
    assertTrue(requiresFormPassword("POST", "/api/v1/consent/update-preview"));
  }

  @Test
  void requiresFormPassword_whenMutatingCatalogOperations_expectProtected() throws Exception {
    assertTrue(requiresFormPassword("POST", "/api/v1/app-catalogs/core/mirrors"));
    assertTrue(requiresFormPassword("POST", "/api/v1/app-catalogs/core/mirrors/backup"));
    assertTrue(requiresFormPassword("DELETE", "/api/v1/app-catalogs/core/mirrors/backup"));
    assertTrue(
        requiresFormPassword("POST", "/api/v1/app-catalogs/core/operations/refresh-primary"));
    assertTrue(requiresFormPassword("POST", "/api/v1/app-catalogs/core/operations/rollback"));
    assertTrue(
        requiresFormPassword("POST", "/api/v1/app-catalogs/core/operations/emergency-refresh"));
  }

  @Test
  void requiresFormPassword_whenReadingCatalogOperations_expectNotProtected() throws Exception {
    assertFalse(requiresFormPassword("GET", "/api/v1/app-catalogs/core/mirrors"));
    assertFalse(requiresFormPassword("GET", "/api/v1/app-catalogs/core/operations/health"));
    assertFalse(requiresFormPassword("GET", "/api/v1/app-catalogs/core/operations/revisions"));
    assertFalse(requiresFormPassword("GET", "/api/v1/app-catalogs/core/operations/key-rotation"));
  }

  @Test
  void requiresFormPassword_whenReadingConsentPreviews_expectNotProtected() throws Exception {
    assertFalse(requiresFormPassword("GET", "/api/v1/consent/install-preview"));
    assertFalse(requiresFormPassword("GET", "/api/v1/consent/update-preview"));
    assertFalse(requiresFormPassword("GET", "/api/v1/consent/audit"));
  }

  private static boolean requiresFormPassword(String method, String path) throws Exception {
    Method guard =
        PlatformApiToadlet.class.getDeclaredMethod("requiresFormPassword", String.class, URI.class);
    guard.setAccessible(true);
    return (Boolean) guard.invoke(null, method, URI.create(path));
  }
}
