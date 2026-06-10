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

  private static boolean requiresFormPassword(String method, String path) throws Exception {
    Method guard =
        PlatformApiToadlet.class.getDeclaredMethod("requiresFormPassword", String.class, URI.class);
    guard.setAccessible(true);
    return (Boolean) guard.invoke(null, method, URI.create(path));
  }
}
