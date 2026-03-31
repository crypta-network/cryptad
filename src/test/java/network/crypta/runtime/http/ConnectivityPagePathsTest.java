package network.crypta.runtime.http;

import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class ConnectivityPagePathsTest {

  @Test
  void connectivityPath_whenClassLoaded_returnsLegacyConnectivityPath() {
    assertEquals("/connectivity/", ConnectivityPagePaths.CONNECTIVITY_PATH);
  }

  @Test
  void pathProperty_whenRead_preservesLegacyOverrideKey() throws Exception {
    Field pathPropertyField = ConnectivityPagePaths.class.getDeclaredField("PATH_PROPERTY");
    pathPropertyField.setAccessible(true);

    assertEquals(
        "network.crypta.runtime.endpoints.http.ConnectivityPagePaths.path",
        pathPropertyField.get(null));
  }

  @Test
  void resolvePath_whenConfiguredPathMissing_returnsLegacyConnectivityPath() {
    assertEquals("/connectivity/", ConnectivityPagePaths.resolvePath(null));
  }

  @Test
  void resolvePath_whenConfiguredPathBlank_returnsLegacyConnectivityPath() {
    assertEquals("/connectivity/", ConnectivityPagePaths.resolvePath("   "));
  }

  @Test
  void resolvePath_whenConfiguredPathNeedsNormalization_addsBoundarySlashes() {
    assertEquals("/custom-connectivity/", ConnectivityPagePaths.resolvePath("custom-connectivity"));
  }

  @Test
  void resolvePath_whenConfiguredPathHasWhitespace_trimsBeforeNormalizing() {
    assertEquals("/custom/nested/", ConnectivityPagePaths.resolvePath(" custom/nested "));
  }

  @Test
  void resolvePath_whenConfiguredPathAlreadyNormalized_preservesExistingSeparators() {
    assertEquals("/custom/nested/", ConnectivityPagePaths.resolvePath("/custom/nested/"));
  }
}
