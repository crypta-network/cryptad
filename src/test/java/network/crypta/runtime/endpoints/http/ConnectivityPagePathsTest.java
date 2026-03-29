package network.crypta.runtime.endpoints.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class ConnectivityPagePathsTest {

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
}
