package network.crypta.platform.appui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AppUiRouteTest {
  @Test
  void parse_whenAppRootRequested_expectRootRoute() throws Exception {
    AppUiRoute route = AppUiRoute.parse("/apps/Demo-App/");

    assertEquals("demo-app", route.appId());
    assertNull(route.assetPath());
  }

  @Test
  void parse_whenAssetPathEndsWithSlash_expectTrailingSlashDoesNotCreateUnsafeSegment()
      throws Exception {
    AppUiRoute route = AppUiRoute.parse("/apps/demo-app/static/");

    assertEquals("demo-app", route.appId());
    assertEquals("static", route.assetPath());
  }

  @Test
  void parse_whenAssetContainsEncodedSlash_expectBadRequest() {
    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class,
            () -> AppUiRoute.parse("/apps/demo-app/static%2Fapp.js"));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void parse_whenAssetContainsEncodedControlCharacter_expectBadRequest() {
    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class,
            () -> AppUiRoute.parse("/apps/demo-app/static/%09app.js"));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void parse_whenPathContainsMalformedPercentEncoding_expectBadRequest() {
    AppStaticAssetException exception =
        assertThrows(
            AppStaticAssetException.class, () -> AppUiRoute.parse("/apps/demo-app/static/%zz.js"));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void parse_whenAppIdDecodesToUnsafeSegment_expectNotFound() {
    AppStaticAssetException exception =
        assertThrows(AppStaticAssetException.class, () -> AppUiRoute.parse("/apps/demo%2Fapp/"));

    assertEquals(404, exception.statusCode());
  }

  @Test
  void trailingSlashRedirectTarget_whenAppRootMissingSlash_expectCanonicalAppRoot()
      throws Exception {
    assertEquals("/apps/demo-app/", AppUiRoute.trailingSlashRedirectTarget("/apps/Demo-App"));
  }
}
