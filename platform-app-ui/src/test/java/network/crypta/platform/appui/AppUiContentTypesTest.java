package network.crypta.platform.appui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class AppUiContentTypesTest {
  @Test
  void forPath_whenKnownExtensionsRequested_expectMappedContentTypes() {
    assertEquals("text/html; charset=UTF-8", AppUiContentTypes.forPath("index.HTML"));
    assertEquals("text/html; charset=UTF-8", AppUiContentTypes.forPath("static/index.htm"));
    assertEquals("text/css; charset=UTF-8", AppUiContentTypes.forPath("static/app.css"));
    assertEquals("text/javascript; charset=UTF-8", AppUiContentTypes.forPath("static/app.js"));
    assertEquals("text/javascript; charset=UTF-8", AppUiContentTypes.forPath("static/app.mjs"));
    assertEquals("application/json; charset=UTF-8", AppUiContentTypes.forPath("static/app.json"));
    assertEquals("application/wasm", AppUiContentTypes.forPath("static/app.wasm"));
    assertEquals("image/svg+xml", AppUiContentTypes.forPath("static/icon.svg"));
    assertEquals("image/png", AppUiContentTypes.forPath("static/icon.png"));
    assertEquals("image/jpeg", AppUiContentTypes.forPath("static/photo.jpg"));
    assertEquals("image/jpeg", AppUiContentTypes.forPath("static/photo.jpeg"));
    assertEquals("image/gif", AppUiContentTypes.forPath("static/image.gif"));
    assertEquals("image/webp", AppUiContentTypes.forPath("static/image.webp"));
    assertEquals("image/x-icon", AppUiContentTypes.forPath("static/favicon.ico"));
  }

  @Test
  void forPath_whenUnknownOrMissingExtensionRequested_expectOctetStream() {
    assertEquals(AppUiContentTypes.OCTET_STREAM, AppUiContentTypes.forPath(null));
    assertEquals(AppUiContentTypes.OCTET_STREAM, AppUiContentTypes.forPath("static/readme"));
    assertEquals(AppUiContentTypes.OCTET_STREAM, AppUiContentTypes.forPath("static/file."));
    assertEquals(AppUiContentTypes.OCTET_STREAM, AppUiContentTypes.forPath("static/file.bin"));
  }
}
