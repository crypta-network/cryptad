package network.crypta.platform.appui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class AppUiSecurityHeadersTest {
  @Test
  void headers_whenJavascriptEnabled_expectSameOriginFormAction() {
    assertEquals(
        "default-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; object-src"
            + " 'none'; form-action 'self'; frame-ancestors 'self'",
        AppUiSecurityHeaders.headers(true).get("content-security-policy"));
  }

  @Test
  void headers_whenJavascriptDisabled_expectSameOriginFormActionAndScriptsBlocked() {
    assertEquals(
        "default-src 'self'; script-src 'none'; connect-src 'self'; base-uri 'none'; object-src"
            + " 'none'; form-action 'self'; frame-ancestors 'self'",
        AppUiSecurityHeaders.headers(false).get("content-security-policy"));
  }

  @Test
  void headers_whenPlatformApiRootProvided_expectConnectSrcAllowsAdminApiOrigin() {
    assertEquals(
        "default-src 'self'; script-src 'self'; connect-src 'self' http://127.0.0.1:8888;"
            + " base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'self'"
            + " http://127.0.0.1:8888",
        AppUiSecurityHeaders.headers(
                true, "http://127.0.0.1:8888/api/v1/", "http://127.0.0.1:8888/app/node/")
            .get("content-security-policy"));
  }
}
