package network.crypta.platform.appui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@SuppressWarnings("java:S100")
class AppUiSecurityHeadersTest {
  private static final String STRICT_JAVASCRIPT_ENABLED_CSP =
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src"
          + " 'self'; connect-src 'self'; media-src 'none'; frame-src 'none'; worker-src 'none';"
          + " object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self';"
          + " manifest-src 'self'";

  @Test
  void headers_whenJavascriptEnabled_expectStrictSameOriginPolicy() {
    assertEquals(
        STRICT_JAVASCRIPT_ENABLED_CSP,
        AppUiSecurityHeaders.headers(true).get("content-security-policy"));
  }

  @Test
  void headers_whenJavascriptEnabled_expectDefensiveHeaders() {
    var headers = AppUiSecurityHeaders.headers(true);

    assertEquals("nosniff", headers.get("x-content-type-options"));
    assertEquals("no-referrer", headers.get("referrer-policy"));
    assertEquals(
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(),"
            + " bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=()",
        headers.get("permissions-policy"));
    assertEquals("same-origin", headers.get("cross-origin-resource-policy"));
    assertEquals("SAMEORIGIN", headers.get("x-frame-options"));
  }

  @Test
  void headers_whenJavascriptDisabled_expectStrictPolicyAndScriptsBlocked() {
    assertEquals(
        STRICT_JAVASCRIPT_ENABLED_CSP.replace("script-src 'self'", "script-src 'none'"),
        AppUiSecurityHeaders.headers(false).get("content-security-policy"));
  }

  @Test
  void headers_whenLocalPlatformApiAndShellRootsProvided_expectCspAllowsOnlyTheirOrigins() {
    assertEquals(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src"
            + " 'self'; connect-src 'self' http://127.0.0.1:8888; media-src 'none'; frame-src"
            + " 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action"
            + " 'self'; frame-ancestors 'self' http://127.0.0.1:8888; manifest-src 'self'",
        AppUiSecurityHeaders.headers(
                true, "http://127.0.0.1:8888/api/v1/", "http://127.0.0.1:8888/app/node/")
            .get("content-security-policy"));
    assertFalse(
        AppUiSecurityHeaders.headers(
                true, "http://127.0.0.1:8888/api/v1/", "http://127.0.0.1:8888/app/node/")
            .containsKey("x-frame-options"));
  }

  @Test
  void headers_whenHttpsLocalPlatformApiAndShellRootsProvided_expectCspAllowsTheirOrigins() {
    assertEquals(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src"
            + " 'self'; connect-src 'self' https://127.0.0.1:9443; media-src 'none'; frame-src"
            + " 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action"
            + " 'self'; frame-ancestors 'self' https://127.0.0.1:9443; manifest-src 'self'",
        AppUiSecurityHeaders.headers(
                true, "https://127.0.0.1:9443/api/v1/", "https://127.0.0.1:9443/app/node/")
            .get("content-security-policy"));
  }

  @Test
  void headers_whenLocalhostAdminRootsProvided_expectCspPreservesLocalhostOrigin() {
    assertEquals(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src"
            + " 'self'; connect-src 'self' http://localhost:8888; media-src 'none'; frame-src"
            + " 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action"
            + " 'self'; frame-ancestors 'self' http://localhost:8888; manifest-src 'self'",
        AppUiSecurityHeaders.headers(
                true, "http://localhost:8888/api/v1/", "http://localhost:8888/app/node/")
            .get("content-security-policy"));
  }

  @Test
  void headers_whenIpv6LoopbackAdminRootsProvided_expectCspPreservesIpv6Origin() {
    assertEquals(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src"
            + " 'self'; connect-src 'self' http://[::1]:8888; media-src 'none'; frame-src"
            + " 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action"
            + " 'self'; frame-ancestors 'self' http://[::1]:8888; manifest-src 'self'",
        AppUiSecurityHeaders.headers(
                true, "http://[::1]:8888/api/v1/", "http://[::1]:8888/app/node/")
            .get("content-security-policy"));
  }

  @Test
  void headers_whenExpandedIpv6LoopbackAdminRootsProvided_expectCspPreservesIpv6Origin() {
    assertEquals(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src"
            + " 'self'; connect-src 'self' http://[0:0:0:0:0:0:0:1]:8888; media-src"
            + " 'none'; frame-src 'none'; worker-src 'none'; object-src 'none'; base-uri"
            + " 'none'; form-action 'self'; frame-ancestors 'self'"
            + " http://[0:0:0:0:0:0:0:1]:8888; manifest-src 'self'",
        AppUiSecurityHeaders.headers(
                true,
                "http://[0:0:0:0:0:0:0:1]:8888/api/v1/",
                "http://[0:0:0:0:0:0:0:1]:8888/app/node/")
            .get("content-security-policy"));
  }

  @Test
  void headers_whenUnsafeRootsProvided_expectOriginsIgnoredAndSameOriginFrameFallback() {
    for (String unsafeRoot :
        java.util.List.of(
            "http://admin.example:8888/api/v1/",
            "http://0.0.0.0:8888/api/v1/",
            "http://127.0.0.1.attacker.example:8888/api/v1/",
            "http://localhost.attacker.example:8888/api/v1/",
            "http://user:pass@127.0.0.1:8888/api/v1/",
            "http://127.0.0.1:8888/api/v1/?token=secret",
            "http://127.0.0.1:8888/api/v1/#fragment",
            "ftp://127.0.0.1:8888/api/v1/",
            "//127.0.0.1:8888/api/v1/")) {
      var headers = AppUiSecurityHeaders.headers(true, unsafeRoot, unsafeRoot);

      assertEquals(STRICT_JAVASCRIPT_ENABLED_CSP, headers.get("content-security-policy"));
      assertEquals("SAMEORIGIN", headers.get("x-frame-options"));
    }
  }
}
