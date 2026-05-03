package network.crypta.platform.appui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class AppUiOriginTest {
  @Test
  void loopback_whenValidPortProvided_expectSerializedLocalOrigin() {
    AppUiOrigin origin = AppUiOrigin.loopback(" Demo-App ", 12345);

    assertEquals("demo-app", origin.appId());
    assertEquals("http://127.0.0.1:12345", origin.origin());
    assertEquals("http://127.0.0.1:12345/", origin.rootUrl());
  }

  @Test
  void constructor_whenRemoteOrWildcardHostProvided_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class, () -> new AppUiOrigin("demo-app", "http", "0.0.0.0", 1));
    assertThrows(
        IllegalArgumentException.class,
        () -> new AppUiOrigin("demo-app", "http", "example.test", 1));
  }

  @Test
  void constructor_whenSchemeOrPortUnsupported_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class, () -> new AppUiOrigin("demo-app", "https", "127.0.0.1", 1));
    assertThrows(
        IllegalArgumentException.class, () -> new AppUiOrigin("demo-app", "http", "127.0.0.1", 0));
    assertThrows(
        IllegalArgumentException.class,
        () -> new AppUiOrigin("demo-app", "http", "127.0.0.1", 65536));
  }

  @Test
  void parse_whenOriginHasPathQueryOrFragment_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AppUiOrigin.parse("demo-app", "http://127.0.0.1:12345/static"));
    assertThrows(
        IllegalArgumentException.class,
        () -> AppUiOrigin.parse("demo-app", "http://127.0.0.1:12345?x=1"));
    assertThrows(
        IllegalArgumentException.class,
        () -> AppUiOrigin.parse("demo-app", "http://127.0.0.1:12345#app"));
  }
}
