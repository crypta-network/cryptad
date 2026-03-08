package network.crypta.launcher;

import com.jthemedetecor.OsThemeDetector;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FlatpakAwareOsThemeDetectorTest {
  @Test
  void getDetector_whenLinuxAndPortalAvailable_expectPortalDetector() {
    AppEnv appEnv = mock(AppEnv.class);
    when(appEnv.isLinux()).thenReturn(true);
    OsThemeDetector portalDetector = mock(OsThemeDetector.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);

    OsThemeDetector detector =
        FlatpakAwareOsThemeDetector.getDetector(
            appEnv, () -> fallbackDetector, () -> portalDetector);

    assertSame(portalDetector, detector);
  }

  @Test
  void getDetector_whenLinuxAndPortalUnavailable_expectFallbackDetector() {
    AppEnv appEnv = mock(AppEnv.class);
    when(appEnv.isLinux()).thenReturn(true);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);

    OsThemeDetector detector =
        FlatpakAwareOsThemeDetector.getDetector(
            appEnv,
            () -> fallbackDetector,
            () -> {
              throw new IllegalStateException("portal unavailable");
            });

    assertSame(fallbackDetector, detector);
  }

  @Test
  void getDetector_whenNotLinux_expectFallbackWithoutPortalAttempt() {
    AppEnv appEnv = mock(AppEnv.class);
    when(appEnv.isLinux()).thenReturn(false);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    AtomicBoolean portalCalled = new AtomicBoolean(false);

    OsThemeDetector detector =
        FlatpakAwareOsThemeDetector.getDetector(
            appEnv,
            () -> fallbackDetector,
            () -> {
              portalCalled.set(true);
              return mock(OsThemeDetector.class);
            });

    assertSame(fallbackDetector, detector);
    assertFalse(portalCalled.get());
  }
}
