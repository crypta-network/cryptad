package com.jthemedetecor;

import java.io.IOException;
import java.util.function.Consumer;
import network.crypta.launcher.PortalThemeDetectorImpl;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PortalThemeDetectorTest {
  @Test
  void delegateMethods_whenInvoked_expectForwardedToImpl() throws IOException {
    PortalThemeDetectorImpl impl = mock(PortalThemeDetectorImpl.class);
    Consumer<Boolean> listener = ignored -> {};
    when(impl.isDark()).thenReturn(true);

    PortalThemeDetector detector = new PortalThemeDetector(impl);

    assertTrue(detector.isDark());
    detector.registerListener(listener);
    detector.removeListener(listener);
    detector.close();

    verify(impl).isDark();
    verify(impl).registerListener(listener);
    verify(impl).removeListener(listener);
    verify(impl).close();
  }
}
