package com.jthemedetecor;

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class WindowsThemeDetectorTest {
  private static final String REGISTRY_PATH =
      "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
  private static final String REGISTRY_VALUE = "AppsUseLightTheme";

  @Test
  void isDark_whenRegistryValueDoesNotExist_expectFalse() {
    WindowsThemeDetector detector = new WindowsThemeDetector();

    try (MockedStatic<Advapi32Util> registry = mockStatic(Advapi32Util.class)) {
      registry
          .when(
              () ->
                  Advapi32Util.registryValueExists(
                      WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE))
          .thenReturn(false);

      boolean dark = detector.isDark();

      assertFalse(dark);
      registry.verify(
          () ->
              Advapi32Util.registryGetIntValue(
                  WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE),
          never());
    }
  }

  @Test
  void isDark_whenRegistryValueIsZero_expectTrue() {
    WindowsThemeDetector detector = new WindowsThemeDetector();

    try (MockedStatic<Advapi32Util> registry = mockStatic(Advapi32Util.class)) {
      registry
          .when(
              () ->
                  Advapi32Util.registryValueExists(
                      WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE))
          .thenReturn(true);
      registry
          .when(
              () ->
                  Advapi32Util.registryGetIntValue(
                      WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE))
          .thenReturn(0);

      boolean dark = detector.isDark();

      assertTrue(dark);
    }
  }

  @Test
  void isDark_whenRegistryValueIsNonZero_expectFalse() {
    WindowsThemeDetector detector = new WindowsThemeDetector();

    try (MockedStatic<Advapi32Util> registry = mockStatic(Advapi32Util.class)) {
      registry
          .when(
              () ->
                  Advapi32Util.registryValueExists(
                      WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE))
          .thenReturn(true);
      registry
          .when(
              () ->
                  Advapi32Util.registryGetIntValue(
                      WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE))
          .thenReturn(1);

      boolean dark = detector.isDark();

      assertFalse(dark);
    }
  }

  @Test
  void registerListener_whenFirstListenerAdded_expectWatcherThreadStarted() {
    TrackingWindowsThemeDetector detector = new TrackingWindowsThemeDetector(false);
    Consumer<Boolean> listener = ignored -> {};

    try (MockedConstruction<Thread> detectorThreads = mockDetectorThreadConstruction()) {
      detector.registerListener(listener);

      Thread detectorThread = detectorThreads.constructed().getFirst();

      assertAll(
          () -> assertEquals(1, detectorThreads.constructed().size()),
          () -> verify(detectorThread).start(),
          () -> assertSame(detectorThread, detectorThreadReference(detector).get()));
    }
  }

  @Test
  void registerListener_whenSameListenerAddedAgain_expectWatcherThreadNotRestarted() {
    TrackingWindowsThemeDetector detector = new TrackingWindowsThemeDetector(false);
    Consumer<Boolean> listener = ignored -> {};

    try (MockedConstruction<Thread> detectorThreads = mockDetectorThreadConstruction()) {
      detector.registerListener(listener);
      detector.registerListener(listener);

      Thread detectorThread = detectorThreads.constructed().getFirst();

      assertAll(
          () -> assertEquals(1, detectorThreads.constructed().size()),
          () -> verify(detectorThread).start());
    }
  }

  @Test
  void registerListener_whenCurrentWatcherInterrupted_expectReplacementThreadStarted() {
    TrackingWindowsThemeDetector detector = new TrackingWindowsThemeDetector(false);
    Consumer<Boolean> firstListener = ignored -> {};
    Consumer<Boolean> secondListener = ignored -> {};

    try (MockedConstruction<Thread> detectorThreads = mockDetectorThreadConstruction()) {
      detector.registerListener(firstListener);
      when(detectorThreads.constructed().getFirst().isInterrupted()).thenReturn(true);

      detector.registerListener(secondListener);

      assertAll(
          () -> assertEquals(2, detectorThreads.constructed().size()),
          () -> verify(detectorThreads.constructed().getFirst()).start(),
          () -> verify(detectorThreads.constructed().get(1)).start(),
          () ->
              assertSame(
                  detectorThreads.constructed().get(1), detectorThreadReference(detector).get()));
    }
  }

  @Test
  void removeListener_whenOtherListenersRemain_expectWatcherThreadKept() {
    TrackingWindowsThemeDetector detector = new TrackingWindowsThemeDetector(false);
    Consumer<Boolean> firstListener = ignored -> {};
    Consumer<Boolean> secondListener = ignored -> {};

    try (MockedConstruction<Thread> detectorThreads = mockDetectorThreadConstruction()) {
      detector.registerListener(firstListener);
      detector.registerListener(secondListener);
      Thread detectorThread = detectorThreads.constructed().getFirst();

      detector.removeListener(firstListener);

      assertAll(
          () -> verify(detectorThread, never()).interrupt(),
          () -> assertSame(detectorThread, detectorThreadReference(detector).get()));
    }
  }

  @Test
  void removeListener_whenLastListenerRemoved_expectWatcherThreadInterruptedAndCleared() {
    TrackingWindowsThemeDetector detector = new TrackingWindowsThemeDetector(false);
    Consumer<Boolean> listener = ignored -> {};

    try (MockedConstruction<Thread> detectorThreads = mockDetectorThreadConstruction()) {
      detector.registerListener(listener);
      Thread detectorThread = detectorThreads.constructed().getFirst();

      detector.removeListener(listener);

      assertAll(
          () -> verify(detectorThread).interrupt(),
          () -> assertNull(detectorThreadReference(detector).get()));
    }
  }

  @Test
  void registerListener_whenListenerIsNull_expectNullPointerException() {
    WindowsThemeDetector detector = new WindowsThemeDetector();

    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> detector.registerListener(null));
  }

  @Test
  void removeListener_whenListenerIsNull_expectNullPointerException() {
    WindowsThemeDetector detector = new WindowsThemeDetector();

    assertThrows(NullPointerException.class, () -> detector.removeListener(null));
  }

  @Test
  void detectorThread_whenCreated_expectPropertiesAndInitialValueMatchDetectorState()
      throws Exception {
    Object darkThread = newDetectorThread(new TrackingWindowsThemeDetector(true));
    Object lightThread = newDetectorThread(new TrackingWindowsThemeDetector(false));

    assertAll(
        () -> assertEquals("Windows 10 Theme Detector Thread", ((Thread) darkThread).getName()),
        () -> assertTrue(((Thread) darkThread).isDaemon()),
        () -> assertEquals(Thread.NORM_PRIORITY - 1, ((Thread) darkThread).getPriority()),
        () -> assertTrue(lastValue(darkThread)),
        () -> assertFalse(lastValue(lightThread)));
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static MockedConstruction<Thread> mockDetectorThreadConstruction() {
    Class<Thread> detectorThreadClass = (Class) detectorThreadClass();

    return mockConstruction(
        detectorThreadClass, (mock, _) -> when(mock.isInterrupted()).thenReturn(false));
  }

  private static AtomicReference<?> detectorThreadReference(WindowsThemeDetector detector)
      throws Exception {
    Field detectorThread = WindowsThemeDetector.class.getDeclaredField("detectorThread");
    detectorThread.setAccessible(true);
    return (AtomicReference<?>) detectorThread.get(detector);
  }

  private static Object newDetectorThread(WindowsThemeDetector detector) throws Exception {
    Constructor<?> constructor =
        detectorThreadClass().getDeclaredConstructor(WindowsThemeDetector.class);
    constructor.setAccessible(true);
    return constructor.newInstance(detector);
  }

  private static boolean lastValue(Object detectorThread) throws Exception {
    Field lastValue = detectorThreadClass().getDeclaredField("lastValue");
    lastValue.setAccessible(true);
    return lastValue.getBoolean(detectorThread);
  }

  private static Class<?> detectorThreadClass() {
    for (Class<?> declaredClass : WindowsThemeDetector.class.getDeclaredClasses()) {
      if (Thread.class.isAssignableFrom(declaredClass)) {
        return declaredClass;
      }
    }

    throw new IllegalStateException("DetectorThread class not found");
  }

  private static final class TrackingWindowsThemeDetector extends WindowsThemeDetector {
    private final boolean dark;

    TrackingWindowsThemeDetector(boolean dark) {
      this.dark = dark;
    }

    @Override
    public boolean isDark() {
      return dark;
    }
  }
}
