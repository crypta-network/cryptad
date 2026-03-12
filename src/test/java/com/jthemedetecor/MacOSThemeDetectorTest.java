package com.jthemedetecor;

import com.jthemedetecor.util.ConcurrentHashSet;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.objenesis.ObjenesisStd;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class MacOSThemeDetectorTest {
  private static final long CALLBACK_TIMEOUT_MILLIS = 500L;

  @ParameterizedTest
  @MethodSource("darkThemeNames")
  void isDarkTheme_whenThemeContainsDarkMarker_expectTrue(String themeName) throws Exception {
    MacOSThemeDetector detector = newDetector();

    boolean darkTheme = invokeIsDarkTheme(detector, themeName);

    assertTrue(darkTheme);
  }

  @ParameterizedTest
  @MethodSource("nonDarkThemeNames")
  void isDarkTheme_whenThemeMissingDarkMarker_expectFalse(String themeName) throws Exception {
    MacOSThemeDetector detector = newDetector();

    boolean darkTheme = invokeIsDarkTheme(detector, themeName);

    assertFalse(darkTheme);
  }

  @Test
  void registerListener_whenNotified_expectListenerReceivesDarkState() throws Exception {
    MacOSThemeDetector detector = newDetector();
    AtomicReference<Boolean> notifiedValue = new AtomicReference<>();

    detector.registerListener(notifiedValue::set);
    invokeNotifyListeners(detector, true);

    assertEquals(Boolean.TRUE, notifiedValue.get());
  }

  @Test
  void registerListener_whenNotifiedWithLightState_expectListenerReceivesLightState()
      throws Exception {
    MacOSThemeDetector detector = newDetector();
    AtomicReference<Boolean> notifiedValue = new AtomicReference<>();

    detector.registerListener(notifiedValue::set);
    invokeNotifyListeners(detector, false);

    assertEquals(Boolean.FALSE, notifiedValue.get());
  }

  @Test
  void registerListener_whenMultipleListenersPresent_expectAllReceiveSameState() throws Exception {
    MacOSThemeDetector detector = newDetector();
    CountDownLatch firstListenerNotified = new CountDownLatch(1);
    CountDownLatch secondListenerNotified = new CountDownLatch(1);

    detector.registerListener(
        dark -> {
          assertTrue(dark);
          firstListenerNotified.countDown();
        });
    detector.registerListener(
        dark -> {
          assertTrue(dark);
          secondListenerNotified.countDown();
        });

    invokeNotifyListeners(detector, true);

    assertAll(
        () ->
            assertTrue(firstListenerNotified.await(CALLBACK_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)),
        () ->
            assertTrue(
                secondListenerNotified.await(CALLBACK_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)));
  }

  @Test
  void removeListener_whenListenerRemoved_expectListenerDoesNotReceiveNotification()
      throws Exception {
    MacOSThemeDetector detector = newDetector();
    CountDownLatch listenerNotified = new CountDownLatch(1);
    Consumer<Boolean> listener = ignored -> listenerNotified.countDown();

    detector.registerListener(listener);
    detector.removeListener(listener);
    invokeNotifyListeners(detector, true);

    assertFalse(listenerNotified.await(CALLBACK_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
  }

  @Test
  void registerListener_whenListenerIsNull_expectNullPointerException() throws Exception {
    MacOSThemeDetector detector = newDetector();

    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> detector.registerListener(null));
  }

  @Test
  void removeListener_whenListenerIsNull_expectNullPointerException() throws Exception {
    MacOSThemeDetector detector = newDetector();

    assertThrows(NullPointerException.class, () -> detector.removeListener(null));
  }

  @Test
  void ensureCallbackMethodReference_whenRunnableIsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> invokeEnsureCallbackMethodReference(null));
  }

  @Test
  void ensureCallbackMethodReference_whenRunnablePresent_expectNoException() {
    assertDoesNotThrow(() -> invokeEnsureCallbackMethodReference(() -> {}));
  }

  @Test
  void detectorThread_whenCreated_expectDaemonAndNameConfigured() throws Exception {
    Thread detectorThread = newDetectorThread();

    assertAll(
        () -> assertEquals("MacOS Theme Detector Thread", detectorThread.getName()),
        () -> assertTrue(detectorThread.isDaemon()));
  }

  private static MacOSThemeDetector newDetector() throws Exception {
    MacOSThemeDetector detector = new ObjenesisStd().newInstance(MacOSThemeDetector.class);
    listenersField().set(detector, new ConcurrentHashSet<Consumer<Boolean>>());
    return detector;
  }

  private static boolean invokeIsDarkTheme(MacOSThemeDetector detector, String themeName)
      throws Exception {
    return (boolean) isDarkThemeMethod().invoke(detector, themeName);
  }

  private static void invokeNotifyListeners(MacOSThemeDetector detector, boolean dark)
      throws Exception {
    notifyListenersMethod().invoke(detector, dark);
  }

  private static Field listenersField() throws NoSuchFieldException {
    Field listenersField = MacOSThemeDetector.class.getDeclaredField("listeners");
    listenersField.setAccessible(true);
    return listenersField;
  }

  private static Method isDarkThemeMethod() throws NoSuchMethodException {
    Method isDarkThemeMethod =
        MacOSThemeDetector.class.getDeclaredMethod("isDarkTheme", String.class);
    isDarkThemeMethod.setAccessible(true);
    return isDarkThemeMethod;
  }

  private static Method notifyListenersMethod() throws NoSuchMethodException {
    Method notifyListenersMethod =
        MacOSThemeDetector.class.getDeclaredMethod("notifyListeners", boolean.class);
    notifyListenersMethod.setAccessible(true);
    return notifyListenersMethod;
  }

  private static Method callbackReferenceMethod() throws NoSuchMethodException {
    Method callbackReferenceMethod =
        MacOSThemeDetector.class.getDeclaredMethod("ensureCallbackMethodReference", Runnable.class);
    callbackReferenceMethod.setAccessible(true);
    return callbackReferenceMethod;
  }

  private static void invokeEnsureCallbackMethodReference(Runnable callbackMethodReference)
      throws Exception {
    try {
      callbackReferenceMethod().invoke(null, callbackMethodReference);
    } catch (InvocationTargetException e) {
      if (e.getCause() instanceof Exception exception) {
        throw exception;
      }
      throw e;
    }
  }

  private static Thread newDetectorThread() throws Exception {
    Constructor<?> constructor = detectorThreadClass().getDeclaredConstructor(Runnable.class);
    constructor.setAccessible(true);
    return (Thread) constructor.newInstance((Runnable) () -> {});
  }

  private static Class<?> detectorThreadClass() {
    for (Class<?> declaredClass : MacOSThemeDetector.class.getDeclaredClasses()) {
      if (Thread.class.isAssignableFrom(declaredClass)) {
        return declaredClass;
      }
    }

    throw new IllegalStateException("DetectorThread class not found");
  }

  private static Stream<String> darkThemeNames() {
    return Stream.of("Dark Aqua", "dark", "Solarized DARK");
  }

  private static Stream<String> nonDarkThemeNames() {
    return Stream.of(null, "", "Light", "Aqua");
  }
}
