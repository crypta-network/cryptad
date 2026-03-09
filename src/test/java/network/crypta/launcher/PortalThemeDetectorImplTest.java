package network.crypta.launcher;

import com.jthemedetecor.OsThemeDetector;
import java.io.Closeable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.exceptions.DBusExecutionException;
import org.freedesktop.dbus.types.UInt32;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("unchecked")
class PortalThemeDetectorImplTest {
  private static final String APPEARANCE = "org.freedesktop.appearance";
  private static final String COLOR_SCHEME = "color-scheme";
  private static final String DESKTOP_PATH = "/org/freedesktop/portal/desktop";
  private static final long ASYNC_TIMEOUT_SECONDS = 5L;

  @ParameterizedTest
  @MethodSource("explicitColorSchemeValues")
  void isDark_whenPortalReturnsExplicitValue_expectMappedResult(
      Variant<Object> value, boolean expected) {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(value).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    assertEquals(expected, detector.isDark());
    verifyNoInteractions(fallbackDetector);
  }

  @Test
  void isDark_whenPortalReturnsNoPreference_expectFallbackDetectorValue() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(0)).when(settings).readOne(APPEARANCE, COLOR_SCHEME);
    doReturn(true).when(fallbackDetector).isDark();

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    assertTrue(detector.isDark());
    verify(fallbackDetector).isDark();
  }

  @Test
  void isDark_whenPortalReturnsUnknownValue_expectFallbackDetectorValue() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>("bogus")).when(settings).readOne(APPEARANCE, COLOR_SCHEME);
    doReturn(true).when(fallbackDetector).isDark();

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    assertTrue(detector.isDark());
    verify(fallbackDetector).isDark();
  }

  @Test
  void isDark_whenReadOneFails_expectReadFallbackUsed() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doThrow(new DBusExecutionException("ReadOne unavailable"))
        .when(settings)
        .readOne(APPEARANCE, COLOR_SCHEME);
    doReturn(new Variant<Object>("1")).when(settings).read(APPEARANCE, COLOR_SCHEME);

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    assertTrue(detector.isDark());
    verify(settings, times(2)).read(APPEARANCE, COLOR_SCHEME);
    verifyNoInteractions(fallbackDetector);
  }

  @Test
  void isDark_whenPortalReadFailsAfterExplicitPreference_expectFallbackListenerActivated() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(new UInt32(1)))
        .doThrow(new DBusExecutionException("ReadOne unavailable"))
        .doReturn(new Variant<Object>(new UInt32(2)))
        .when(settings)
        .readOne(APPEARANCE, COLOR_SCHEME);
    doThrow(new IllegalStateException("portal settings unavailable"))
        .when(settings)
        .read(APPEARANCE, COLOR_SCHEME);
    doReturn(true).when(fallbackDetector).isDark();

    AtomicReference<Consumer<Boolean>> fallbackListener = new AtomicReference<>();
    Consumer<Boolean> activeListener = mock(Consumer.class);
    doAnswer(
            invocation -> {
              fallbackListener.set(invocation.getArgument(0));
              return null;
            })
        .when(fallbackDetector)
        .registerListener(any());

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    detector.registerListener(activeListener);

    assertTrue(detector.isDark());
    assertNotNull(fallbackListener.get());

    fallbackListener.get().accept(false);
    verify(activeListener).accept(false);

    assertFalse(detector.isDark());
    verify(fallbackDetector).removeListener(fallbackListener.get());
  }

  @Test
  void registerListener_whenPortalSignalArrives_expectOnlyActiveListenersNotified()
      throws Exception {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(new UInt32(0))).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    AtomicInteger registrationCount = new AtomicInteger();
    AtomicReference<Consumer<PortalSettings.SettingChanged>> signalHandler =
        new AtomicReference<>();
    @SuppressWarnings("resource")
    AutoCloseable signalRegistration = mock(AutoCloseable.class);
    AtomicReference<Consumer<Boolean>> fallbackListener = new AtomicReference<>();
    Consumer<Boolean> activeListener = mock(Consumer.class);
    Consumer<Boolean> removedListener = mock(Consumer.class);

    doAnswer(
            invocation -> {
              fallbackListener.set(invocation.getArgument(0));
              return null;
            })
        .when(fallbackDetector)
        .registerListener(any());

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            handler -> {
              registrationCount.incrementAndGet();
              signalHandler.set(handler);
              return signalRegistration;
            },
            mock(Closeable.class),
            fallbackDetector);

    detector.registerListener(activeListener);
    detector.registerListener(removedListener);
    detector.removeListener(removedListener);

    assertEquals(1, registrationCount.get());
    assertNotNull(signalHandler.get());
    assertNotNull(fallbackListener.get());

    signalHandler
        .get()
        .accept(
            new PortalSettings.SettingChanged(
                DESKTOP_PATH, APPEARANCE, COLOR_SCHEME, new Variant<>(new UInt32(1))));

    verify(activeListener).accept(true);
    verify(fallbackDetector).removeListener(fallbackListener.get());
    verifyNoInteractions(removedListener);
  }

  @Test
  void registerListener_whenPortalSignalRegistrationFails_expectKeepsExplicitPortalPreference() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(new UInt32(1))).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    Consumer<Boolean> activeListener = mock(Consumer.class);

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> {
              throw new DBusException("subscription failed");
            },
            mock(Closeable.class),
            fallbackDetector);

    detector.registerListener(activeListener);

    verify(fallbackDetector, never()).registerListener(any());
    verifyNoInteractions(activeListener);
  }

  @Test
  void registerListener_whenLastListenerRemovedDuringSignalRegistration_expectRegistrationClosed()
      throws Exception {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(new UInt32(1))).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    CountDownLatch registrationStarted = new CountDownLatch(1);
    CountDownLatch allowRegistrationFinish = new CountDownLatch(1);
    AutoCloseable signalRegistration = mock(AutoCloseable.class);
    Consumer<Boolean> listener = mock(Consumer.class);

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            _ -> {
              registrationStarted.countDown();
              awaitLatchUninterruptibly(allowRegistrationFinish);
              return signalRegistration;
            },
            mock(Closeable.class),
            fallbackDetector);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<?> registerFuture = executor.submit(() -> detector.registerListener(listener));
      awaitLatch(registrationStarted);
      Future<?> removeFuture = executor.submit(() -> detector.removeListener(listener));

      allowRegistrationFinish.countDown();
      awaitFuture(registerFuture);
      awaitFuture(removeFuture);
    }

    verify(signalRegistration).close();
    verifyNoInteractions(fallbackDetector);
  }

  @Test
  void
      registerListener_whenFallbackDetectorChangesAndPortalHasNoPreference_expectListenersNotified() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(0)).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    AtomicReference<Consumer<Boolean>> fallbackListener = new AtomicReference<>();
    Consumer<Boolean> activeListener = mock(Consumer.class);

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    doAnswer(
            invocation -> {
              fallbackListener.set(invocation.getArgument(0));
              return null;
            })
        .when(fallbackDetector)
        .registerListener(any());
    detector.registerListener(activeListener);

    assertNotNull(fallbackListener.get());
    verify(fallbackDetector).registerListener(any());
    fallbackListener.get().accept(true);

    verify(activeListener).accept(true);
  }

  @Test
  void registerListener_whenLastListenerRemovedDuringFallbackRegistration_expectFallbackRemoved()
      throws Exception {
    PortalSettings settings = mock(PortalSettings.class);
    doReturn(new Variant<Object>(0)).when(settings).readOne(APPEARANCE, COLOR_SCHEME);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    CountDownLatch registrationStarted = new CountDownLatch(1);
    CountDownLatch allowRegistrationFinish = new CountDownLatch(1);
    AtomicBoolean listenerRegistered = new AtomicBoolean(false);
    Consumer<Boolean> listener = mock(Consumer.class);

    doAnswer(
            _ -> {
              registrationStarted.countDown();
              awaitLatchUninterruptibly(allowRegistrationFinish);
              listenerRegistered.set(true);
              return null;
            })
        .when(fallbackDetector)
        .registerListener(any());
    doAnswer(
            _ -> {
              listenerRegistered.set(false);
              return null;
            })
        .when(fallbackDetector)
        .removeListener(any());

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<?> registerFuture = executor.submit(() -> detector.registerListener(listener));
      awaitLatch(registrationStarted);
      Future<?> removeFuture = executor.submit(() -> detector.removeListener(listener));

      allowRegistrationFinish.countDown();
      awaitFuture(registerFuture);
      awaitFuture(removeFuture);
    }

    assertFalse(listenerRegistered.get());
  }

  @Test
  void registerListener_whenFallbackDetectorChangesAndPortalHasExplicitPreference_expectIgnored() {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(new UInt32(1))).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    Consumer<Boolean> activeListener = mock(Consumer.class);

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings,
            ignored -> mock(AutoCloseable.class),
            mock(Closeable.class),
            fallbackDetector);

    detector.registerListener(activeListener);

    verify(fallbackDetector, never()).registerListener(any());
    verifyNoInteractions(activeListener);
  }

  @Test
  void settingChangedConstructor_whenReflected_expectPublic() throws Exception {
    Constructor<PortalSettings.SettingChanged> constructor =
        PortalSettings.SettingChanged.class.getConstructor(
            String.class, String.class, String.class, Variant.class);

    assertTrue(Modifier.isPublic(constructor.getModifiers()));
  }

  @Test
  void constructor_whenValidationFails_expectFallbackModeWithoutClosingConnection()
      throws Exception {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    Closeable connectionCloser = mock(Closeable.class);
    doThrow(new DBusExecutionException("ReadOne unavailable"))
        .when(settings)
        .readOne(APPEARANCE, COLOR_SCHEME);
    doThrow(new IllegalStateException("portal settings unavailable"))
        .when(settings)
        .read(APPEARANCE, COLOR_SCHEME);
    doReturn(true).when(fallbackDetector).isDark();

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings, ignored -> mock(AutoCloseable.class), connectionCloser, fallbackDetector);

    assertTrue(detector.isDark());
    verify(connectionCloser, never()).close();
    verify(fallbackDetector, never()).registerListener(any());
  }

  @Test
  void openPortalClient_whenSettingsLookupFails_expectConnectionClosed() throws Exception {
    DBusConnection connection = mock(DBusConnection.class);
    doThrow(new DBusException("portal settings unavailable"))
        .when(connection)
        .getRemoteObject("org.freedesktop.portal.Desktop", DESKTOP_PATH, PortalSettings.class);

    assertThrows(
        IllegalStateException.class,
        () -> PortalThemeDetectorImpl.openPortalClient(() -> connection));

    verify(connection).close();
  }

  @Test
  void constructor_whenFallbackDetectorCreationFails_expectConnectionClosed() throws Exception {
    DBusConnection connection = mock(DBusConnection.class);
    PortalSettings settings = mock(PortalSettings.class);
    doReturn(settings)
        .when(connection)
        .getRemoteObject("org.freedesktop.portal.Desktop", DESKTOP_PATH, PortalSettings.class);
    doReturn(new Variant<Object>(new UInt32(1))).when(settings).readOne(APPEARANCE, COLOR_SCHEME);

    //noinspection resource
    assertThrows(
        IllegalStateException.class,
        () ->
            new PortalThemeDetectorImpl(
                () -> connection,
                () -> {
                  throw new IllegalStateException("fallback detector unavailable");
                }));

    verify(connection).close();
  }

  @Test
  void close_whenConnectionCloserPresent_expectCloseDelegated() throws Exception {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(new UInt32(0))).when(settings).readOne(APPEARANCE, COLOR_SCHEME);
    Closeable connectionCloser = mock(Closeable.class);
    AutoCloseable signalRegistration = mock(AutoCloseable.class);
    AtomicReference<Consumer<Boolean>> fallbackListener = new AtomicReference<>();

    doAnswer(
            invocation -> {
              fallbackListener.set(invocation.getArgument(0));
              return null;
            })
        .when(fallbackDetector)
        .registerListener(any());

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings, ignored -> signalRegistration, connectionCloser, fallbackDetector);

    detector.registerListener(mock(Consumer.class));

    detector.close();

    verify(signalRegistration).close();
    verify(connectionCloser).close();
    verify(fallbackDetector).removeListener(fallbackListener.get());
  }

  @Test
  void createSignalRegistrar_whenRegistering_expectScopedHandlerOnPortalSettingsObject()
      throws Exception {
    DBusConnection connection = mock(DBusConnection.class);
    PortalSettings settings = mock(PortalSettings.class);
    AutoCloseable signalRegistration = mock(AutoCloseable.class);

    doReturn(signalRegistration)
        .when(connection)
        .addSigHandler(
            org.mockito.ArgumentMatchers.eq(PortalSettings.SettingChanged.class),
            org.mockito.ArgumentMatchers.same(settings),
            any());

    PortalThemeDetectorImpl.SignalRegistrar registrar =
        PortalThemeDetectorImpl.createSignalRegistrar(connection, settings);

    AutoCloseable returnedRegistration = registrar.register(mock(Consumer.class));

    assertEquals(signalRegistration, returnedRegistration);
    verify(connection)
        .addSigHandler(
            org.mockito.ArgumentMatchers.eq(PortalSettings.SettingChanged.class),
            org.mockito.ArgumentMatchers.same(settings),
            any());
  }

  @Test
  void removeListener_whenLastListenerRemoved_expectInternalListenersUnregistered()
      throws Exception {
    PortalSettings settings = mock(PortalSettings.class);
    OsThemeDetector fallbackDetector = mock(OsThemeDetector.class);
    doReturn(new Variant<Object>(0)).when(settings).readOne(APPEARANCE, COLOR_SCHEME);
    AutoCloseable signalRegistration = mock(AutoCloseable.class);
    AtomicReference<Consumer<Boolean>> fallbackListener = new AtomicReference<>();
    Consumer<Boolean> activeListener = mock(Consumer.class);

    doAnswer(
            invocation -> {
              fallbackListener.set(invocation.getArgument(0));
              return null;
            })
        .when(fallbackDetector)
        .registerListener(any());

    PortalThemeDetectorImpl detector =
        new PortalThemeDetectorImpl(
            settings, ignored -> signalRegistration, mock(Closeable.class), fallbackDetector);

    detector.registerListener(activeListener);
    detector.removeListener(activeListener);

    verify(signalRegistration).close();
    verify(fallbackDetector).removeListener(fallbackListener.get());
  }

  private static Stream<Arguments> explicitColorSchemeValues() {
    return Stream.of(
        Arguments.of(new Variant<Object>(new UInt32(1)), true),
        Arguments.of(new Variant<Object>("1"), true),
        Arguments.of(new Variant<Object>(new Variant<Object>("1")), true),
        Arguments.of(new Variant<Object>(new UInt32(2)), false));
  }

  private static void awaitFuture(Future<?> future) throws Exception {
    future.get(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS);
  }

  private static void awaitLatch(CountDownLatch latch) throws InterruptedException {
    assertTrue(latch.await(ASYNC_TIMEOUT_SECONDS, TimeUnit.SECONDS));
  }

  private static void awaitLatchUninterruptibly(CountDownLatch latch) {
    try {
      awaitLatch(latch);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError(e);
    }
  }
}
