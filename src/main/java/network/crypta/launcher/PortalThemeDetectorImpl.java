package network.crypta.launcher;

import com.jthemedetecor.OsThemeDetector;
import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.annotations.DBusMemberName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.exceptions.DBusExecutionException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.UInt32;
import org.freedesktop.dbus.types.Variant;

import static network.crypta.launcher.LauncherLog.logDebug;

/**
 * Detects launcher theme preference through the XDG desktop portal.
 *
 * <p>This implementation backs {@link com.jthemedetecor.PortalThemeDetector} while keeping the
 * DBus-facing logic inside the launcher package. It reads the {@code
 * org.freedesktop.appearance/color-scheme} setting from the XDG desktop portal, which gives
 * reliable results in Flatpak sandboxes where desktop-environment-specific probes may be
 * unavailable or misleading. Callers typically create one instance during launcher startup, query
 * {@link #isDark()} for the initial state, optionally subscribe with {@link
 * #registerListener(Consumer)}, and call {@link #close()} during shutdown.
 *
 * <p>State can change from synchronous portal reads and asynchronous signal callbacks. Listener
 * bookkeeping uses a {@link CopyOnWriteArraySet} together with atomics so registration, removal,
 * and callback delivery can proceed without external synchronization. When the portal does not
 * expose a usable preference, the detector temporarily delegates to an upstream {@link
 * OsThemeDetector} and stops listening to that fallback as soon as the portal reports an explicit
 * value.
 *
 * <ul>
 *   <li>Prefers explicit portal state over platform heuristics.
 *   <li>Falls back when portal reads are unavailable, unsupported, or invalid.
 *   <li>Subscribes lazily and tears down internal listeners when no callers remain.
 * </ul>
 *
 * @see com.jthemedetecor.PortalThemeDetector
 */
public class PortalThemeDetectorImpl implements Closeable {
  private static final String DESKTOP_PORTAL = "org.freedesktop.portal.Desktop";
  private static final String DESKTOP_PATH = buildDesktopPath();
  private static final String APPEARANCE = "org.freedesktop.appearance";
  private static final String COLOR_SCHEME = "color-scheme";
  private static final int PREFER_DARK = 1;

  private final PortalSettings settings;
  private final SignalRegistrar signalRegistrar;
  private final Closeable connectionCloser;
  private final OsThemeDetector fallbackDetector;
  private final Consumer<Boolean> fallbackThemeListener = this::handleFallbackThemeChanged;
  private final CopyOnWriteArraySet<Consumer<Boolean>> listeners = new CopyOnWriteArraySet<>();
  private final AtomicBoolean signalRegistered = new AtomicBoolean(false);
  private final AtomicBoolean fallbackRegistered = new AtomicBoolean(false);
  private final AtomicReference<AutoCloseable> signalRegistration = new AtomicReference<>();
  private final AtomicReference<PortalPreference> portalPreference =
      new AtomicReference<>(PortalPreference.UNSPECIFIED);

  /**
   * Creates a detector backed by a live XDG desktop portal connection.
   *
   * <p>The constructor opens the session bus, resolves the portal settings object, and captures an
   * initial portal preference so later calls can decide whether fallback theme detection is needed.
   * Use this constructor in normal launcher code when no test doubles or alternate connection
   * plumbing are required. If fallback detector creation fails after the portal connection opens,
   * the constructor closes the partially initialized portal client before rethrowing. Construction
   * does not register long-lived listeners; portal and fallback subscriptions remain lazy until
   * {@link #registerListener(Consumer)} is called.
   *
   * @throws IllegalStateException if the session bus or portal settings object cannot be opened
   */
  public PortalThemeDetectorImpl() {
    this(() -> DBusConnectionBuilder.forSessionBus().build(), OsThemeDetector::getDetector);
  }

  PortalThemeDetectorImpl(
      ConnectionFactory connectionFactory, FallbackDetectorFactory fallbackDetectorFactory) {
    this(openPortalClientWithFallback(connectionFactory, fallbackDetectorFactory));
  }

  private PortalThemeDetectorImpl(PortalClient portalClient, OsThemeDetector fallbackDetector) {
    this.settings = Objects.requireNonNull(portalClient.settings());
    this.signalRegistrar = Objects.requireNonNull(portalClient.signalRegistrar());
    this.connectionCloser = Objects.requireNonNull(portalClient.connectionCloser());
    this.fallbackDetector = Objects.requireNonNull(fallbackDetector);
    this.portalPreference.set(Objects.requireNonNull(portalClient.initialPreference()));
  }

  private PortalThemeDetectorImpl(DefaultDetectors defaultDetectors) {
    this(defaultDetectors.portalClient(), defaultDetectors.fallbackDetector());
  }

  PortalThemeDetectorImpl(
      PortalSettings settings,
      SignalRegistrar signalRegistrar,
      Closeable connectionCloser,
      OsThemeDetector fallbackDetector) {
    this(
        createValidatedPortalClient(settings, signalRegistrar, connectionCloser), fallbackDetector);
  }

  /**
   * Returns whether the active theme should be treated as dark.
   *
   * <p>Each call rereads the portal setting and updates the cached portal preference so the result
   * reflects the current desktop state even when no listener is registered. Explicit portal values
   * take precedence over the fallback detector. If the portal reports no preference or throws while
   * reading, the detector consults the fallback implementation instead. When both sources fail,
   * this method returns {@code false} as a conservative default.
   *
   * @return {@code true} when the portal or fallback detector currently prefers a dark theme;
   *     {@code false} when light or unknown state should be treated as non-dark
   */
  public boolean isDark() {
    try {
      PortalPreference preference = resolvePortalPreference(readColorScheme(settings));
      portalPreference.set(preference);
      return resolveDarkTheme(preference);
    } catch (RuntimeException _) {
      portalPreference.set(PortalPreference.UNSPECIFIED);
      return safeFallbackIsDark();
    }
  }

  /**
   * Registers a listener for future dark-theme changes.
   *
   * <p>The listener is stored in a set, so registering the same instance repeatedly does not create
   * duplicate notifications. The first external listener triggers lazy subscription to the portal
   * signal stream. When the cached portal preference is unspecified, this method also keeps the
   * fallback detector subscribed so upstream detector changes can still reach listeners until the
   * portal reports an explicit preference. Signal registration failures are logged and suppressed
   * rather than being propagated to the caller.
   *
   * @param darkThemeListener non-null callback that receives {@code true} for dark mode and {@code
   *     false} for light mode
   * @throws NullPointerException if {@code darkThemeListener} is {@code null}
   */
  public void registerListener(Consumer<Boolean> darkThemeListener) {
    listeners.add(Objects.requireNonNull(darkThemeListener));
    if (signalRegistered.compareAndSet(false, true)) {
      try {
        signalRegistration.set(signalRegistrar.register(this::handleSettingChanged));
      } catch (DBusException e) {
        signalRegistered.set(false);
        logDebug("Failed to register portal theme listener; live updates disabled", e);
      }
    }
    syncFallbackListenerRegistration();
  }

  /**
   * Removes a previously registered listener if present.
   *
   * <p>Passing a listener that is not currently registered has no effect, and passing {@code null}
   * is ignored. When the removal leaves the detector with no external listeners, the instance
   * closes its portal signal subscription and unregisters its fallback listener. That teardown
   * avoids holding DBus or upstream detector callbacks open while the detector is idle.
   *
   * @param darkThemeListener listener instance to remove, or {@code null} when no action is needed
   */
  public void removeListener(Consumer<Boolean> darkThemeListener) {
    if (darkThemeListener != null) {
      listeners.remove(darkThemeListener);
    }
    if (listeners.isEmpty()) {
      unregisterInternalListeners();
    }
  }

  /**
   * Releases internal listeners and closes the underlying portal connection.
   *
   * <p>This method first unregisters any portal signal handler and fallback detector listener, then
   * delegates to the connection closer captured during construction. Runtime failures that occur
   * while closing those resources are logged and suppressed so best-effort cleanup can continue,
   * but checked I/O failures from the connection closer are still propagated to the caller. After
   * this method returns, the detector should be treated as closed and not reused.
   *
   * @throws IOException if the underlying portal connection reports an I/O failure while closing
   */
  @Override
  public void close() throws IOException {
    unregisterInternalListeners();
    try {
      connectionCloser.close();
    } catch (RuntimeException e) {
      logDebug("Failed to close portal theme detector", e);
    }
  }

  private static DefaultDetectors openPortalClientWithFallback(
      ConnectionFactory connectionFactory, FallbackDetectorFactory fallbackDetectorFactory) {
    PortalClient portalClient = openPortalClient(connectionFactory);
    try {
      return new DefaultDetectors(
          portalClient, Objects.requireNonNull(fallbackDetectorFactory.create()));
    } catch (RuntimeException | Error e) {
      closeConnectionOnFailure(portalClient.connectionCloser(), e);
      throw e;
    }
  }

  static PortalClient openPortalClient(ConnectionFactory connectionFactory) {
    DBusConnection connection = null;
    try {
      connection = connectionFactory.open();
      PortalSettings settings =
          connection.getRemoteObject(DESKTOP_PORTAL, DESKTOP_PATH, PortalSettings.class);
      return createValidatedPortalClient(
          settings, createSignalRegistrar(connection, settings), connection);
    } catch (DBusException e) {
      closeConnectionOnFailure(connection, e);
      throw new IllegalStateException("Failed to open XDG portal theme detector", e);
    } catch (RuntimeException e) {
      closeConnectionOnFailure(connection, e);
      throw e;
    }
  }

  static SignalRegistrar createSignalRegistrar(DBusConnection connection, PortalSettings settings) {
    Objects.requireNonNull(connection);
    Objects.requireNonNull(settings);
    return signalHandler ->
        connection.addSigHandler(
            PortalSettings.SettingChanged.class, DESKTOP_PORTAL, settings, signalHandler::accept);
  }

  private static PortalClient createValidatedPortalClient(
      PortalSettings settings, SignalRegistrar signalRegistrar, Closeable connectionCloser) {
    Objects.requireNonNull(settings);
    Objects.requireNonNull(signalRegistrar);
    Objects.requireNonNull(connectionCloser);
    PortalPreference initialPreference;
    try {
      initialPreference = resolvePortalPreference(readColorScheme(settings));
    } catch (RuntimeException e) {
      logDebug(
          "Initial portal theme read failed; using fallback detector until portal recovers", e);
      initialPreference = PortalPreference.UNSPECIFIED;
    }
    return new PortalClient(settings, signalRegistrar, connectionCloser, initialPreference);
  }

  private static Variant<Object> readColorScheme(PortalSettings settings) {
    try {
      return settings.readOne(APPEARANCE, COLOR_SCHEME);
    } catch (DBusExecutionException _) {
      return settings.read(APPEARANCE, COLOR_SCHEME);
    }
  }

  private void handleSettingChanged(PortalSettings.SettingChanged signal) {
    if (!APPEARANCE.equals(signal.namespace) || !COLOR_SCHEME.equals(signal.key)) {
      return;
    }

    PortalPreference preference = resolvePortalPreference(signal.value);
    portalPreference.set(preference);
    syncFallbackListenerRegistration();
    notifyListeners(resolveDarkTheme(preference));
  }

  private void handleFallbackThemeChanged(Boolean darkTheme) {
    if (portalPreference.get() == PortalPreference.UNSPECIFIED) {
      notifyListeners(Boolean.TRUE.equals(darkTheme));
    }
  }

  private void notifyListeners(boolean dark) {
    for (Consumer<Boolean> listener : listeners) {
      try {
        listener.accept(dark);
      } catch (RuntimeException e) {
        logDebug("Portal theme listener threw an exception", e);
      }
    }
  }

  private boolean resolveDarkTheme(PortalPreference preference) {
    return switch (preference) {
      case DARK -> true;
      case LIGHT -> false;
      case UNSPECIFIED -> safeFallbackIsDark();
    };
  }

  private boolean safeFallbackIsDark() {
    try {
      return fallbackDetector.isDark();
    } catch (RuntimeException _) {
      return false;
    }
  }

  private static PortalPreference resolvePortalPreference(Variant<Object> variant) {
    Object value = unwrap(variant);
    return switch (value) {
      case UInt32 uint32 -> fromCode(uint32.intValue());
      case Number number -> fromCode(number.intValue());
      case String stringValue -> fromCode(parseIntOrDefault(stringValue));
      default -> PortalPreference.UNSPECIFIED;
    };
  }

  private static PortalPreference fromCode(int code) {
    return switch (code) {
      case PREFER_DARK -> PortalPreference.DARK;
      case 2 -> PortalPreference.LIGHT;
      default -> PortalPreference.UNSPECIFIED;
    };
  }

  private static Object unwrap(Object value) {
    Object current = value;
    while (current instanceof Variant<?> variant) {
      current = variant.getValue();
    }
    return current;
  }

  private static int parseIntOrDefault(String value) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException _) {
      return 0;
    }
  }

  private static String buildDesktopPath() {
    return "/" + String.join("/", "org", "freedesktop", "portal", "desktop");
  }

  private static void closeConnectionOnFailure(Closeable connectionCloser, Throwable failure) {
    if (connectionCloser == null) {
      return;
    }
    try {
      connectionCloser.close();
    } catch (IOException | RuntimeException closeFailure) {
      failure.addSuppressed(closeFailure);
    }
  }

  private void syncFallbackListenerRegistration() {
    boolean fallbackNeeded = portalPreference.get() == PortalPreference.UNSPECIFIED;
    if (fallbackNeeded) {
      if (fallbackRegistered.compareAndSet(false, true)) {
        fallbackDetector.registerListener(fallbackThemeListener);
      }
      return;
    }
    if (fallbackRegistered.compareAndSet(true, false)) {
      fallbackDetector.removeListener(fallbackThemeListener);
    }
  }

  private void unregisterInternalListeners() {
    if (fallbackRegistered.compareAndSet(true, false)) {
      fallbackDetector.removeListener(fallbackThemeListener);
    }
    signalRegistered.set(false);
    AutoCloseable registration = signalRegistration.getAndSet(null);
    if (registration != null) {
      try {
        registration.close();
      } catch (Exception e) {
        logDebug("Failed to unregister portal signal handler", e);
      }
    }
  }

  @FunctionalInterface
  interface SignalRegistrar {
    AutoCloseable register(Consumer<PortalSettings.SettingChanged> signalHandler)
        throws DBusException;
  }

  @FunctionalInterface
  interface ConnectionFactory {
    DBusConnection open() throws DBusException;
  }

  @FunctionalInterface
  interface FallbackDetectorFactory {
    OsThemeDetector create();
  }

  private record DefaultDetectors(PortalClient portalClient, OsThemeDetector fallbackDetector) {}

  private record PortalClient(
      PortalSettings settings,
      SignalRegistrar signalRegistrar,
      Closeable connectionCloser,
      PortalPreference initialPreference) {}

  private enum PortalPreference {
    DARK,
    LIGHT,
    UNSPECIFIED
  }
}

@DBusInterfaceName("org.freedesktop.portal.Settings")
interface PortalSettings extends DBusInterface {
  @DBusMemberName("Read")
  Variant<Object> read(String namespace, String key);

  @DBusMemberName("ReadOne")
  Variant<Object> readOne(String namespace, String key);

  @DBusInterfaceName("org.freedesktop.portal.Settings")
  class SettingChanged extends DBusSignal {
    final String namespace;
    final String key;
    final Variant<Object> value;

    public SettingChanged(String path, String namespace, String key, Variant<Object> value)
        throws DBusException {
      super(path, namespace, key, value);
      this.namespace = namespace;
      this.key = key;
      this.value = value;
    }
  }
}
