/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.jthemedetecor;

import com.jthemedetecor.util.OsInfo;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import oshi.annotation.concurrent.ThreadSafe;

/**
 * Abstract entry point for querying and monitoring the operating system theme.
 *
 * <p>The static factory methods in this type choose the most suitable detector for the current
 * platform and cache that detector for repeated use. Callers normally get the singleton through
 * {@link #getDetector()}, read the current state with {@link #isDark()}, and optionally subscribe
 * to changes with {@link #registerListener(Consumer)}. Platform-specific implementations
 * encapsulate the details of Windows registry watches, GNOME/KDE command execution, macOS
 * callbacks, or the no-op fallback used on unsupported systems.
 *
 * <p>The shared detector instance is created lazily and published safely for concurrent access.
 * Implementations are expected to remain thread-safe for theme reads and listener registration, but
 * their internal trade-offs vary by platform. Unsupported systems still receive a stable detector
 * object, so callers do not need separated null handling.
 *
 * @author Daniel Gyorffy
 */
public abstract class OsThemeDetector {

  private static final Logger logger = LoggerFactory.getLogger(OsThemeDetector.class);
  private static final AtomicReference<OsThemeDetector> DETECTOR = new AtomicReference<>();
  private static final Object DETECTOR_LOCK = new Object();

  OsThemeDetector() {}

  /**
   * Returns the lazily created detector instance for the current runtime environment.
   *
   * <p>The first call inspects the platform through {@link OsInfo}, constructs the best available
   * detector implementation, and caches that result for the lifetime of the process. Later calls
   * reuse the same instance, so listener registration and background monitoring remain coordinated.
   * If detector construction fails, the original exception is allowed to propagate so higher-level
   * launcher code can apply its own fallback policy.
   *
   * @return the shared detector chosen for the current operating system and desktop environment
   */
  @NotNull
  @ThreadSafe
  public static OsThemeDetector getDetector() {
    OsThemeDetector detector = DETECTOR.get();
    if (detector != null) {
      return detector;
    }

    synchronized (DETECTOR_LOCK) {
      detector = DETECTOR.get();
      if (detector == null) {
        detector = createDetector();
        DETECTOR.set(detector);
      }
      return detector;
    }
  }

  /**
   * Returns whether the operating system currently reports a dark theme.
   *
   * <p>Implementations may consult native APIs, desktop configuration tools, or cached state from a
   * monitoring thread. The method is read-only from the caller's perspective and should be safe to
   * invoke repeatedly, although the underlying cost depends on the platform-specific detector.
   *
   * @return {@code true} when the operating system prefers a dark theme; {@code false} otherwise
   */
  @ThreadSafe
  public abstract boolean isDark();

  /**
   * Registers a listener that receives future operating system theme changes.
   *
   * <p>Implementations may start native watchers or background polling when the first listener is
   * added. The supplied consumer is invoked with the newly detected dark-mode state after a change
   * is observed. Listener registration is idempotent only if the concrete implementation's backing
   * collection suppresses duplicates for the same consumer instance.
   *
   * @param darkThemeListener consumer notified with {@code true} for dark mode and {@code false}
   *     for light mode after a detected theme transition
   */
  @ThreadSafe
  public abstract void registerListener(@NotNull Consumer<Boolean> darkThemeListener);

  /**
   * Removes a previously registered listener.
   *
   * <p>Implementations may stop native watches or background threads once no listeners remain. A
   * removal request for an unknown listener is treated as a no-op so callers can perform cleanup
   * defensively during shutdown sequences.
   *
   * @param darkThemeListener listener instance to remove, or {@code null} when the implementation
   *     tolerates null-safe cleanup requests
   */
  @ThreadSafe
  public abstract void removeListener(@Nullable Consumer<Boolean> darkThemeListener);

  /**
   * Returns whether this runtime has a platform-specific detector implementation available.
   *
   * <p>This check is based on the same {@link OsInfo} predicates used by {@link #getDetector()},
   * but it avoids constructing the detector instance. Callers can use it for UI hints or logging
   * when they need to know whether dark-mode detection is expected to work natively on the current
   * host.
   *
   * @return {@code true} when a dedicated detector exists for the current platform; {@code false}
   *     when calls would fall back to the empty detector
   */
  @ThreadSafe
  public static boolean isSupported() {
    return OsInfo.isWindows10OrLater()
        || OsInfo.isMacOsMojaveOrLater()
        || OsInfo.isGnome()
        || OsInfo.isKde();
  }

  private static OsThemeDetector createDetector() {
    if (OsInfo.isWindows10OrLater()) {
      logDetection("Windows 10", WindowsThemeDetector.class);
      return new WindowsThemeDetector();
    } else if (OsInfo.isGnome()) {
      logDetection("Gnome", GnomeThemeDetector.class);
      return new GnomeThemeDetector();
    } else if (OsInfo.isKde()) {
      logDetection("KDE", KdeThemeDetector.class);
      return new KdeThemeDetector();
    } else if (OsInfo.isMacOsMojaveOrLater()) {
      logDetection("MacOS", MacOSThemeDetector.class);
      return new MacOSThemeDetector();
    } else {
      logger.debug(
          "Theme detection is not supported on the system: {} {}",
          OsInfo.getFamily(),
          OsInfo.getVersion());
      logger.debug("Creating empty detector...");
      return new EmptyDetector();
    }
  }

  private static void logDetection(String desktop, Class<? extends OsThemeDetector> detectorClass) {
    logger.debug("Supported Desktop detected: {}", desktop);
    logger.debug("Creating {}...", detectorClass.getName());
  }

  private static final class EmptyDetector extends OsThemeDetector {
    @Override
    public boolean isDark() {
      return false;
    }

    @Override
    public void registerListener(@NotNull Consumer<Boolean> darkThemeListener) {
      // The empty detector never emits theme changes.
    }

    @Override
    public void removeListener(@Nullable Consumer<Boolean> darkThemeListener) {
      // The empty detector never stores listeners.
    }
  }
}
