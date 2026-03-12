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

import com.jthemedetecor.util.ConcurrentHashSet;
import com.sun.jna.Callback;
import de.jangassen.jfa.foundation.Foundation;
import de.jangassen.jfa.foundation.ID;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * macOS detector backed by Foundation notifications and user-default lookups.
 *
 * <p>This implementation queries {@code NSUserDefaults} for the {@code AppleInterfaceStyle} key and
 * treats values containing {@code dark} as a dark-mode preference. Unlike the Linux
 * implementations, it does not launch external processes. Instead, it registers an Objective-C
 * observer through JFA and JNA, so macOS posts theme changes back into Java code.
 *
 * <p>Registered listeners are stored in a concurrent set, while callback dispatch runs through a
 * dedicated single-thread executor. That keeps notification delivery off the native callback thread
 * and preserves a stable ordering model for listener invocation without changing the public
 * detector contract.
 *
 * @author Daniel Gyorffy
 */
class MacOSThemeDetector extends OsThemeDetector {

  /** Native callback contract invoked when macOS announces an interface theme change. */
  @FunctionalInterface
  private interface ThemeChangedCallback extends Callback {
    /** Handles a native theme-change notification from the Objective-C runtime. */
    void callback();
  }

  /** Logger used for observer registration and native query failures. */
  private static final Logger logger = LoggerFactory.getLogger(MacOSThemeDetector.class);

  /** Registered Java listeners that should receive dark-mode transition events. */
  private final Set<Consumer<Boolean>> listeners = new ConcurrentHashSet<>();

  /**
   * Executor that serializes listener callbacks away from the native Foundation callback thread.
   */
  private final ExecutorService callbackExecutor =
      Executors.newSingleThreadExecutor(DetectorThread::new);

  /** Native callback instance bridged into Java listener notification code. */
  private final ThemeChangedCallback themeChangedCallback =
      () -> callbackExecutor.execute(() -> notifyListeners(isDark()));

  /** Creates the detector and registers the native observer needed for future callbacks. */
  MacOSThemeDetector() {
    ensureCallbackMethodReference(themeChangedCallback::callback);
    initObserver();
  }

  /** Registers an Objective-C observer for {@code AppleInterfaceThemeChangedNotification}. */
  private void initObserver() {
    final Foundation.NSAutoreleasePool pool = new Foundation.NSAutoreleasePool();
    try {
      final ID delegateClass =
          Foundation.allocateObjcClassPair(
              Foundation.getObjcClass("NSObject"), "NSColorChangesObserver");
      if (!ID.NIL.equals(delegateClass)) {
        if (!Foundation.addMethod(
            delegateClass,
            Foundation.createSelector("handleAppleThemeChanged:"),
            themeChangedCallback,
            "v@")) {
          logger.error("Observer method cannot be added");
        }
        Foundation.registerObjcClassPair(delegateClass);
      }

      final ID delegate = Foundation.invoke("NSColorChangesObserver", "new");
      Foundation.invoke(
          Foundation.invoke("NSDistributedNotificationCenter", "defaultCenter"),
          "addObserver:selector:name:object:",
          delegate,
          Foundation.createSelector("handleAppleThemeChanged:"),
          Foundation.nsString("AppleInterfaceThemeChangedNotification"),
          ID.NIL);
    } finally {
      pool.drain();
    }
  }

  @SuppressWarnings("DuplicatedCode")
  @Override
  public boolean isDark() {
    final Foundation.NSAutoreleasePool pool = new Foundation.NSAutoreleasePool();
    try {
      final ID userDefaults = Foundation.invoke("NSUserDefaults", "standardUserDefaults");
      final String appleInterfaceStyle =
          Foundation.toStringViaUTF8(
              Foundation.invoke(
                  userDefaults, "objectForKey:", Foundation.nsString("AppleInterfaceStyle")));
      return isDarkTheme(appleInterfaceStyle);
    } catch (RuntimeException e) {
      logger.error("Couldn't execute theme name query with the Os", e);
    } finally {
      pool.drain();
    }
    return false;
  }

  /**
   * Returns whether the supplied macOS theme value indicates dark mode.
   *
   * @param themeName raw theme value returned from {@code NSUserDefaults}
   * @return {@code true} when the value contains a case-insensitive {@code dark} marker
   */
  private boolean isDarkTheme(String themeName) {
    return themeName != null && themeName.toLowerCase(Locale.ROOT).contains("dark");
  }

  @Override
  public void registerListener(@NotNull Consumer<Boolean> darkThemeListener) {
    listeners.add(darkThemeListener);
  }

  @Override
  public void removeListener(@Nullable Consumer<Boolean> darkThemeListener) {
    listeners.remove(darkThemeListener);
  }

  /**
   * Delivers the detected dark-mode state to each registered listener.
   *
   * @param isDark state to publish to current listeners
   */
  private void notifyListeners(boolean isDark) {
    listeners.forEach(listener -> listener.accept(isDark));
  }

  /**
   * Forces a direct Java-side reference to the callback method so static analysis can see it.
   *
   * @param callbackMethodReference method reference bound to the callback contract
   */
  private static void ensureCallbackMethodReference(Runnable callbackMethodReference) {
    Objects.requireNonNull(callbackMethodReference);
  }

  /** Dedicated thread type used by the single-thread callback executor. */
  private static final class DetectorThread extends Thread {
    /**
     * Creates a daemon thread for serialized macOS theme callback delivery.
     *
     * @param runnable callback work submitted by the executor
     */
    DetectorThread(@NotNull Runnable runnable) {
      super(runnable);
      setName("MacOS Theme Detector Thread");
      setDaemon(true);
    }
  }
}
