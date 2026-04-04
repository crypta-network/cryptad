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
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinReg;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Windows detector backed by registry reads and changes notifications through JNA.
 *
 * <p>This implementation reads the user's theme preference from the {@code AppsUseLightTheme}
 * registry value under the standard personalization key. A missing value or a non-zero value is
 * treated as light mode, while a zero value indicates dark mode. This keeps the detector aligned
 * with the Windows 10 and later personalization model used by desktop applications.
 *
 * <p>Listener registration starts a background thread that waits for registry-change events instead
 * of polling. The detector stores listeners in a concurrent set and coordinates the watcher thread
 * through an atomic reference, so registration and shutdown can happen safely from different
 * threads.
 *
 * @author Daniel Gyorffy
 * @author airsquared
 */
class WindowsThemeDetector extends OsThemeDetector {

  /** Logger used for registry watcher failures and listener callback exceptions. */
  private static final Logger logger = LoggerFactory.getLogger(WindowsThemeDetector.class);

  /** Registry key containing per-user theme personalization values. */
  private static final String REGISTRY_PATH =
      "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";

  /** Registry value that stores whether applications should use the light theme. */
  private static final String REGISTRY_VALUE = "AppsUseLightTheme";

  /** Registered listeners awaiting Windows theme transition notifications. */
  private final Set<Consumer<Boolean>> listeners = new ConcurrentHashSet<>();

  /** Holder for the currently active registry watcher thread, if one is running. */
  private final AtomicReference<DetectorThread> detectorThread = new AtomicReference<>();

  /** Creates a detector that defers registry access until first use. */
  WindowsThemeDetector() {}

  @Override
  public boolean isDark() {
    return Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE)
        && Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, REGISTRY_VALUE)
            == 0;
  }

  @SuppressWarnings("DuplicatedCode")
  @Override
  public synchronized void registerListener(@NotNull Consumer<Boolean> darkThemeListener) {
    Objects.requireNonNull(darkThemeListener);
    final boolean listenerAdded = listeners.add(darkThemeListener);
    final boolean singleListener = listenerAdded && listeners.size() == 1;
    final DetectorThread currentDetectorThread = detectorThread.get();
    final boolean threadInterrupted =
        currentDetectorThread != null && currentDetectorThread.isInterrupted();

    if (singleListener || threadInterrupted) {
      final DetectorThread newDetectorThread = new DetectorThread(this);
      detectorThread.set(newDetectorThread);
      newDetectorThread.start();
    }
  }

  @Override
  public synchronized void removeListener(@Nullable Consumer<Boolean> darkThemeListener) {
    listeners.remove(darkThemeListener);
    if (listeners.isEmpty()) {
      DetectorThread currentDetectorThread = detectorThread.getAndSet(null);
      if (currentDetectorThread != null) {
        currentDetectorThread.interrupt();
      }
    }
  }

  /** Background thread that waits for registry changes and publishes theme transitions. */
  private static final class DetectorThread extends Thread {

    /** Owning detector used for theme queries and listener dispatch. */
    private final WindowsThemeDetector themeDetector;

    /** Most recently published dark-mode value used to suppress duplicate callbacks. */
    private boolean lastValue;

    /**
     * Creates a watcher thread bound to the supplied detector instance.
     *
     * @param themeDetector detector owning the registry query and listener collection
     */
    @SuppressWarnings("ThreadPriorityCheck")
    DetectorThread(WindowsThemeDetector themeDetector) {
      this.themeDetector = themeDetector;
      this.lastValue = themeDetector.isDark();
      this.setName("Windows 10 Theme Detector Thread");
      this.setDaemon(true);
      this.setPriority(Thread.NORM_PRIORITY - 1);
    }

    @Override
    public void run() {
      WinReg.HKEYByReference hkey = new WinReg.HKEYByReference();
      int err =
          Advapi32.INSTANCE.RegOpenKeyEx(
              WinReg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, WinNT.KEY_READ, hkey);
      if (err != WinError.ERROR_SUCCESS) {
        throw new Win32Exception(err);
      }

      while (!this.isInterrupted()) {
        err =
            Advapi32.INSTANCE.RegNotifyChangeKeyValue(
                hkey.getValue(), false, WinNT.REG_NOTIFY_CHANGE_LAST_SET, null, false);
        if (err != WinError.ERROR_SUCCESS) {
          throw new Win32Exception(err);
        }

        boolean currentDetection = themeDetector.isDark();
        if (currentDetection != this.lastValue) {
          lastValue = currentDetection;
          logger.debug("Theme change detected: dark: {}", currentDetection);
          for (Consumer<Boolean> listener : themeDetector.listeners) {
            try {
              listener.accept(currentDetection);
            } catch (RuntimeException e) {
              logger.error("Caught exception during listener notifying ", e);
            }
          }
        }
      }
      Advapi32Util.registryCloseKey(hkey.getValue());
    }
  }
}
