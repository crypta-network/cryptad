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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GNOME and GTK-specific detector backed by the {@code gsettings} command-line tools.
 *
 * <p>This implementation is selected by {@link OsThemeDetector} when the runtime reports a GNOME
 * desktop environment. One-off theme reads execute {@code gsettings get} against the GNOME
 * interface schema and treat either a dark GTK theme name or a dark color-scheme preference as a
 * positive dark-mode signal. That approach keeps the detector compatible with older GTK setups as
 * well as newer color-scheme-based desktops.
 *
 * <p>Listener registration starts a lightweight background thread that tails {@code gsettings
 * monitor} output and notifies registered consumers only when the effective dark-mode state
 * changes. Listener storage is concurrent, while thread lifecycle is coordinated through an atomic
 * reference so callers can add and remove listeners safely from different threads.
 *
 * @author Daniel Gyorffy
 */
class GnomeThemeDetector extends OsThemeDetector {

  /** Logger used for theme-detection and monitor-process failures. */
  private static final Logger logger = LoggerFactory.getLogger(GnomeThemeDetector.class);

  /** Base executable name used for GNOME settings queries and monitoring. */
  private static final String GSETTINGS_BINARY_NAME = "gsettings";

  /** GNOME schema containing the appearance keys this detector reads and monitors. */
  private static final String GNOME_INTERFACE_SCHEMA = "org.gnome.desktop.interface";

  /** Arguments passed to {@code gsettings} when starting a long-lived monitor process. */
  private static final List<String> MONITORING_ARGS = List.of("monitor", GNOME_INTERFACE_SCHEMA);

  /** Splits monitored key/value lines into the changed key and its reported value. */
  private static final Pattern KEY_VALUE_SPLITTER = Pattern.compile("\\s+");

  /** Query argument lists evaluated to determine whether GNOME currently uses a dark theme. */
  private static final List<List<String>> GET_ARGS =
      List.of(
          List.of("get", GNOME_INTERFACE_SCHEMA, "gtk-theme"),
          List.of("get", GNOME_INTERFACE_SCHEMA, "color-scheme"));

  /** Registered listeners awaiting dark-mode transition callbacks. */
  private final Set<Consumer<Boolean>> listeners = new ConcurrentHashSet<>();

  /** Pattern matching dark theme markers in GNOME-reported theme values. */
  private final Pattern darkThemeNamePattern =
      Pattern.compile(".*dark.*", Pattern.CASE_INSENSITIVE);

  /** Holder for the currently active monitor thread, if any listeners are registered. */
  private final AtomicReference<DetectorThread> detectorThread = new AtomicReference<>();

  /**
   * Creates a detector that defers all external process work until it is queried or listened to.
   */
  GnomeThemeDetector() {}

  @Override
  public boolean isDark() {
    try {
      for (List<String> commandArgs : GET_ARGS) {
        Process process = startGsettingsCommand(commandArgs);
        try (BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(process.getInputStream(), Charset.defaultCharset()))) {
          String readLine = reader.readLine();
          if (readLine != null && isDarkTheme(readLine)) {
            return true;
          }
        }
      }
    } catch (IOException e) {
      logger.error("Couldn't detect Linux OS theme", e);
    }
    return false;
  }

  /**
   * Returns whether a GNOME-reported theme value indicates dark mode.
   *
   * @param gtkTheme raw theme value returned by {@code gsettings}
   * @return {@code true} when the value contains a case-insensitive dark marker
   */
  private boolean isDarkTheme(String gtkTheme) {
    return darkThemeNamePattern.matcher(gtkTheme).matches();
  }

  /**
   * Starts a {@code gsettings} child process for the supplied argument list.
   *
   * @param commandArgs arguments appended after the resolved {@code gsettings} executable
   * @return the started child process for reading GNOME settings output
   * @throws IOException if the executable cannot be resolved or the process cannot be started
   */
  private Process startGsettingsCommand(List<String> commandArgs) throws IOException {
    return new ProcessBuilder(buildGsettingsCommand(commandArgs)).start();
  }

  /**
   * Builds the full command line used for a {@code gsettings} invocation.
   *
   * @param commandArgs arguments appended after the resolved executable path
   * @return a new command list suitable for {@link ProcessBuilder}
   * @throws IOException if the {@code gsettings} executable cannot be resolved
   */
  private List<String> buildGsettingsCommand(List<String> commandArgs) throws IOException {
    List<String> command = new ArrayList<>();
    command.add(resolveGsettingsExecutable());
    command.addAll(commandArgs);
    return command;
  }

  /**
   * Resolves the executable used to run GNOME settings commands.
   *
   * @return the executable path or bare command name used for {@code gsettings}
   * @throws IOException if a non-blank process search path is available but no executable is found
   */
  private String resolveGsettingsExecutable() throws IOException {
    return ExecutableResolver.resolveFromPath(GSETTINGS_BINARY_NAME);
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

  /**
   * Background monitor that translates {@code gsettings monitor} output into listener callbacks.
   */
  private static final class DetectorThread extends Thread {

    /** Owning detector used for theme parsing and listener dispatch. */
    private final GnomeThemeDetector detector;

    /** Pattern matching the monitored GNOME keys that affect effective dark-mode state. */
    private final Pattern outputPattern =
        Pattern.compile("(gtk-theme|color-scheme).*", Pattern.CASE_INSENSITIVE);

    /** Most recently published dark-mode state used to suppress duplicate callbacks. */
    private boolean lastValue;

    /**
     * Creates a monitor thread bound to the supplied detector instance.
     *
     * @param detector detector owning the listener set and theme-parsing rules
     */
    DetectorThread(@NotNull GnomeThemeDetector detector) {
      this.detector = detector;
      this.lastValue = detector.isDark();
      this.setName("GTK Theme Detector Thread");
      this.setDaemon(true);
      this.setPriority(Thread.NORM_PRIORITY - 1);
    }

    @Override
    public void run() {
      try {
        monitorChanges(detector.startGsettingsCommand(MONITORING_ARGS));
      } catch (IOException e) {
        logger.error("Couldn't start monitoring process ", e);
      } catch (ArrayIndexOutOfBoundsException e) {
        logger.error("Couldn't parse command line output", e);
      }
    }

    /**
     * Reads monitor output until the thread is interrupted or the process ends.
     *
     * @param monitoringProcess running {@code gsettings monitor} process supplying change lines
     * @throws IOException if reading monitor output fails
     */
    private void monitorChanges(Process monitoringProcess) throws IOException {
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(
                  monitoringProcess.getInputStream(), Charset.defaultCharset()))) {
        while (!this.isInterrupted()) {
          processMonitoringLine(reader.readLine());
        }
        destroyMonitoringProcess(monitoringProcess);
      }
    }

    /**
     * Parses a monitor line and publishes a callback only when the effective theme state changes.
     *
     * @param readLine single line emitted by {@code gsettings monitor}
     */
    private void processMonitoringLine(String readLine) {
      if (shouldIgnoreLine(readLine)) {
        return;
      }
      boolean currentDetection = detector.isDarkTheme(extractThemeValue(readLine));
      logger.debug("Theme changed detection, dark: {}", currentDetection);
      if (currentDetection != lastValue) {
        lastValue = currentDetection;
        notifyListeners(currentDetection);
      }
    }

    /**
     * Returns whether a monitor line can be ignored safely.
     *
     * @param readLine single line emitted by the monitoring process, possibly {@code null}
     * @return {@code true} when the line is absent or unrelated to the tracked appearance keys
     */
    private boolean shouldIgnoreLine(String readLine) {
      return readLine == null || !outputPattern.matcher(readLine).matches();
    }

    /**
     * Extracts the theme value portion from a GNOME monitor output line.
     *
     * @param readLine single line emitted by {@code gsettings monitor}
     * @return the substring representing the changed key's value
     */
    private String extractThemeValue(String readLine) {
      return KEY_VALUE_SPLITTER.split(readLine, 2)[1];
    }

    /**
     * Delivers a newly detected dark-mode state to every registered listener.
     *
     * @param currentDetection the dark-mode state that should be published to listeners
     */
    private void notifyListeners(boolean currentDetection) {
      for (Consumer<Boolean> listener : detector.listeners) {
        try {
          listener.accept(currentDetection);
        } catch (RuntimeException e) {
          logger.error("Caught exception during listener notifying ", e);
        }
      }
    }

    /**
     * Stops the monitor process when the thread is shutting down.
     *
     * @param monitoringProcess running process created for {@code gsettings monitor}
     */
    private void destroyMonitoringProcess(Process monitoringProcess) {
      logger.debug("ThemeDetectorThread has been interrupted!");
      if (monitoringProcess.isAlive()) {
        monitoringProcess.destroy();
        logger.debug("Monitoring process has been destroyed!");
      }
    }
  }
}
