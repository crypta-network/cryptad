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
 * Used for detecting the dark theme on a Linux (GNOME/GTK) system. Tested on Ubuntu.
 *
 * @author Daniel Gyorffy
 */
class GnomeThemeDetector extends OsThemeDetector {

  private static final Logger logger = LoggerFactory.getLogger(GnomeThemeDetector.class);
  private static final String GSETTINGS_BINARY_NAME = "gsettings";
  private static final String GNOME_INTERFACE_SCHEMA = "org.gnome.desktop.interface";
  private static final List<String> MONITORING_ARGS = List.of("monitor", GNOME_INTERFACE_SCHEMA);
  private static final Pattern KEY_VALUE_SPLITTER = Pattern.compile("\\s+");
  private static final List<List<String>> GET_ARGS =
      List.of(
          List.of("get", GNOME_INTERFACE_SCHEMA, "gtk-theme"),
          List.of("get", GNOME_INTERFACE_SCHEMA, "color-scheme"));

  private final Set<Consumer<Boolean>> listeners = new ConcurrentHashSet<>();
  private final Pattern darkThemeNamePattern =
      Pattern.compile(".*dark.*", Pattern.CASE_INSENSITIVE);

  private final AtomicReference<DetectorThread> detectorThread = new AtomicReference<>();

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

  private boolean isDarkTheme(String gtkTheme) {
    return darkThemeNamePattern.matcher(gtkTheme).matches();
  }

  private Process startGsettingsCommand(List<String> commandArgs) throws IOException {
    return new ProcessBuilder(buildGsettingsCommand(commandArgs)).start();
  }

  private List<String> buildGsettingsCommand(List<String> commandArgs) throws IOException {
    List<String> command = new ArrayList<>();
    command.add(resolveGsettingsExecutable());
    command.addAll(commandArgs);
    return command;
  }

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

  /** Thread implementation for detecting the actually changed theme. */
  private static final class DetectorThread extends Thread {

    private final GnomeThemeDetector detector;
    private final Pattern outputPattern =
        Pattern.compile("(gtk-theme|color-scheme).*", Pattern.CASE_INSENSITIVE);
    private boolean lastValue;

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

    private boolean shouldIgnoreLine(String readLine) {
      return readLine == null || !outputPattern.matcher(readLine).matches();
    }

    private String extractThemeValue(String readLine) {
      return KEY_VALUE_SPLITTER.split(readLine, 2)[1];
    }

    private void notifyListeners(boolean currentDetection) {
      for (Consumer<Boolean> listener : detector.listeners) {
        try {
          listener.accept(currentDetection);
        } catch (RuntimeException e) {
          logger.error("Caught exception during listener notifying ", e);
        }
      }
    }

    private void destroyMonitoringProcess(Process monitoringProcess) {
      logger.debug("ThemeDetectorThread has been interrupted!");
      if (monitoringProcess.isAlive()) {
        monitoringProcess.destroy();
        logger.debug("Monitoring process has been destroyed!");
      }
    }
  }
}
