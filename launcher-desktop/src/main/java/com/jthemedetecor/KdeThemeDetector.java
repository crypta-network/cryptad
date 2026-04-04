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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KDE and Plasma-specific detector backed by the {@code kreadconfig} helper tools.
 *
 * <p>This detector is chosen when the current Linux desktop environment identifies itself as KDE.
 * It reads the active color-scheme name from {@code kdeglobals} and treats theme names containing a
 * case-insensitive {@code dark} marker as dark-mode selections. The resolver prefers newer helper
 * binaries first, but it still supports fallback helper names and bare command execution, so
 * non-standard Linux installations continue to work.
 *
 * <p>When listeners are registered, the detector starts a background thread that periodically
 * re-queries the configured theme and emits notifications only when the effective dark-mode state
 * changes. Listener storage is concurrent, while the monitor-thread lifecycle is coordinated
 * through an atomic reference to avoid duplicate polling threads during registration races.
 *
 * @author Thomas Sartre
 * @see GnomeThemeDetector
 */
public class KdeThemeDetector extends OsThemeDetector {

  private static final Logger logger = LoggerFactory.getLogger(KdeThemeDetector.class);
  private static final List<String> KREADCONFIG_BINARY_NAMES =
      List.of("kreadconfig6", "kreadconfig5");
  private static final List<String> GET_THEME_ARGS =
      List.of("--file", "kdeglobals", "--group", "General", "--key", "ColorScheme");
  private static final long POLLING_INTERVAL_MILLIS = TimeUnit.SECONDS.toMillis(5);

  private final Set<Consumer<Boolean>> listeners = new ConcurrentHashSet<>();
  private final Pattern darkThemeNamePattern =
      Pattern.compile(".*dark.*", Pattern.CASE_INSENSITIVE);

  private final AtomicReference<DetectorThread> detectorThread = new AtomicReference<>();

  /** Creates a KDE theme detector that defers all external process work until first use. */
  public KdeThemeDetector() {
    // No eager setup is required here; the explicit constructor exists for doclint-clean API docs.
  }

  @Override
  public boolean isDark() {
    try {
      Process process = startThemeQuery();
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(process.getInputStream(), Charset.defaultCharset()))) {
        String theme = reader.readLine();
        if (theme != null && isDarkTheme(theme)) {
          return true;
        }
      }
    } catch (IOException e) {
      logger.error("Couldn't detect KDE OS theme", e);
    }
    return false;
  }

  private boolean isDarkTheme(String theme) {
    return darkThemeNamePattern.matcher(theme).matches();
  }

  private Process startThemeQuery() throws IOException {
    IOException lastFailure = null;
    for (String executable : resolveKreadconfigExecutables()) {
      try {
        return new ProcessBuilder(buildThemeQueryCommand(executable)).start();
      } catch (IOException e) {
        lastFailure = e;
      }
    }

    throw new IOException("Unable to start KDE theme query", lastFailure);
  }

  private List<String> buildThemeQueryCommand(String executable) {
    List<String> command = new ArrayList<>();
    command.add(executable);
    command.addAll(GET_THEME_ARGS);
    return command;
  }

  String resolveKreadconfigExecutable(@Nullable String path) throws IOException {
    return ExecutableResolver.resolveFirstFromPath(KREADCONFIG_BINARY_NAMES, path);
  }

  List<String> resolveKreadconfigExecutables() throws IOException {
    return resolveKreadconfigExecutables(System.getenv("PATH"));
  }

  List<String> resolveKreadconfigExecutables(@Nullable String path) throws IOException {
    return ExecutableResolver.resolveCandidatesFromPath(KREADCONFIG_BINARY_NAMES, path);
  }

  long pollingIntervalMillis() {
    return POLLING_INTERVAL_MILLIS;
  }

  @Override
  public synchronized void registerListener(@NotNull Consumer<Boolean> darkThemeListener) {
    Objects.requireNonNull(darkThemeListener);
    boolean listenerAdded = listeners.add(darkThemeListener);
    boolean singleListener = listenerAdded && listeners.size() == 1;
    DetectorThread currentDetectorThread = detectorThread.get();

    if (singleListener
        || (currentDetectorThread != null && currentDetectorThread.isInterrupted())) {
      DetectorThread newDetectorThread = new DetectorThread(this);
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

    private final KdeThemeDetector detector;
    private boolean lastValue;

    @SuppressWarnings("ThreadPriorityCheck")
    DetectorThread(@NotNull KdeThemeDetector detector) {
      this.detector = detector;
      this.lastValue = detector.isDark();
      this.setName("KDE Theme Detector Thread");
      this.setDaemon(true);
      this.setPriority(Thread.NORM_PRIORITY - 1);
    }

    @Override
    public void run() {
      while (!this.isInterrupted()) {
        boolean currentDetection = detector.isDark();
        if (currentDetection != lastValue) {
          lastValue = currentDetection;
          for (Consumer<Boolean> listener : detector.listeners) {
            try {
              listener.accept(currentDetection);
            } catch (RuntimeException e) {
              logger.error("Caught exception during listener notification", e);
            }
          }
        }
        pauseBeforeNextQuery();
      }
    }

    private void pauseBeforeNextQuery() {
      try {
        Thread.sleep(detector.pollingIntervalMillis());
      } catch (InterruptedException _) {
        interrupt();
      }
    }
  }
}
