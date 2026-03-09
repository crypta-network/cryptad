package com.jthemedetecor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class GnomeThemeDetectorTest {
  private static final String RESOLVED_GSETTINGS = "/mock/bin/gsettings";
  private static final String GNOME_SCHEMA = "org.gnome.desktop.interface";
  private static final long THREAD_TIMEOUT_SECONDS = 5L;

  @Test
  void isDark_whenGtkThemeContainsDark_expectTrueAfterFirstQuery() {
    GnomeThemeDetector detector = new GnomeThemeDetector();
    List<List<String>> constructedCommands = new ArrayList<>();

    try (MockedStatic<ExecutableResolver> executableResolver =
            mockStatic(ExecutableResolver.class);
        MockedConstruction<ProcessBuilder> processBuilders =
            mockProcessBuilders(
                List.of(new FixedOutputProcess("'Adwaita-dark'\n")), constructedCommands)) {
      executableResolver
          .when(() -> ExecutableResolver.resolveFromPath("gsettings"))
          .thenReturn(RESOLVED_GSETTINGS);

      boolean dark = detector.isDark();

      assertAll(
          () -> assertTrue(dark),
          () -> assertEquals(1, processBuilders.constructed().size()),
          () ->
              assertEquals(
                  List.of(RESOLVED_GSETTINGS, "get", GNOME_SCHEMA, "gtk-theme"),
                  constructedCommands.getFirst()));
    }
  }

  @Test
  void isDark_whenGtkThemeIsLightAndColorSchemePrefersDark_expectTrueAfterSecondQuery() {
    GnomeThemeDetector detector = new GnomeThemeDetector();
    List<List<String>> constructedCommands = new ArrayList<>();

    try (MockedStatic<ExecutableResolver> executableResolver =
            mockStatic(ExecutableResolver.class);
        MockedConstruction<ProcessBuilder> processBuilders =
            mockProcessBuilders(
                List.of(
                    new FixedOutputProcess("'Adwaita'\n"),
                    new FixedOutputProcess("'prefer-dark'\n")),
                constructedCommands)) {
      executableResolver
          .when(() -> ExecutableResolver.resolveFromPath("gsettings"))
          .thenReturn(RESOLVED_GSETTINGS);

      boolean dark = detector.isDark();

      assertAll(
          () -> assertTrue(dark),
          () -> assertEquals(2, processBuilders.constructed().size()),
          () ->
              assertEquals(
                  List.of(RESOLVED_GSETTINGS, "get", GNOME_SCHEMA, "gtk-theme"),
                  constructedCommands.getFirst()),
          () ->
              assertEquals(
                  List.of(RESOLVED_GSETTINGS, "get", GNOME_SCHEMA, "color-scheme"),
                  constructedCommands.get(1)));
    }
  }

  @Test
  void isDark_whenGsettingsReturnsOnlyLightValues_expectFalse() {
    GnomeThemeDetector detector = new GnomeThemeDetector();
    List<List<String>> constructedCommands = new ArrayList<>();

    try (MockedStatic<ExecutableResolver> executableResolver =
            mockStatic(ExecutableResolver.class);
        MockedConstruction<ProcessBuilder> processBuilders =
            mockProcessBuilders(
                List.of(
                    new FixedOutputProcess("'Adwaita'\n"), new FixedOutputProcess("'default'\n")),
                constructedCommands)) {
      executableResolver
          .when(() -> ExecutableResolver.resolveFromPath("gsettings"))
          .thenReturn(RESOLVED_GSETTINGS);

      boolean dark = detector.isDark();

      assertAll(
          () -> assertFalse(dark),
          () -> assertEquals(2, processBuilders.constructed().size()),
          () -> assertEquals(2, constructedCommands.size()),
          () ->
              assertEquals(
                  List.of(RESOLVED_GSETTINGS, "get", GNOME_SCHEMA, "gtk-theme"),
                  constructedCommands.getFirst()),
          () ->
              assertEquals(
                  List.of(RESOLVED_GSETTINGS, "get", GNOME_SCHEMA, "color-scheme"),
                  constructedCommands.get(1)));
    }
  }

  @Test
  void isDark_whenExecutableResolutionFails_expectFalse() {
    GnomeThemeDetector detector = new GnomeThemeDetector();

    try (MockedStatic<ExecutableResolver> executableResolver =
        mockStatic(ExecutableResolver.class)) {
      executableResolver
          .when(() -> ExecutableResolver.resolveFromPath("gsettings"))
          .thenThrow(new IOException("missing gsettings"));

      boolean dark = detector.isDark();

      assertFalse(dark);
    }
  }

  @Test
  void registerListener_whenListenerIsNull_expectNullPointerException() {
    GnomeThemeDetector detector = new GnomeThemeDetector();

    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> detector.registerListener(null));
  }

  @Test
  void removeListener_whenListenerIsNull_expectNullPointerException() {
    GnomeThemeDetector detector = new GnomeThemeDetector();

    assertThrows(NullPointerException.class, () -> detector.removeListener(null));
  }

  @Test
  void processMonitoringLine_whenThemeChanges_expectListenerNotified() throws Exception {
    TrackingGnomeThemeDetector detector = new TrackingGnomeThemeDetector(false);
    AtomicReference<Boolean> notifiedValue = new AtomicReference<>();
    AtomicInteger notificationCount = new AtomicInteger();
    Consumer<Boolean> listener =
        dark -> {
          notifiedValue.set(dark);
          notificationCount.incrementAndGet();
        };
    Object detectorThread = newDetectorThread(detector);

    addListener(detector, listener);

    invokeProcessMonitoringLine(detectorThread, "gtk-theme: 'Adwaita-dark'");

    assertAll(
        () -> assertEquals(Boolean.TRUE, notifiedValue.get()),
        () -> assertEquals(1, notificationCount.get()));
  }

  @Test
  void processMonitoringLine_whenThemeDoesNotChange_expectNoNotification() throws Exception {
    TrackingGnomeThemeDetector detector = new TrackingGnomeThemeDetector(true);
    AtomicInteger notificationCount = new AtomicInteger();
    Object detectorThread = newDetectorThread(detector);

    addListener(detector, ignored -> notificationCount.incrementAndGet());

    invokeProcessMonitoringLine(detectorThread, "gtk-theme: 'Adwaita-dark'");

    assertEquals(0, notificationCount.get());
  }

  @Test
  void processMonitoringLine_whenLineIsUnrelated_expectNoNotification() throws Exception {
    TrackingGnomeThemeDetector detector = new TrackingGnomeThemeDetector(false);
    AtomicInteger notificationCount = new AtomicInteger();
    Object detectorThread = newDetectorThread(detector);

    addListener(detector, ignored -> notificationCount.incrementAndGet());

    invokeProcessMonitoringLine(detectorThread, "cursor-size: 24");

    assertEquals(0, notificationCount.get());
  }

  @Test
  void monitorChanges_whenMonitorStreamEnds_expectThreadStopsAndProcessDestroyed()
      throws Exception {
    TrackingGnomeThemeDetector detector = new TrackingGnomeThemeDetector(false);
    Object detectorThread = newDetectorThread(detector);
    FixedOutputProcess monitoringProcess = new FixedOutputProcess("");
    AtomicReference<Throwable> failure = new AtomicReference<>();

    Thread monitoringThread = startMonitoringThread(detectorThread, monitoringProcess, failure);

    awaitThreadExit(monitoringThread);

    assertAll(
        () -> assertNull(failure.get()),
        () -> assertFalse(monitoringThread.isAlive()),
        () -> assertFalse(monitoringProcess.isAlive()));
  }

  @Test
  void interrupt_whenMonitorReadBlocks_expectThreadStopsAndProcessDestroyed() throws Exception {
    TrackingGnomeThemeDetector detector = new TrackingGnomeThemeDetector(false);
    Object detectorThread = newDetectorThread(detector);
    BlockingProcess monitoringProcess = new BlockingProcess();
    AtomicReference<Throwable> failure = new AtomicReference<>();

    Thread monitoringThread = startMonitoringThread(detectorThread, monitoringProcess, failure);
    monitoringProcess.awaitReadStarted();

    ((Thread) detectorThread).interrupt();
    awaitThreadExit(monitoringThread);

    assertAll(
        () -> assertNull(failure.get()),
        () -> assertFalse(monitoringThread.isAlive()),
        () -> assertTrue(monitoringProcess.wasDestroyed()),
        () -> assertFalse(monitoringProcess.isAlive()));
  }

  private static MockedConstruction<ProcessBuilder> mockProcessBuilders(
      List<? extends Process> processes, List<List<String>> constructedCommands) {
    AtomicInteger startIndex = new AtomicInteger();

    return mockConstruction(
        ProcessBuilder.class,
        (processBuilder, context) -> {
          constructedCommands.add(extractCommand(context));
          when(processBuilder.start()).thenAnswer(_ -> processes.get(startIndex.getAndIncrement()));
        });
  }

  @SuppressWarnings("unchecked")
  private static List<String> extractCommand(MockedConstruction.Context context) {
    return List.copyOf((List<String>) context.arguments().getFirst());
  }

  private static Object newDetectorThread(GnomeThemeDetector detector) throws Exception {
    Constructor<?> constructor =
        detectorThreadClass().getDeclaredConstructor(GnomeThemeDetector.class);
    constructor.setAccessible(true);
    return constructor.newInstance(detector);
  }

  private static Thread startMonitoringThread(
      Object detectorThread, Process monitoringProcess, AtomicReference<Throwable> failure) {
    Thread monitoringThread =
        Thread.ofPlatform()
            .name("gnome-detector-test")
            .unstarted(
                () -> {
                  try {
                    invokeMonitorChanges(detectorThread, monitoringProcess);
                  } catch (Throwable t) {
                    failure.set(t);
                  }
                });
    monitoringThread.start();
    return monitoringThread;
  }

  private static void invokeMonitorChanges(Object detectorThread, Process monitoringProcess)
      throws Exception {
    Method monitorChanges =
        detectorThreadClass().getDeclaredMethod("monitorChanges", Process.class);
    monitorChanges.setAccessible(true);
    try {
      monitorChanges.invoke(detectorThread, monitoringProcess);
    } catch (InvocationTargetException e) {
      if (((Thread) detectorThread).isInterrupted() && e.getCause() instanceof IOException) {
        return;
      }
      throw e;
    }
  }

  private static void invokeProcessMonitoringLine(Object detectorThread, String readLine)
      throws Exception {
    Method processMonitoringLine =
        detectorThreadClass().getDeclaredMethod("processMonitoringLine", String.class);
    processMonitoringLine.setAccessible(true);
    processMonitoringLine.invoke(detectorThread, readLine);
  }

  private static Class<?> detectorThreadClass() {
    for (Class<?> declaredClass : GnomeThemeDetector.class.getDeclaredClasses()) {
      if (Thread.class.isAssignableFrom(declaredClass)) {
        return declaredClass;
      }
    }

    throw new IllegalStateException("DetectorThread class not found");
  }

  @SuppressWarnings("unchecked")
  private static void addListener(GnomeThemeDetector detector, Consumer<Boolean> listener)
      throws Exception {
    Field listenersField = GnomeThemeDetector.class.getDeclaredField("listeners");
    listenersField.setAccessible(true);
    ((java.util.Set<Consumer<Boolean>>) listenersField.get(detector)).add(listener);
  }

  private static void awaitThreadExit(Thread detectorThread) throws InterruptedException {
    detectorThread.join(TimeUnit.SECONDS.toMillis(THREAD_TIMEOUT_SECONDS));
    assertFalse(detectorThread.isAlive());
  }

  private static class FixedOutputProcess extends Process {
    private final InputStream inputStream;
    private final AtomicBoolean alive = new AtomicBoolean(true);

    FixedOutputProcess(String output) {
      this.inputStream = new ByteArrayInputStream(output.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return inputStream;
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      alive.set(false);
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      alive.set(false);
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      alive.set(false);
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return alive.get();
    }
  }

  private static final class BlockingProcess extends Process {
    private final BlockingInputStream inputStream = new BlockingInputStream();
    private final AtomicBoolean alive = new AtomicBoolean(true);
    private final AtomicBoolean destroyed = new AtomicBoolean(false);

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return inputStream;
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      destroy();
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      destroy();
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      destroyed.set(true);
      alive.set(false);
      inputStream.close();
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return alive.get();
    }

    private void awaitReadStarted() throws InterruptedException {
      assertTrue(inputStream.readStarted.await(THREAD_TIMEOUT_SECONDS, TimeUnit.SECONDS));
    }

    private boolean wasDestroyed() {
      return destroyed.get();
    }
  }

  private static final class BlockingInputStream extends InputStream {
    private final CountDownLatch readStarted = new CountDownLatch(1);
    private final CountDownLatch closed = new CountDownLatch(1);

    @Override
    public int read() throws IOException {
      readStarted.countDown();
      try {
        if (!closed.await(THREAD_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
          throw new IOException("Timed out while waiting for monitor shutdown");
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while waiting for monitor shutdown", e);
      }
      return -1;
    }

    @Override
    public int read(byte @NonNull [] b, int off, int len) throws IOException {
      if (len == 0) {
        return 0;
      }
      return read();
    }

    @Override
    public void close() {
      closed.countDown();
    }
  }

  private static final class TrackingGnomeThemeDetector extends GnomeThemeDetector {
    private final boolean dark;

    TrackingGnomeThemeDetector(boolean dark) {
      this.dark = dark;
    }

    @Override
    public boolean isDark() {
      return dark;
    }
  }
}
