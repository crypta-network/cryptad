package com.jthemedetecor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KdeThemeDetectorTest {
  private static final long EXCESSIVE_QUERY_TIMEOUT_MILLIS = 160L;

  @TempDir Path tempDir;

  @Test
  void resolveKreadconfigExecutable_whenOnlyPlasma6HelperExists_expectPlasma6Helper()
      throws IOException {
    Path customPrefix = Files.createDirectories(tempDir.resolve("plasma").resolve("bin"));
    Path executable = Files.writeString(customPrefix.resolve("kreadconfig6"), "#!/bin/sh\n");

    assertTrue(executable.toFile().setExecutable(true));

    KdeThemeDetector detector = new KdeThemeDetector();

    assertEquals(
        executable.toAbsolutePath().toString(),
        detector.resolveKreadconfigExecutable(customPrefix.toString()));
  }

  @Test
  void resolveKreadconfigExecutables_whenPathBlank_expectBareExecutableNamesInPriorityOrder()
      throws IOException {
    KdeThemeDetector detector = new KdeThemeDetector();

    assertEquals(
        List.of("kreadconfig6", "kreadconfig5"), detector.resolveKreadconfigExecutables(" "));
  }

  @Test
  void registerListener_whenPolling_expectQueriesAreThrottled() throws InterruptedException {
    TrackingKdeThemeDetector detector = new TrackingKdeThemeDetector();
    Consumer<Boolean> listener = ignored -> {};

    detector.registerListener(listener);
    try {
      assertTrue(detector.awaitFirstQuery());
      assertFalse(detector.awaitExcessiveQueries());
      assertTrue(detector.queryCount() < 10);
    } finally {
      detector.removeListener(listener);
    }
  }

  private static final class TrackingKdeThemeDetector extends KdeThemeDetector {
    private final AtomicInteger queryCount = new AtomicInteger();
    private final CountDownLatch firstQuery = new CountDownLatch(1);
    private final CountDownLatch excessiveQueries = new CountDownLatch(10);

    @Override
    public boolean isDark() {
      queryCount.incrementAndGet();
      firstQuery.countDown();
      excessiveQueries.countDown();
      return false;
    }

    @Override
    long pollingIntervalMillis() {
      return 50L;
    }

    boolean awaitFirstQuery() throws InterruptedException {
      return firstQuery.await(1, TimeUnit.SECONDS);
    }

    boolean awaitExcessiveQueries() throws InterruptedException {
      return excessiveQueries.await(EXCESSIVE_QUERY_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
    }

    int queryCount() {
      return queryCount.get();
    }
  }
}
