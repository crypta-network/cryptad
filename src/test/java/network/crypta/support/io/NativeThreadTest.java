package network.crypta.support.io;

import com.sun.jna.Platform;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link NativeThread} in AAA style (JUnit 6 + Mockito).
 *
 * <p>Naming: method_whenCondition_expectOutcome
 */
@SuppressWarnings("java:S100")
class NativeThreadTest {

  // ---------- normalizeName ----------

  @ParameterizedTest
  @DisplayName("normalizeName trims and strips tokens in order")
  @CsvSource({
    // input, expected
    "Worker for Peer@host (ID 123),Worker",
    "Task@abc,Task",
    "  Task Name (running)  ,Task Name",
    "NoTokensHere,NoTokensHere",
    "'', ''",
    "A for B for C,A",
    // '@' before " for " should be applied after first cut
    "Alpha@Beta for Gamma,Alpha",
    // 'for' without surrounding spaces should not match the token
    "Effort forbear,Effort forbear"
  })
  void normalizeName_whenVariousInputs_expectSanitized(String input, String expected) {
    // Arrange + Act
    String actual = NativeThread.normalizeName(input);
    // Assert
    assertEquals(expected, actual);
  }

  @Test
  @SuppressWarnings({"ConstantValue", "DataFlowIssue"})
  void normalizeName_whenNull_expectNullPointerException() {
    // Arrange
    String input = null;
    // Act + Assert
    assertThrows(NullPointerException.class, () -> NativeThread.normalizeName(input));
  }

  // ---------- getNormalizedName ----------

  @Test
  @Timeout(value = 5, unit = TimeUnit.SECONDS)
  void getNormalizedName_whenThreadHasDecoratedName_expectBaseName() throws Exception {
    // Arrange
    Runnable noop = () -> {};
    NativeThread t =
        new NativeThread(
            noop,
            "Worker for Node@host (running)",
            NativeThread.PriorityLevel.NORM_PRIORITY.value,
            true) {
          @Override
          public void realRun() {
            // intentionally empty: exercising base Thread.run() path only
          }
        };

    // Act
    t.start();
    t.join(2000);

    // Assert
    assertEquals("Worker", t.getNormalizedName());
  }

  // ---------- getNativePriority ----------

  @Test
  void getNativePriority_whenConstructedWithValues_expectSameValues() {
    // Arrange
    NativeThread tMin = new NativeThread("a", NativeThread.PriorityLevel.MIN_PRIORITY.value, true);
    NativeThread tNorm =
        new NativeThread("b", NativeThread.PriorityLevel.NORM_PRIORITY.value, true);
    NativeThread tMax = new NativeThread("c", NativeThread.PriorityLevel.MAX_PRIORITY.value, true);
    // Act + Assert
    assertEquals(NativeThread.PriorityLevel.MIN_PRIORITY.value, tMin.getNativePriority());
    assertEquals(NativeThread.PriorityLevel.NORM_PRIORITY.value, tNorm.getNativePriority());
    assertEquals(NativeThread.PriorityLevel.MAX_PRIORITY.value, tMax.getNativePriority());
  }

  // ---------- run() behavior ----------

  @Test
  @Timeout(value = 5, unit = TimeUnit.SECONDS)
  void run_whenRunnableProvided_expectRunnableAndRealRunCalled() throws Exception {
    // Arrange
    CountDownLatch ranRunnable = new CountDownLatch(1);
    CountDownLatch ranRealRun = new CountDownLatch(1);
    Runnable r = Mockito.mock(Runnable.class);
    doAnswer(
            inv -> {
              ranRunnable.countDown();
              return null;
            })
        .when(r)
        .run();

    NativeThread t =
        new NativeThread(r, "TestThread", NativeThread.PriorityLevel.NORM_PRIORITY.value, true) {
          @Override
          public void realRun() {
            ranRealRun.countDown();
          }
        };

    // Act
    t.start();
    t.join(3000);

    // Assert
    assertTrue(ranRunnable.await(100, TimeUnit.MILLISECONDS), "Runnable.run() was not called");
    assertTrue(ranRealRun.await(100, TimeUnit.MILLISECONDS), "realRun() was not called");
    verify(r, times(1)).run();
  }

  @Test
  @Timeout(value = 5, unit = TimeUnit.SECONDS)
  void run_whenPriorityIsOutOfRange_expectIllegalArgumentException() throws Exception {
    // Arrange
    AtomicReference<Throwable> thrown = new AtomicReference<>();
    Runnable noop = () -> {};
    NativeThread t =
        new NativeThread(noop, "BadPriority", 0 /* invalid */, true) {
          @Override
          public void realRun() {
            // intentionally empty: this test focuses on setPriority exception propagation
          }
        };
    t.setUncaughtExceptionHandler((thr, ex) -> thrown.set(ex));

    // Act
    t.start();
    t.join(2000);

    // Assert
    Throwable ex = thrown.get();
    assertNotNull(ex, "Expected an exception from setPriority");
    assertInstanceOf(
        IllegalArgumentException.class,
        ex,
        "Expected IllegalArgumentException but was: " + ex.getClass());
  }

  // ---------- usingNativeCode (OS-conditional) ----------

  @Test
  void usingNativeCode_whenNotLinux_expectFalse() {
    // Arrange
    assumeFalse(Platform.isLinux());
    // Act + Assert
    assertFalse(NativeThread.usingNativeCode());
  }

  @Test
  void usingNativeCode_whenLinux_expectConsistentBoolean() {
    // Note: On Linux the value depends on environment, so only assert it doesn't throw.
    assumeTrue(Platform.isLinux());
    assertDoesNotThrow(NativeThread::usingNativeCode);
  }
}
