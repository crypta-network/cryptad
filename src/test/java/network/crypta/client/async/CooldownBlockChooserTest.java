package network.crypta.client.async;

import java.util.Random;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CooldownBlockChooserTest {

  @Test
  void chooseKey_whenNoCooldown_returnsEligibleBlock() {
    // Arrange
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 3,
            new Random(42L),
            /* maxRetries= */ 5,
            /* cooldownTries= */ 2,
            /* cooldownTime= */ 50_000L);

    // Act
    int chosen = chooser.chooseKey();

    // Assert
    assertTrue(chosen >= 0 && chosen < 3, "An eligible block should be chosen");
    assertEquals(0L, chooser.overallCooldownTime(), "No cooldown gating when a block is chosen");
  }

  @Test
  void onNonFatalFailure_everyNth_setsCooldownAndPreventsSelection() {
    // Arrange
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 1,
            new Random(123L),
            /* maxRetries= */ 9,
            /* cooldownTries= */ 2,
            /* cooldownTime= */ 300_000L);

    // Prime: pick the only block and fail once (no cooldown yet)
    assertEquals(0, chooser.chooseKey());
    assertFalse(chooser.onNonFatalFailure(0), "Not fatal after first failure");
    assertEquals(0L, chooser.getCooldownTime(0));

    // Second failure triggers cooldown (2 % 2 == 0)
    assertFalse(chooser.onNonFatalFailure(0), "Still not fatal with generous maxRetries");

    // Act
    int chosenAfterCooldown = chooser.chooseKey();

    // Assert
    assertEquals(-1, chosenAfterCooldown, "No block should be fetchable during cooldown");
    long wake = chooser.getCooldownTime(0);
    long overall = chooser.overallCooldownTime();
    assertTrue(wake > System.currentTimeMillis(), "Per-block wake time should be in the future");
    assertEquals(wake, overall, "Overall cooldown should reflect the earliest wake-up");
  }

  @Test
  void chooseKey_whenCooldownTimeZero_doesNotBlockSelection() {
    // Arrange: every 2nd failure triggers a cooldown of 0ms
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 1,
            new Random(7L),
            /* maxRetries= */ 9,
            /* cooldownTries= */ 2,
            /* cooldownTime= */ 0L);

    assertEquals(0, chooser.chooseKey());
    chooser.onNonFatalFailure(0); // 1st failure -> no cooldown

    // Act: 2nd failure would schedule cooldown, but zero duration should make it effectively valid.
    // A first chooseKey() may see now == wakeUp and return -1; the next one must succeed.
    chooser.onNonFatalFailure(0); // 2nd failure -> cooldown of 0ms
    long wake = chooser.getCooldownTime(0);
    // Wait until the system clock advances beyond the recorded wake time (normally immediate).
    long deadline = System.currentTimeMillis() + 25; // hard cap to avoid long spins
    while (System.currentTimeMillis() <= wake && System.currentTimeMillis() <= deadline) {
      // Brief spin to allow the clock to advance beyond the recorded wake time.
      // Avoid sleeps to keep the test deterministic and fast.
      Thread.onSpinWait();
    }
    int chosen = chooser.chooseKey();

    // Assert
    assertEquals(0, chosen, "Zero-duration cooldown must not block selection");
    assertEquals(0L, chooser.getCooldownTime(0), "Cooldown time should be cleared once valid");
    assertEquals(0L, chooser.overallCooldownTime(), "No overall cooldown when block is selectable");
  }

  @Test
  void onNonFatalFailure_whenExceedsMaxRetries_marksFatalAndNoCooldown() {
    // Arrange: keep cooldownTries high so we don't set a cooldown before exceeding retries
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 1,
            new Random(1L),
            /* maxRetries= */ 1,
            /* cooldownTries= */ 10,
            /* cooldownTime= */ 120_000L);

    // First failure: not fatal, no cooldown due to high cooldownTries
    assertFalse(chooser.onNonFatalFailure(0));
    assertEquals(0L, chooser.getCooldownTime(0));

    // Act: Second failure exceeds maxRetries (1)
    boolean fatal = chooser.onNonFatalFailure(0);

    // Assert: fatal and chooser won't select the block anymore (retry limit)
    assertTrue(fatal, "Exceeding maxRetries should be reported as fatal");
    assertEquals(
        0L, chooser.getCooldownTime(0), "Cooldown must not be scheduled when retries exceeded");
    assertEquals(
        -1, chooser.chooseKey(), "No selection after exceeding retry budget for the only block");
  }

  @Test
  void overallCooldownTime_afterScan_reflectsEarliestPerBlockCooldown() {
    // Arrange: three blocks, all enter cooldown at slightly different instants
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 3,
            new Random(99L),
            /* maxRetries= */ 9,
            /* cooldownTries= */ 2,
            /* cooldownTime= */ 600_000L);

    // Put each block into cooldown by failing twice
    for (int i = 0; i < 3; i++) {
      chooser.onNonFatalFailure(i); // first -> no cooldown
      chooser.onNonFatalFailure(i); // second -> cooldown
    }

    long w0 = chooser.getCooldownTime(0);
    long w1 = chooser.getCooldownTime(1);
    long w2 = chooser.getCooldownTime(2);
    assertTrue(w0 > 0 && w1 > 0 && w2 > 0, "All blocks should have a future wake-up time set");

    long expectedMin = Math.min(w0, Math.min(w1, w2));

    // Act: a chooseKey() scan updates the overall earliest wake-up time
    assertEquals(-1, chooser.chooseKey(), "All blocks cooling down -> no selection");

    // Assert
    assertEquals(
        expectedMin,
        chooser.overallCooldownTime(),
        "Overall cooldown time should be the earliest per-block wake-up");
  }

  @Test
  void getCooldownTime_whenBlockSucceeded_returnsZero() {
    // Arrange
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 1,
            new Random(2L),
            /* maxRetries= */ 9,
            /* cooldownTries= */ 2,
            /* cooldownTime= */ 60_000L);

    // Succeed the only block
    assertTrue(chooser.onSuccess(0));

    // Even if we try to set cooldown via failures afterward, success state should force zero
    chooser.onNonFatalFailure(0);

    // Assert
    assertEquals(0L, chooser.getCooldownTime(0), "Succeeded blocks must report zero cooldown");
  }

  @Test
  void onUnSuccess_clearsPerBlockCooldownAndOverall() {
    // Arrange
    CooldownBlockChooser chooser =
        new CooldownBlockChooser(
            /* blocks= */ 1,
            new Random(3L),
            /* maxRetries= */ 9,
            /* cooldownTries= */ 2,
            /* cooldownTime= */ 120_000L);

    // Enter cooldown
    chooser.onNonFatalFailure(0);
    chooser.onNonFatalFailure(0); // triggers cooldown
    assertEquals(-1, chooser.chooseKey()); // ensure overall cooldown is computed
    assertTrue(chooser.overallCooldownTime() > System.currentTimeMillis());
    assertTrue(chooser.getCooldownTime(0) > 0);

    // Act: clear via onUnSuccess (allowed even if not previously completed)
    chooser.onUnSuccess(0);

    // Assert: both overall and per-block cooldown cleared; selection resumes
    assertEquals(0L, chooser.overallCooldownTime());
    assertEquals(0L, chooser.getCooldownTime(0));
    assertEquals(0, chooser.chooseKey());
  }
}
