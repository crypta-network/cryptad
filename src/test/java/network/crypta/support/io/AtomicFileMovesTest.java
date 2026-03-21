package network.crypta.support.io;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

@SuppressWarnings("java:S100")
class AtomicFileMovesTest {

  @Test
  @DisplayName("moveTo_whenAtomicMoveSupported_expectTrue")
  void moveTo_whenAtomicMoveSupported_expectTrue(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("from.bin");
    Path dst = tmp.resolve("to.bin");
    Files.write(src, List.of("x"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .then(_ -> dst);

      // Act
      boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_whenAtomicNotSupported_thenFallbackSucceeds_expectTrue")
  void moveTo_whenAtomicNotSupported_thenFallbackSucceeds_expectTrue(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path src = tmp.resolve("from2.bin");
    Path dst = tmp.resolve("to2.bin");
    Files.write(src, List.of("y"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new java.nio.file.AtomicMoveNotSupportedException("a", "b", "nope"));
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.REPLACE_EXISTING)))
          .then(_ -> dst);

      // Act
      boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_whenAtomicMoveThrowsIOException_thenFallbackSucceeds_expectTrue")
  void moveTo_whenAtomicMoveThrowsIOException_thenFallbackSucceeds_expectTrue(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path src = tmp.resolve("from-io.bin");
    Path dst = tmp.resolve("to-io.bin");
    Files.write(src, List.of("io"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new IOException("transient-atomic-failure"));
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.REPLACE_EXISTING)))
          .then(_ -> dst);

      // Act
      boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_whenAtomicMoveSeesExistingTarget_thenFallbackReplaces_expectTrue")
  void moveTo_whenAtomicMoveSeesExistingTarget_thenFallbackReplaces_expectTrue(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path src = tmp.resolve("from-existing.bin");
    Path dst = tmp.resolve("to-existing.bin");
    Files.write(src, List.of("fresh"));
    Files.write(dst, List.of("stale"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new FileAlreadyExistsException(src.toString(), dst.toString(), "exists"));
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.REPLACE_EXISTING)))
          .then(_ -> dst);

      // Act
      boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertTrue(ok);
    }
  }

  @Test
  @DisplayName("moveTo_whenFallbackFailsAllRetries_expectFalse")
  void moveTo_whenFallbackFailsAllRetries_expectFalse(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("from-fail.bin");
    Path dst = tmp.resolve("to-fail.bin");
    Files.write(src, List.of("fail"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new java.nio.file.AtomicMoveNotSupportedException("a", "b", "nope"));
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.REPLACE_EXISTING)))
          .thenThrow(new IOException("locked-1"))
          .thenThrow(new IOException("locked-2"))
          .thenThrow(new IOException("locked-3"))
          .thenThrow(new IOException("locked-4"))
          .thenThrow(new IOException("locked-5"));

      // Act
      boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

      // Assert
      assertFalse(ok);
      files.verify(() -> Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING), times(5));
    }
  }

  @Test
  @DisplayName("moveTo_whenRetrySleepInterrupted_expectFalseAndPreservesInterrupt")
  void moveTo_whenRetrySleepInterrupted_expectFalseAndPreservesInterrupt(@TempDir Path tmp)
      throws Exception {
    // Arrange
    Path src = tmp.resolve("from-interrupted.bin");
    Path dst = tmp.resolve("to-interrupted.bin");
    Files.write(src, List.of("interrupt"));

    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.ATOMIC_MOVE)))
          .thenThrow(new java.nio.file.AtomicMoveNotSupportedException("a", "b", "nope"));
      files
          .when(() -> Files.move(eq(src), eq(dst), eq(StandardCopyOption.REPLACE_EXISTING)))
          .thenThrow(new IOException("locked"));

      Thread.currentThread().interrupt();
      try {
        // Act
        boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

        // Assert
        assertFalse(ok);
        assertTrue(Thread.currentThread().isInterrupted());
        files.verify(() -> Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING), times(1));
      } finally {
        boolean clearedInterrupt = Thread.interrupted();
        if (clearedInterrupt) {
          assertFalse(Thread.currentThread().isInterrupted());
        }
      }
    }
  }

  @Test
  @DisplayName("moveTo_overwriteFalseAndDestExists_expectFalse")
  void moveTo_overwriteFalseAndDestExists_expectFalse(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("from4.bin");
    Path dst = tmp.resolve("to4.bin");
    Files.write(src, List.of("1"));
    Files.write(dst, List.of("2"));

    // Act
    boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile(), false);

    // Assert
    assertFalse(ok);
  }

  @Test
  @DisplayName("moveTo_whenDestinationExists_replacesExistingContent")
  void moveTo_whenDestinationExists_replacesExistingContent(@TempDir Path tmp) throws Exception {
    // Arrange
    Path src = tmp.resolve("from-replace.bin");
    Path dst = tmp.resolve("to-replace.bin");
    Files.writeString(src, "new-content");
    Files.writeString(dst, "old-content");

    // Act
    boolean ok = AtomicFileMoves.moveTo(src.toFile(), dst.toFile());

    // Assert
    assertTrue(ok);
    assertFalse(Files.exists(src));
    assertTrue(Files.exists(dst));
    assertEquals("new-content", Files.readString(dst));
  }
}
