package network.crypta.node;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.api.StringCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "deprecation"})
class ProgramDirectoryTest {

  @TempDir Path tempDir;

  @Test
  void move_whenFirstSetToNewDirectory_expectDirCreatedAndSet() throws IOException {
    // Arrange
    ProgramDirectory pd = new ProgramDirectory();
    Path newDir = tempDir.resolve("initial");

    // Act
    pd.move(newDir.toString());

    // Assert
    assertEquals(newDir.toFile().getCanonicalFile(), pd.dir().getCanonicalFile());
    assertTrue(Files.isDirectory(newDir));
  }

  @Test
  void move_whenMovingToDifferentDirectoryLater_expectIOExceptionNotImplemented()
      throws IOException {
    // Arrange
    ProgramDirectory pd = new ProgramDirectory();
    Path dir1 = tempDir.resolve("d1");
    Path dir2 = tempDir.resolve("d2");
    pd.move(dir1.toString());

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> pd.move(dir2.toString()));
    assertEquals("move not implemented", ex.getMessage());
  }

  @Test
  void move_whenTargetIsExistingFile_expectIOExceptionWithL10nPathAppended() throws IOException {
    // Arrange
    ProgramDirectory pd = new ProgramDirectory();
    Path targetFile = Files.createTempFile(tempDir, "file", ".txt");

    // Act
    IOException ex = assertThrows(IOException.class, () -> pd.move(targetFile.toString()));

    // Assert
    assertTrue(
        ex.getMessage().startsWith("Could not find or make a directory called: "),
        "message should include the fixed prefix");
    assertTrue(
        ex.getMessage().contains(targetFile.toString()),
        "message should include the localized path (key or translation) value");
  }

  @Test
  void getStringCallback_whenDefaultConstructor_expectReadOnlyBehavior() throws Exception {
    // Arrange
    ProgramDirectory pd = new ProgramDirectory();
    StringCallback cb = pd.getStringCallback();
    Path path1 = tempDir.resolve("ro1");
    Path path2 = tempDir.resolve("ro2");

    // Act
    cb.set(path1.toString());

    // Assert
    assertTrue(cb.isReadOnly(), "Default callback must be read-only");
    assertEquals(new File(path1.toString()).getPath(), cb.get());

    // Setting to the same path is a no-op
    assertDoesNotThrow(() -> cb.set(path1.toString()));

    // Changing to a different path is rejected
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> cb.set(path2.toString()));
    assertEquals("Moving program directory on the fly not supported at present", ex.getMessage());
  }

  @Test
  void getStringCallback_whenRWConstructor_expectWritableAndCreatesDirectory() throws Exception {
    // Arrange
    final String errorKey = "____TEST_DO_NOT_TRANSLATE____";
    ProgramDirectory pd = new ProgramDirectory(errorKey);
    StringCallback cb = pd.getStringCallback();
    Path path1 = tempDir.resolve("rw1");
    Path path2 = tempDir.resolve("rw2"); // does not exist yet

    // Act + Assert
    assertFalse(cb.isReadOnly(), "RW callback must be writable");

    // The initial set succeeds; RWDirectoryCallback does not create the directory on the first set
    cb.set(path1.toString());
    assertEquals(new File(path1.toString()).getPath(), cb.get());
    assertFalse(Files.exists(path1), "Initial path is not created by first set call");

    // Setting the same path again is a no-op
    assertDoesNotThrow(() -> cb.set(path1.toString()));

    // Change to a different path: directory should be created and accepted
    cb.set(path2.toString());
    assertEquals(new File(path2.toString()).getPath(), cb.get());
    assertTrue(Files.isDirectory(path2));
  }

  @Test
  void rwCallback_whenTargetIsFile_expectInvalidConfigWithL10nMessage() throws Exception {
    // Arrange
    final String errorKey = "____TEST_DO_NOT_TRANSLATE____";
    ProgramDirectory pd = new ProgramDirectory(errorKey);
    StringCallback cb = pd.getStringCallback();
    Path initial = tempDir.resolve("rw_init");
    Path filePath = Files.createTempFile(tempDir, "as_file", ".bin");
    cb.set(initial.toString());

    // Act
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> cb.set(filePath.toString()));

    // Assert — message equals localized string for the error key
    assertEquals(NodeL10n.getBase().getString(errorKey), ex.getMessage());
  }

  @Test
  void file_whenCalled_expectChildAndTrackedBasename() throws IOException {
    // Arrange
    ProgramDirectory pd = new ProgramDirectory();
    Path dir = tempDir.resolve("base");
    pd.move(dir.toString());

    String basename = "test.txt";

    // Act
    File f = pd.file(basename);

    // Assert
    assertNotNull(f);
    assertEquals(new File(dir.toFile(), basename).getCanonicalFile(), f.getCanonicalFile());
    // Access to protected field is allowed within the same package
    assertTrue(pd.files.contains(basename), "basename must be tracked in files set");
  }

  @Test
  void nextOrder_whenCalledTwice_expectMonotonicIncreaseByOne() {
    // Arrange + Act
    int a = ProgramDirectory.nextOrder();
    int b = ProgramDirectory.nextOrder();

    // Assert
    assertEquals(a + 1, b);
  }
}
