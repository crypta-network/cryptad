package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ConfigurablePersisterTest {

  @Mock private Persistable persistable;
  @Mock private Ticker ticker;

  @TempDir Path tmpDir;

  @Test
  void constructor_whenDefaultPathUnderBaseDir_createsFilesAndTargetsSet() throws Exception {
    // Arrange
    Config cfg = new Config();
    SubConfig node = cfg.createSubConfig("node");
    String optionName = "throttleFile";
    String defaultName = "throttles.txt";

    File baseDir = tmpDir.toFile();

    // Act
    ConfigurablePersister cp =
        new ConfigurablePersister(
            persistable,
            new ConfigurablePersisterParams(
                node,
                optionName,
                defaultName,
                new Option.Meta(0, false, false, "short", "long"),
                baseDir),
            ticker);

    // Assert
    File expectedTarget = new File(baseDir, defaultName);
    File expectedTemp = new File(expectedTarget + ".tmp");
    assertTrue(expectedTarget.exists(), "target file should be created");
    assertTrue(expectedTemp.exists(), "temp file should be created");
    assertEquals(expectedTarget.getCanonicalFile(), cp.persistTarget.getCanonicalFile());
    assertEquals(expectedTemp.getCanonicalFile(), cp.persistTemp.getCanonicalFile());

    // After initialization, the option's callback should report the current target path
    node.finishedInitialization();
    String configured = node.getString(optionName);
    assertEquals(expectedTarget.toString(), configured);
  }

  @Test
  void constructor_whenParentIsFile_throwsNodeInitExceptionWithExitCode() throws IOException {
    // Arrange
    Config cfg = new Config();
    SubConfig node = cfg.createSubConfig("node");
    String optionName = "throttleFile";
    File baseDir = tmpDir.toFile();

    // Create a file which we will try to treat as a parent directory
    File notADir = new File(baseDir, "parentFile");
    assertTrue(notADir.createNewFile(), "setup: parentFile should be created");

    String defaultName = "parentFile" + File.separator + "child.txt"; // parent is a file

    // Act + Assert
    NodeInitException ex =
        assertThrows(
            NodeInitException.class,
            () ->
                new ConfigurablePersister(
                    persistable,
                    new ConfigurablePersisterParams(
                        node,
                        optionName,
                        defaultName,
                        new Option.Meta(0, false, false, "short", "long"),
                        baseDir),
                    ticker));

    assertEquals(NodeInitException.EXIT_THROTTLE_FILE_ERROR, ex.exitCode);
    String msg = ex.getMessage();
    assertNotNull(msg);
    // Should contain the localized reason and mention the .tmp path
    String expectedReason =
        NodeL10n.getBase().getString("ConfigurablePersister.doesNotExistCannotCreate");
    assertTrue(msg.contains(expectedReason), msg);
    assertTrue(msg.contains(".tmp"), msg);
  }

  @Test
  void set_whenChangeToNewValidPath_updatesTargetsAndCreatesFiles() throws Exception {
    // Arrange: construct with a valid default
    Config cfg = new Config();
    SubConfig node = cfg.createSubConfig("node");
    String optionName = "throttleFile";
    File baseDir = tmpDir.toFile();
    ConfigurablePersister cp =
        new ConfigurablePersister(
            persistable,
            new ConfigurablePersisterParams(
                node,
                optionName,
                "throttles.txt",
                new Option.Meta(0, false, false, "short", "long"),
                baseDir),
            ticker);

    File newTarget = new File(baseDir, "new-throttles.txt");

    // Act: update through the registered option (invokes callback -> setThrottles)
    Option<?> opt = node.getOption(optionName);
    opt.setValue(newTarget.toString());

    // Assert: fields updated and files created
    File expectedTemp = new File(newTarget + ".tmp");
    assertTrue(newTarget.exists(), "new target should be created");
    assertTrue(expectedTemp.exists(), "new temp should be created");
    assertEquals(newTarget.getCanonicalFile(), cp.persistTarget.getCanonicalFile());
    assertEquals(expectedTemp.getCanonicalFile(), cp.persistTemp.getCanonicalFile());

    node.finishedInitialization();
    assertEquals(newTarget.toString(), node.getString(optionName));
  }

  @Test
  void set_whenChangeToInvalidPath_throwsInvalidConfigValueAndDoesNotChangeTargets()
      throws Exception {
    // Arrange: construct with a valid default
    Config cfg = new Config();
    SubConfig node = cfg.createSubConfig("node");
    String optionName = "throttleFile";
    File baseDir = tmpDir.toFile();
    ConfigurablePersister cp =
        new ConfigurablePersister(
            persistable,
            new ConfigurablePersisterParams(
                node,
                optionName,
                "throttles.txt",
                new Option.Meta(0, false, false, "short", "long"),
                baseDir),
            ticker);

    File originalTarget = cp.persistTarget;

    // Create a file and attempt to use it as a parent directory for the new value
    File parentIsFile = new File(baseDir, "not-a-dir");
    assertTrue(parentIsFile.createNewFile(), "setup: not-a-dir should be created");
    String badPath = new File(parentIsFile, "child.txt").toString();

    // Act + Assert: setting to an invalid path throws and does not update internal fields
    Option<?> opt = node.getOption(optionName);
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue(badPath));
    assertEquals(originalTarget.getCanonicalFile(), cp.persistTarget.getCanonicalFile());

    node.finishedInitialization();
    assertEquals(originalTarget.toString(), node.getString(optionName));
  }
}
