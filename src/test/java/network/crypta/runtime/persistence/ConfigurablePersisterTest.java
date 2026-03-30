package network.crypta.runtime.persistence;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeInitException;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    assertEquals(expectedTarget.getCanonicalFile(), cp.getPersistTarget().getCanonicalFile());
    assertEquals(expectedTemp.getCanonicalFile(), cp.getPersistTemp().getCanonicalFile());

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

    File notADir = new File(baseDir, "parentFile");
    assertTrue(notADir.createNewFile(), "setup: parentFile should be created");

    String defaultName = "parentFile" + File.separator + "child.txt";

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
    String expectedReason =
        NodeL10n.getBase().getString("ConfigurablePersister.doesNotExistCannotCreate");
    assertTrue(msg.contains(expectedReason), msg);
    assertTrue(msg.contains(".tmp"), msg);
  }

  @Test
  void set_whenChangeToNewValidPath_updatesTargetsAndCreatesFiles() throws Exception {
    // Arrange
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

    // Act
    Option<?> opt = node.getOption(optionName);
    opt.setValue(newTarget.toString());

    // Assert
    File expectedTemp = new File(newTarget + ".tmp");
    assertTrue(newTarget.exists(), "new target should be created");
    assertTrue(expectedTemp.exists(), "new temp should be created");
    assertEquals(newTarget.getCanonicalFile(), cp.getPersistTarget().getCanonicalFile());
    assertEquals(expectedTemp.getCanonicalFile(), cp.getPersistTemp().getCanonicalFile());

    node.finishedInitialization();
    assertEquals(newTarget.toString(), node.getString(optionName));
  }

  @Test
  void set_whenChangeToInvalidPath_throwsInvalidConfigValueAndDoesNotChangeTargets()
      throws Exception {
    // Arrange
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

    File originalTarget = cp.getPersistTarget();

    File parentIsFile = new File(baseDir, "not-a-dir");
    assertTrue(parentIsFile.createNewFile(), "setup: not-a-dir should be created");
    String badPath = new File(parentIsFile, "child.txt").toString();

    // Act + Assert
    Option<?> opt = node.getOption(optionName);
    assertThrows(InvalidConfigValueException.class, () -> opt.setValue(badPath));
    assertEquals(originalTarget.getCanonicalFile(), cp.getPersistTarget().getCanonicalFile());

    node.finishedInitialization();
    assertEquals(originalTarget.toString(), node.getString(optionName));
  }
}
