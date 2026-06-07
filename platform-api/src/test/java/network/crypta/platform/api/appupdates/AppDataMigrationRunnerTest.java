package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppDataMigrationCommand;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppDataMigrationRunnerTest {
  private static final String BUNDLE_DIRECTORY = "bundle";
  private static final String MIGRATION_SCRIPT = "migrate.sh";
  private static final String NAMESPACE = "feeds";
  private static final String PAYLOADS_DIRECTORY = "payloads";

  @TempDir private Path tempDir;

  @Test
  void run_whenOnlyProcessGroupCleanupCouldBeBypassed_expectFailsClosedBeforeCommand()
      throws Exception {
    Path bundleRoot = tempDir.resolve(BUNDLE_DIRECTORY);
    Path binDirectory = bundleRoot.resolve("bin");
    Files.createDirectories(binDirectory);
    Path script = binDirectory.resolve(MIGRATION_SCRIPT);
    Files.writeString(
        script,
        """
        #!/bin/sh
        touch ran
        setsid sh -c 'sleep 10' >/dev/null 2>&1 &
        printf '{}' > "$CRYPTA_APP_MIGRATION_OUTPUT"
        exit 0
        """);
    assertTrue(script.toFile().setExecutable(true));
    AppDataMigrationRunner runner =
        new AppDataMigrationRunner.LocalProcessMigrationRunner(
            Duration.ofSeconds(3), new AppEnv(Map.of("PATH", "/usr/bin:/bin"), "Linux"));

    try (TestMigrationDataAccess dataAccess =
        new TestMigrationDataAccess(tempDir.resolve(PAYLOADS_DIRECTORY))) {
      IOException exception =
          assertThrows(
              IOException.class,
              () ->
                  runner.run(
                      bundleRoot, migrationPlan(), AppDataMigrationRunner.Mode.APPLY, dataAccess));

      assertEquals("migration process containment is unavailable", exception.getMessage());
      assertFalse(dataAccess.completed());
    }
    assertFalse(Files.exists(bundleRoot.resolve("ran")));
  }

  @Test
  void run_whenProcessBoundaryUnavailable_expectFailsClosedBeforeCommand() throws Exception {
    Path bundleRoot = tempDir.resolve(BUNDLE_DIRECTORY);
    Path binDirectory = bundleRoot.resolve("bin");
    Files.createDirectories(binDirectory);
    Path script = binDirectory.resolve(MIGRATION_SCRIPT);
    Files.writeString(
        script,
        """
        #!/bin/sh
        touch ran
        printf '{}' > "$CRYPTA_APP_MIGRATION_OUTPUT"
        exit 0
        """);
    assertTrue(script.toFile().setExecutable(true));
    AppDataMigrationRunner runner =
        new AppDataMigrationRunner.LocalProcessMigrationRunner(
            Duration.ofSeconds(3), new AppEnv(Map.of("PATH", "/usr/bin:/bin"), "Windows 11"));

    try (TestMigrationDataAccess dataAccess =
        new TestMigrationDataAccess(tempDir.resolve(PAYLOADS_DIRECTORY))) {
      assertThrows(
          IOException.class,
          () ->
              runner.run(
                  bundleRoot, migrationPlan(), AppDataMigrationRunner.Mode.APPLY, dataAccess));

      assertFalse(dataAccess.completed());
    }
    assertFalse(Files.exists(bundleRoot.resolve("ran")));
  }

  @Test
  void run_whenMigrationCommandIsNotExecutable_expectFailsBeforeCompletion() throws Exception {
    Path bundleRoot = tempDir.resolve(BUNDLE_DIRECTORY);
    Path binDirectory = bundleRoot.resolve("bin");
    Files.createDirectories(binDirectory);
    Path script = binDirectory.resolve(MIGRATION_SCRIPT);
    Files.writeString(
        script,
        """
        #!/bin/sh
        touch ran
        printf '{}' > "$CRYPTA_APP_MIGRATION_OUTPUT"
        exit 0
        """);
    Assumptions.assumeTrue(script.toFile().setExecutable(false, false));
    Assumptions.assumeFalse(Files.isExecutable(script));
    AppDataMigrationRunner runner =
        new AppDataMigrationRunner.LocalProcessMigrationRunner(Duration.ofSeconds(3));

    try (TestMigrationDataAccess dataAccess =
        new TestMigrationDataAccess(tempDir.resolve(PAYLOADS_DIRECTORY))) {
      IOException exception =
          assertThrows(
              IOException.class,
              () ->
                  runner.run(
                      bundleRoot, migrationPlan(), AppDataMigrationRunner.Mode.APPLY, dataAccess));

      assertEquals("migration command is not executable", exception.getMessage());
      assertFalse(dataAccess.completed());
    }
    assertFalse(Files.exists(bundleRoot.resolve("ran")));
  }

  private static AppDataMigrationPlan migrationPlan() {
    return AppDataMigrationPlan.ready(
        1,
        2,
        List.of(
            new AppDataMigrationPlan.NamespaceStep(
                NAMESPACE,
                1,
                2,
                "feeds-v1-v2",
                true,
                false,
                "Upgrade feed records.",
                new AppDataMigrationCommand("bin/migrate.sh"))));
  }

  private static final class TestMigrationDataAccess
      implements AppDataMigrationRunner.MigrationDataAccess {
    private final Path root;
    private boolean completed;

    private TestMigrationDataAccess(Path root) {
      this.root = root;
    }

    @Override
    public AppDataMigrationRunner.StepDataFiles prepare(
        AppDataMigrationPlan.NamespaceStep step, AppDataMigrationRunner.Mode mode)
        throws IOException {
      Files.createDirectories(root);
      Path inputPayload = root.resolve("input.json");
      Path outputPayload = root.resolve("output.json");
      Files.writeString(inputPayload, "{}");
      return new AppDataMigrationRunner.StepDataFiles(inputPayload, outputPayload);
    }

    @Override
    public void complete(
        AppDataMigrationPlan.NamespaceStep step,
        AppDataMigrationRunner.Mode mode,
        AppDataMigrationRunner.StepDataFiles files) {
      completed = true;
    }

    @Override
    public void close() {
      // Test payload files live under @TempDir and no external handles are retained.
    }

    private boolean completed() {
      return completed;
    }
  }
}
