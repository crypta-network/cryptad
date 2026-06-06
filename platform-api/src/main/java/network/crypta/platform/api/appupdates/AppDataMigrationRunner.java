package network.crypta.platform.api.appupdates;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import network.crypta.fs.AppEnv;

/**
 * Executes signed app-data migration entrypoints for the app update lifecycle.
 *
 * <p>The runner is intentionally narrow: it receives a verified bundle root, an immutable migration
 * plan, a dry-run or apply mode, and a scoped app-data channel supplied by {@link
 * AppUpdateService}. It does not parse shell fragments or invent command arguments from manifest
 * text. Each command is resolved as a relative bundle path and receives fixed environment variables
 * that point at bounded input and output payload files.
 *
 * <p>Implementations must fail closed. A required migration cannot be treated as successful when
 * command launch, data preparation, process containment, timeout handling, output validation, or
 * commit work is unavailable. The public result carries only path-free status fields and an exit
 * code; raw stdout, stderr, tokens, and app-data values stay out of update summaries.
 */
@FunctionalInterface
public interface AppDataMigrationRunner {
  /** Default wall-clock timeout applied independently to each migration step. */
  Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

  /** Maximum command output bytes drained before diagnostics are discarded. */
  int MAX_CAPTURE_BYTES = 4096;

  /** Grace period, in milliseconds, used between process-group termination probes. */
  long PROCESS_GROUP_TERMINATE_GRACE_MILLIS = 500L;

  /** Maximum time, in milliseconds, to wait for stdout/stderr drain after cleanup. */
  long OUTPUT_DRAIN_TIMEOUT_MILLIS = 500L;

  /**
   * Runs all steps in a migration plan for one bundle root.
   *
   * <p>The runner calls {@link MigrationDataAccess#prepare(AppDataMigrationPlan.NamespaceStep,
   * Mode)} before launching each step and calls {@link MigrationDataAccess#complete(
   * AppDataMigrationPlan.NamespaceStep, Mode, StepDataFiles)} only after the command exits
   * successfully and remains inside the intended lifecycle boundary. Implementations stop at the
   * first failed step and return a path-free failure result.
   *
   * @param bundleRoot staged or installed bundle root used for relative command resolution
   * @param plan migration plan to execute in declared namespace-step order
   * @param mode dry-run or apply mode passed to each command
   * @param dataAccess scoped app-data input/output channel for migration commands
   * @return path-free execution result for the completed or failed migration sequence
   * @throws IOException if the runner cannot inspect, contain, or execute the command safely
   */
  MigrationExecutionResult run(
      Path bundleRoot, AppDataMigrationPlan plan, Mode mode, MigrationDataAccess dataAccess)
      throws IOException;

  /**
   * Returns the production runner.
   *
   * <p>The local runner requires process-group containment support before it will launch app-owned
   * migration code. On hosts where that boundary is unavailable, migration execution fails closed
   * and the update lifecycle reports a stable blocker instead of silently skipping the migration.
   *
   * @return local process migration runner with the default per-step timeout
   */
  static AppDataMigrationRunner localProcess() {
    return new LocalProcessMigrationRunner(DEFAULT_TIMEOUT);
  }

  /**
   * Migration command execution mode exposed through {@code CRYPTA_APP_MIGRATION_MODE}.
   *
   * <p>Dry-run mode validates command behavior and output shape before bundle replacement. Apply
   * mode runs after the update lifecycle has prepared rollback state and is ready to commit the
   * migrated namespace payload.
   */
  enum Mode {
    /** Validate without mutating durable state. */
    DRY_RUN("dry-run"),

    /** Apply the durable state migration. */
    APPLY("apply");

    /** Environment-variable value passed to the migration command. */
    private final String environmentValue;

    /**
     * Creates a mode with the exact environment value given to migration commands.
     *
     * @param environmentValue stable mode string used in the command environment
     */
    Mode(String environmentValue) {
      this.environmentValue = environmentValue;
    }

    /**
     * Returns the command-facing mode value.
     *
     * @return stable value for {@code CRYPTA_APP_MIGRATION_MODE}
     */
    String environmentValue() {
      return environmentValue;
    }
  }

  /**
   * Path-free migration execution result.
   *
   * <p>The result is safe to fold into lifecycle state because it contains only a boolean outcome,
   * a stable status string, and the direct process exit code when one exists. Timeout and
   * containment failures use a {@code null} exit code because no trustworthy command status is
   * available.
   *
   * @param success whether every requested migration step completed successfully
   * @param status stable path-free status string for lifecycle handling
   * @param exitCode direct command exit code, or {@code null} for timeout or containment failure
   */
  record MigrationExecutionResult(boolean success, String status, Integer exitCode) {
    /**
     * Creates a result.
     *
     * @param success whether the migration runner completed every requested step
     * @param status stable non-blank status string for lifecycle state
     * @param exitCode direct command exit code, or {@code null} when unavailable
     */
    public MigrationExecutionResult {
      status = Objects.requireNonNull(status, "status").trim();
      if (status.isEmpty()) {
        throw new IllegalArgumentException("status must not be blank");
      }
    }

    /**
     * Returns a successful migration result.
     *
     * @return path-free success result with a zero exit code
     */
    static MigrationExecutionResult passed() {
      return new MigrationExecutionResult(true, "passed", 0);
    }

    /**
     * Returns a failed migration result.
     *
     * @param exitCode direct command exit code, or {@code null} when no code is trustworthy
     * @return path-free failure result for update lifecycle handling
     */
    static MigrationExecutionResult failed(Integer exitCode) {
      return new MigrationExecutionResult(false, "failed", exitCode);
    }
  }

  /**
   * Scoped app-data input/output files for one migration step.
   *
   * <p>The files are generated by {@link MigrationDataAccess} and are exposed to the migration
   * command through environment variables. They are temporary payload channels, not durable backup
   * locations and not operator-facing paths.
   *
   * @param inputPayload payload file containing the exported namespace data for this step
   * @param outputPayload payload file the command must write with migrated namespace data
   */
  record StepDataFiles(Path inputPayload, Path outputPayload) {
    /**
     * Creates a validated file pair.
     *
     * @param inputPayload input payload path prepared before command execution
     * @param outputPayload output payload path expected after successful execution
     */
    public StepDataFiles {
      Objects.requireNonNull(inputPayload, "inputPayload");
      Objects.requireNonNull(outputPayload, "outputPayload");
    }
  }

  /**
   * Supplies bounded app-data payload files to migration commands and commits validated output.
   *
   * <p>The update service owns this channel so migration commands never receive ambient app-data
   * authority. Dry-run completion validates output without mutating durable state. Apply completion
   * imports the validated namespace payload under the update lifecycle's writing barrier.
   */
  interface MigrationDataAccess extends AutoCloseable {
    /**
     * Prepares input and output files for one migration command invocation.
     *
     * @param step namespace step being executed
     * @param mode dry-run or apply mode
     * @return input/output payload file paths for the command environment
     * @throws IOException when payload files cannot be prepared
     */
    StepDataFiles prepare(AppDataMigrationPlan.NamespaceStep step, Mode mode) throws IOException;

    /**
     * Validates or commits output written by a successful migration command.
     *
     * @param step namespace step that completed
     * @param mode dry-run or apply mode
     * @param files input/output payload file paths
     * @throws IOException when output cannot be inspected
     */
    void complete(AppDataMigrationPlan.NamespaceStep step, Mode mode, StepDataFiles files)
        throws IOException;

    /**
     * Releases temporary files or locks held by the scoped migration channel.
     *
     * @throws IOException when cleanup cannot complete after the migration attempt
     */
    @Override
    void close() throws IOException;
  }

  /**
   * Local short-lived process implementation used by production update flows.
   *
   * <p>The runner launches each signed command directly, never through a shell parser. It clears
   * the inherited environment, installs only the fixed migration variables, and requires a
   * process-group boundary so descendant processes cannot outlive the migration step. Unsupported
   * hosts fail before app-owned code is started.
   */
  final class LocalProcessMigrationRunner implements AppDataMigrationRunner {
    /** Per-step wall-clock timeout used for direct command execution. */
    private final Duration timeout;

    /** Host-specific process boundary used to launch and reap the command group. */
    private final ProcessBoundary processBoundary;

    /**
     * Creates a local process runner using the detected host environment.
     *
     * @param timeout per-step wall-clock timeout for each migration command
     */
    LocalProcessMigrationRunner(Duration timeout) {
      this(timeout, new AppEnv());
    }

    /**
     * Creates a local process runner with an explicit environment detector.
     *
     * @param timeout per-step wall-clock timeout for each migration command
     * @param appEnv environment helper used to detect process-group support
     */
    LocalProcessMigrationRunner(Duration timeout, AppEnv appEnv) {
      this.timeout = Objects.requireNonNull(timeout, "timeout");
      processBoundary = ProcessBoundary.detect(Objects.requireNonNull(appEnv, "appEnv"));
    }

    @Override
    public MigrationExecutionResult run(
        Path bundleRoot, AppDataMigrationPlan plan, Mode mode, MigrationDataAccess dataAccess)
        throws IOException {
      Path normalizedBundleRoot =
          Objects.requireNonNull(bundleRoot, "bundleRoot").toAbsolutePath().normalize();
      Objects.requireNonNull(plan, "plan");
      Objects.requireNonNull(mode, "mode");
      Objects.requireNonNull(dataAccess, "dataAccess");
      for (AppDataMigrationPlan.NamespaceStep step : plan.namespaces()) {
        StepDataFiles files = dataAccess.prepare(step, mode);
        MigrationExecutionResult result = runStep(normalizedBundleRoot, step, mode, files);
        if (!result.success()) {
          return result;
        }
        dataAccess.complete(step, mode, files);
      }
      return MigrationExecutionResult.passed();
    }

    /**
     * Runs one namespace migration command and validates its process lifecycle.
     *
     * <p>The command must exit before the timeout, and the process boundary must find no live
     * descendants after termination. If a descendant is still present, the runner fails the step
     * before the data-access channel can commit output.
     *
     * @param bundleRoot normalized bundle root used as the working directory
     * @param step namespace migration step being executed
     * @param mode dry-run or apply mode supplied to the command
     * @param files prepared input and output payload files for this step
     * @return path-free step execution result
     * @throws IOException when command launch or output capture cannot be trusted
     */
    private MigrationExecutionResult runStep(
        Path bundleRoot, AppDataMigrationPlan.NamespaceStep step, Mode mode, StepDataFiles files)
        throws IOException {
      Path command = resolveCommand(bundleRoot, step);
      ProcessBuilder builder = new ProcessBuilder(commandLine(command));
      builder.directory(bundleRoot.toFile());
      builder.redirectErrorStream(true);
      builder.environment().clear();
      builder.environment().putAll(environment(step, mode, files));
      Process process = builder.start();
      long processGroupId = process.pid();
      CompletableFuture<byte[]> output =
          CompletableFuture.supplyAsync(() -> readBoundedOutput(process.getInputStream()));
      try {
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
          processBoundary.terminateProcessGroup(processGroupId);
          output.cancel(true);
          return MigrationExecutionResult.failed(null);
        }
        boolean hadDetachedProcess = processBoundary.terminateProcessGroup(processGroupId);
        if (hadDetachedProcess) {
          output.get(OUTPUT_DRAIN_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
          return MigrationExecutionResult.failed(null);
        }
        output.get(OUTPUT_DRAIN_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        int exitCode = process.exitValue();
        if (exitCode != 0) {
          return MigrationExecutionResult.failed(exitCode);
        }
        return MigrationExecutionResult.passed();
      } catch (InterruptedException exception) {
        processBoundary.terminateProcessGroup(processGroupId);
        Thread.currentThread().interrupt();
        throw new IOException("migration process interrupted", exception);
      } catch (ExecutionException exception) {
        processBoundary.terminateProcessGroup(processGroupId);
        throw new IOException("migration output could not be captured", exception);
      } catch (TimeoutException _) {
        processBoundary.terminateProcessGroup(processGroupId);
        output.cancel(true);
        return MigrationExecutionResult.failed(null);
      }
    }

    /**
     * Resolves a signed migration command relative to the bundle root.
     *
     * @param bundleRoot normalized staged or installed bundle root
     * @param step namespace step whose command must be resolved
     * @return regular non-symlink command path inside {@code bundleRoot}
     * @throws IOException when the command escapes the bundle or is not a regular file
     */
    private static Path resolveCommand(Path bundleRoot, AppDataMigrationPlan.NamespaceStep step)
        throws IOException {
      Path command = bundleRoot.resolve(step.command().path()).normalize();
      if (!command.startsWith(bundleRoot)
          || Files.isSymbolicLink(command)
          || !Files.isRegularFile(command, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException("migration command is not a safe bundle file");
      }
      return command;
    }

    /**
     * Builds the direct process command line for a validated executable.
     *
     * @param command command path already resolved inside the bundle root
     * @return process-boundary command line used by {@link ProcessBuilder}
     * @throws IOException when executability or process containment is unavailable
     */
    private List<String> commandLine(Path command) throws IOException {
      if (!Files.isExecutable(command)) {
        throw new IOException("migration command is not executable");
      }
      return processBoundary.commandLine(command);
    }

    /**
     * Builds the sanitized environment for one migration command.
     *
     * @param step namespace migration step being executed
     * @param mode dry-run or apply mode exposed to the command
     * @param files scoped input and output payload files for this step
     * @return environment map containing only fixed migration variables and a minimal path
     */
    private static Map<String, String> environment(
        AppDataMigrationPlan.NamespaceStep step, Mode mode, StepDataFiles files) {
      LinkedHashMap<String, String> environment = new LinkedHashMap<>();
      environment.put("CRYPTA_APP_MIGRATION_MODE", mode.environmentValue());
      environment.put("CRYPTA_APP_MIGRATION_NAMESPACE", step.namespace());
      environment.put("CRYPTA_APP_MIGRATION_FROM", Integer.toString(step.fromSchemaVersion()));
      environment.put("CRYPTA_APP_MIGRATION_TO", Integer.toString(step.toSchemaVersion()));
      environment.put("CRYPTA_APP_MIGRATION_STEP_ID", step.stepId());
      environment.put("CRYPTA_APP_MIGRATION_INPUT", files.inputPayload().toString());
      environment.put("CRYPTA_APP_MIGRATION_OUTPUT", files.outputPayload().toString());
      environment.put("PATH", "/usr/bin:/bin");
      return environment;
    }

    /**
     * Drains command output without storing unbounded diagnostics.
     *
     * <p>The return value is currently used only to ensure pipes drain before cleanup completes.
     * Captured bytes are bounded and not exposed in public migration summaries.
     *
     * @param input process output stream to drain
     * @return bounded UTF-8-normalized bytes read before EOF or failure
     */
    private static byte[] readBoundedOutput(InputStream input) {
      try (InputStream source = input;
          ByteArrayOutputStream sink = new ByteArrayOutputStream()) {
        byte[] buffer = new byte[512];
        int total = 0;
        int read;
        while ((read = source.read(buffer)) >= 0) {
          if (total < MAX_CAPTURE_BYTES) {
            int accepted = Math.min(read, MAX_CAPTURE_BYTES - total);
            sink.write(buffer, 0, accepted);
            total += accepted;
          }
        }
        return sink.toString(StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8);
      } catch (IOException _) {
        return new byte[0];
      }
    }

    /**
     * Linux process-group boundary used to contain migration commands.
     *
     * <p>The boundary launches commands through {@code setsid} and later addresses the negative
     * process-group id with {@code kill}. If either tool is unavailable, the runner refuses to
     * launch migration commands because descendant processes could escape the update lifecycle.
     *
     * @param supported whether this host has the required process-group tooling
     * @param setsidCommand absolute path to {@code setsid}, or blank when unsupported
     * @param killCommand absolute path to {@code kill}, or blank when unsupported
     */
    private record ProcessBoundary(boolean supported, String setsidCommand, String killCommand) {
      /**
       * Detects whether the current host supports process-group migration containment.
       *
       * @param appEnv environment helper used for platform and command lookup checks
       * @return supported boundary when Linux {@code setsid} and {@code kill} are available
       */
      private static ProcessBoundary detect(AppEnv appEnv) {
        if (!appEnv.isLinux() || !appEnv.onPath("setsid") || !appEnv.onPath("kill")) {
          return unsupported();
        }
        String setsid = commandPath("setsid");
        String kill = commandPath("kill");
        if (setsid == null || kill == null) {
          return unsupported();
        }
        return new ProcessBoundary(true, setsid, kill);
      }

      /**
       * Returns a boundary that fails closed before command execution.
       *
       * @return unsupported process boundary with no command paths
       */
      private static ProcessBoundary unsupported() {
        return new ProcessBoundary(false, "", "");
      }

      /**
       * Resolves a supported process-control command from deterministic system locations.
       *
       * @param command command basename to resolve
       * @return executable absolute command path, or {@code null} when unavailable
       */
      private static String commandPath(String command) {
        for (Path candidate : List.of(Path.of("/usr/bin", command), Path.of("/bin", command))) {
          if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
            return candidate.toString();
          }
        }
        return null;
      }

      /**
       * Builds the process command line that starts a fresh process group.
       *
       * @param command validated migration command inside the bundle root
       * @return direct command line headed by {@code setsid}
       * @throws IOException when the host cannot provide process-group containment
       */
      private List<String> commandLine(Path command) throws IOException {
        if (!supported) {
          throw new IOException("migration process-group isolation is unavailable");
        }
        return List.of(setsidCommand, command.toString());
      }

      /**
       * Terminates the migration process group and reports whether a group existed.
       *
       * @param processGroupId process id of the launched command's process group leader
       * @return {@code true} when a process group was signaled, including detached descendants
       */
      private boolean terminateProcessGroup(long processGroupId) {
        if (!supported) {
          return false;
        }
        boolean signaled = sendSignal("TERM", processGroupId);
        if (!signaled) {
          return false;
        }
        waitForProcessGroupExit(processGroupId);
        if (processGroupAlive(processGroupId)) {
          sendSignal("KILL", processGroupId);
          waitForProcessGroupExit(processGroupId);
        }
        return true;
      }

      /**
       * Checks whether the migration process group still has live members.
       *
       * @param processGroupId process group id to probe
       * @return {@code true} when the group exists according to {@code kill -0}
       */
      private boolean processGroupAlive(long processGroupId) {
        return runKillCommand(List.of("-0", "--", "-" + processGroupId));
      }

      /**
       * Sends a POSIX signal to the migration process group.
       *
       * @param signal signal name without the leading dash
       * @param processGroupId process group id to signal
       * @return {@code true} when the signal command reports success
       */
      private boolean sendSignal(String signal, long processGroupId) {
        return runKillCommand(List.of("-" + signal, "--", "-" + processGroupId));
      }

      /**
       * Runs the configured {@code kill} command with bounded waiting and drained output.
       *
       * @param arguments command arguments appended after the {@code kill} executable
       * @return {@code true} when the command exits with code zero before the grace deadline
       */
      private boolean runKillCommand(List<String> arguments) {
        try {
          return runStartedKillCommand(arguments);
        } catch (IOException _) {
          return false;
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return false;
        }
      }

      /**
       * Starts and waits for one {@code kill} command invocation.
       *
       * <p>The process is definitely available inside this helper, so interruption cleanup can
       * forcibly stop it without nullable state.
       *
       * @param arguments command arguments appended after the {@code kill} executable
       * @return {@code true} when the command exits with code zero before the grace deadline
       * @throws IOException when the command cannot start or output cannot drain
       * @throws InterruptedException when interrupted while draining or waiting
       */
      private boolean runStartedKillCommand(List<String> arguments)
          throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(killCommand);
        builder.command().addAll(arguments);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        try {
          try (InputStream output = process.getInputStream()) {
            output.transferTo(OutputStream.nullOutputStream());
          }
          if (!process.waitFor(PROCESS_GROUP_TERMINATE_GRACE_MILLIS, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            return false;
          }
          return process.exitValue() == 0;
        } catch (InterruptedException exception) {
          process.destroyForcibly();
          throw exception;
        }
      }

      /**
       * Waits briefly for a migration process group to disappear.
       *
       * @param processGroupId process group id to poll until it exits or the grace deadline expires
       */
      private void waitForProcessGroupExit(long processGroupId) {
        long deadlineNanos =
            System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(PROCESS_GROUP_TERMINATE_GRACE_MILLIS);
        while (processGroupAlive(processGroupId)) {
          long remainingNanos = deadlineNanos - System.nanoTime();
          if (remainingNanos <= 0L) {
            return;
          }
          try {
            TimeUnit.MILLISECONDS.sleep(
                Math.clamp(TimeUnit.NANOSECONDS.toMillis(remainingNanos), 1L, 25L));
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            return;
          }
        }
      }
    }
  }
}
