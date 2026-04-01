package network.crypta.runtime.bootstrap;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import network.crypta.fs.Dirs;
import network.crypta.node.Version;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.ExitCode;
import picocli.CommandLine.IExecutionExceptionHandler;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParseResult;
import picocli.CommandLine;

/**
 * Command line options for the Cryptad daemon.
 *
 * <p>This type is the top-level picocli command model used to parse daemon startup arguments. It
 * exposes fields for explicit directory overrides, service-mode selection, and optional
 * configuration-file selection through both named and positional options. After parsing, callers
 * consume the normalized helper methods to translate raw command-line values into values used by
 * node startup wiring.
 *
 * <p>Instances are mutable during argument parsing and then typically treated as read-only for the
 * remainder of the startup. The class performs lightweight validation for service-mode input and
 * throws a picocli {@link ParameterException} with usage context when the supplied value is
 * invalid. Directory override keys intentionally match the names expected by app-directory
 * resolution code.
 */
@Command(
    name = Dirs.APP_RUNTIME_SUBPATH,
    mixinStandardHelpOptions = true,
    usageHelpAutoWidth = true,
    sortOptions = false,
    showDefaultValues = true,
    header = {"Crypta: Distributed, encrypted, censorship-resistant datastore", ""},
    descriptionHeading = "Description:%n",
    description = {
      "Runs the Crypta reference daemon, the core peer-to-peer node.",
      "",
      "By default the node resolves standard platform directories and the",
      "configuration file \"cryptad.ini\" under the resolved config dir.",
      "Use the options below to override directories or select service mode."
    },
    synopsisHeading = "Usage:%n",
    optionListHeading = "Options:%n",
    parameterListHeading = "Parameters:%n",
    footerHeading = "%nExamples:%n",
    footer = {
      "  Show help:          cryptad --help",
      "  Show version:       cryptad --version",
      "  Use config file:    cryptad -c /etc/cryptad/cryptad.ini",
      "  Override dirs:      cryptad --config-dir ~/.config/cryptad --data-dir"
          + " ~/.local/share/cryptad",
      "  Force service mode: cryptad --service",
      "  Force user mode:    cryptad --user"
    },
    versionProvider = NodeCli.CryptadVersionProvider.class)
public class NodeCli {
  /**
   * Creates a mutable CLI option model for one parse operation.
   *
   * <p>Picocli populates fields on this instance directly while parsing command-line arguments.
   */
  public NodeCli() {
    // Intentionally empty: picocli instantiates and populates this option holder reflectively.
  }

  /** Optional explicit config file path (flag). */
  @Option(
      names = {"-c", "--config-file"},
      paramLabel = "FILE",
      description = {"Path to configuration file (cryptad.ini). Overrides --config-dir."})
  private File configFileOpt = null;

  /** Optional explicit config file path (positional). */
  @Parameters(
      arity = "0..1",
      paramLabel = "FILE",
      description = {
        "Optional positional configuration file (cryptad.ini). Same as --config-file."
      })
  private File configFilePositional = null;

  /** Override the config directory where cryptad.ini is located. */
  @Option(
      names = {"-C", "--config-dir"},
      paramLabel = "PATH",
      description = {"Override configuration directory where cryptad.ini is located."})
  public String configDir;

  /** Override the data directory. */
  @Option(
      names = {"-d", "--data-dir"},
      paramLabel = "PATH",
      description = {"Override data directory (datastores, persistent state)."})
  public String dataDir;

  /** Override the cache directory. */
  @Option(
      names = {"-x", "--cache-dir"},
      paramLabel = "PATH",
      description = {"Override cache directory (temporary files, caches)."})
  public String cacheDir;

  /** Override the run directory (PID, sockets, etc.). */
  @Option(
      names = {"-r", "--run-dir"},
      paramLabel = "PATH",
      description = {"Override run directory (PID, sockets, runtime files)."})
  public String runDir;

  /** Override the logs' directory. */
  @Option(
      names = {"-L", "--logs-dir"},
      paramLabel = "PATH",
      description = {"Override logs directory (log files destination)."})
  public String logsDir;

  /** Choose a service mode explicitly. */
  @Option(
      names = {"-m", "--service-mode"},
      paramLabel = "MODE",
      description = {
        "Service mode selection: 'service' or 'user'.",
        "If omitted, mode is auto-detected from environment."
      })
  public String serviceMode;

  /** Shortcut flags for service/user modes. */
  @ArgGroup() public ModeShortcuts modeShortcuts;

  /**
   * Mutually exclusive shortcut switches that map directly to {@code --service-mode}.
   *
   * <p>These flags exist to provide concise command-line ergonomics for common launch scenarios
   * while preserving a single normalized mode value used by startup logic.
   */
  public static class ModeShortcuts {
    /** Creates an empty shortcut container populated by picocli during parsing. */
    public ModeShortcuts() {
      // Intentionally empty: picocli writes shortcut-flag fields after construction.
    }

    /** Forces service-managed mode, equivalent to {@code --service-mode=service}. */
    @Option(
        names = {"--service", "--daemon"},
        description = {"Shortcut for --service-mode=service"})
    public boolean service;

    /** Forces interactive user mode, equivalent to {@code --service-mode=user}. */
    @Option(
        names = {"--user", "--app"},
        description = {"Shortcut for --service-mode=user"})
    public boolean user;
  }

  /**
   * Resolves the explicitly requested configuration file path.
   *
   * <p>The named option {@code --config-file} takes precedence over the optional positional file
   * argument when both are present. If neither channel supplies a file path, this method returns
   * {@code null} and callers should continue with default config-path resolution.
   *
   * @return the chosen explicit configuration file path, or {@code null} when not provided
   */
  public File explicitConfigFile() {
    return configFileOpt != null ? configFileOpt : configFilePositional;
  }

  /**
   * Collects non-null directory override options into a mutable map.
   *
   * <p>The returned map only includes keys for options that were explicitly passed by the user.
   * Keys are inserted in a stable order matching option declaration order to keep diagnostics and
   * downstream processing deterministic. Callers may safely mutate the returned map without
   * affecting this CLI object.
   *
   * @return a new map containing user-supplied directory override entries
   */
  public Map<String, String> directoryOverrides() {
    Map<String, String> out = new LinkedHashMap<>();
    if (configDir != null) {
      out.put("configDir", configDir);
    }
    if (dataDir != null) {
      out.put("dataDir", dataDir);
    }
    if (cacheDir != null) {
      out.put("cacheDir", cacheDir);
    }
    if (runDir != null) {
      out.put("runDir", runDir);
    }
    if (logsDir != null) {
      out.put("logsDir", logsDir);
    }
    return out;
  }

  /**
   * Computes a normalized service-mode override from explicit options.
   *
   * <p>If {@code --service-mode} is present, accepted values are {@code service} and {@code user}
   * (case-insensitive). If that option is absent, shortcut flags are evaluated. When no mode option
   * is provided, this method returns {@code null} to indicate environment-based auto-detection.
   *
   * @return {@code "service"}, {@code "user"}, or {@code null} when no explicit override exists
   * @throws ParameterException if {@code --service-mode} is supplied with an unsupported value
   */
  public String serviceModeOverride() {
    if (serviceMode != null) {
      String m = serviceMode.toLowerCase(Locale.ROOT);
      if ("service".equals(m) || "user".equals(m)) {
        return m;
      }
      throw new ParameterException(
          new CommandLine(this), "--service-mode must be either 'service' or 'user'");
    }
    if (modeShortcuts != null) {
      if (modeShortcuts.service) {
        return "service";
      }
      if (modeShortcuts.user) {
        return "user";
      }
    }
    return null;
  }

  /**
   * Produces CLI version output using runtime build metadata.
   *
   * <p>The provider format includes node name/build identity and protocol compatibility values, so
   * support tooling and operators can quickly verify the running binary.
   */
  public static class CryptadVersionProvider implements IVersionProvider {
    /** Creates a provider instance used by picocli when rendering {@code --version}. */
    public CryptadVersionProvider() {
      // Intentionally empty: stateless provider used by picocli's version rendering hook.
    }

    /**
     * Returns the lines printed for the {@code --version} option.
     *
     * @return an ordered array of human-readable version and protocol detail lines
     */
    @Override
    public String[] getVersion() {
      return new String[] {
        Version.NODE_NAME + " " + Version.currentBuildNumber() + " (" + Version.gitRevision() + ")",
        "Protocol: " + Version.LAST_GOOD_FRED_PROTOCOL_VERSION,
        "Wire: " + Version.getVersionString(),
      };
    }
  }

  /**
   * Renders user-friendly error output for command-line usage failures.
   *
   * <p>When parsing or execution fails, this handler writes the error message and usage synopsis to
   * stderr and returns picocli's usage exit code.
   */
  public static class PrettyExceptionHandler implements IExecutionExceptionHandler {
    /** Creates an exception handler instance for command execution. */
    public PrettyExceptionHandler() {
      // Intentionally empty: this handler is stateless and only exposes behavior via interface
      // methods.
    }

    /**
     * Writes the failure message and usage text, then returns a usage error code.
     *
     * @param ex the thrown exception describing the failure; may be {@code null}
     * @param commandLine the active command instance used to get configured output and usage
     * @param parseResult parse metadata for the current invocation; provided by picocli
     * @return {@link ExitCode#USAGE} to signal a command-line usage error
     */
    @Override
    @SuppressWarnings("java:S106")
    public int handleExecutionException(
        Exception ex, CommandLine commandLine, ParseResult parseResult) {
      PrintWriter out =
          commandLine != null
              ? commandLine.getErr()
              : new PrintWriter(System.err, false, StandardCharsets.UTF_8);
      out.println("Error: " + (ex != null ? ex.getMessage() : null));
      out.println();
      if (commandLine != null) {
        commandLine.usage(out);
      }
      out.flush();
      return ExitCode.USAGE;
    }
  }
}
