package network.crypta.node;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import network.crypta.fs.Dirs;
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
 * <p>Provides standard help/version flags and clear options for directory overrides and service
 * mode.
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

  public static class ModeShortcuts {
    @Option(
        names = {"--service", "--daemon"},
        description = {"Shortcut for --service-mode=service"})
    public boolean service;

    @Option(
        names = {"--user", "--app"},
        description = {"Shortcut for --service-mode=user"})
    public boolean user;
  }

  /** Resolve the explicit config file if provided via either channel. */
  public File explicitConfigFile() {
    return configFileOpt != null ? configFileOpt : configFilePositional;
  }

  /** Copy directory overrides into a mutable map for AppDirs. */
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

  /** Compute the service mode override based on flags, or null. */
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

  /** Provides a richer, dynamic version string. */
  public static class CryptadVersionProvider implements IVersionProvider {
    @Override
    public String[] getVersion() {
      return new String[] {
        Version.NODE_NAME + " " + Version.currentBuildNumber() + " (" + Version.gitRevision() + ")",
        "Protocol: " + Version.LAST_GOOD_FRED_PROTOCOL_VERSION,
        "Wire: " + Version.getVersionString(),
      };
    }
  }

  /** Pretty exception handler for picocli usage errors. */
  public static class PrettyExceptionHandler implements IExecutionExceptionHandler {
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
