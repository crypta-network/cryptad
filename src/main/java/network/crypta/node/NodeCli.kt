package network.crypta.node

import java.io.PrintWriter
import network.crypta.fs.APP_RUNTIME_SUBPATH
import picocli.CommandLine
import picocli.CommandLine.*

/**
 * Command line options for the Cryptad daemon.
 *
 * Provides a user-friendly CLI with standard help/version flags and clear options for configuring
 * directory overrides and service mode.
 *
 * Usage examples:
 * - Print help: `cryptad --help`
 * - Print version: `cryptad --version`
 * - Use explicit config file: `cryptad -c /path/to/cryptad.ini`
 * - Override dirs: `cryptad --config-dir ~/.config/cryptad --data-dir ~/.local/share/cryptad`
 * - Force service mode: `cryptad --service` or `cryptad --service-mode=service`
 */
@Command(
  name = APP_RUNTIME_SUBPATH,
  mixinStandardHelpOptions = true,
  usageHelpAutoWidth = true,
  sortOptions = false,
  showDefaultValues = true,
  header = ["Crypta: Distributed, encrypted, censorship-resistant datastore", ""],
  descriptionHeading = "Description:%n",
  description =
    [
      "Runs the Crypta reference daemon, the core peer-to-peer node.",
      "",
      "By default the node resolves standard platform directories and the",
      "configuration file \"cryptad.ini\" under the resolved config dir.",
      "Use the options below to override directories or select service mode.",
    ],
  synopsisHeading = "Usage:%n",
  optionListHeading = "Options:%n",
  parameterListHeading = "Parameters:%n",
  footerHeading = "%nExamples:%n",
  footer =
    [
      "  Show help:          cryptad --help",
      "  Show version:       cryptad --version",
      "  Use config file:    cryptad -c /etc/cryptad/cryptad.ini",
      "  Override dirs:      cryptad --config-dir ~/.config/cryptad --data-dir ~/.local/share/cryptad",
      "  Force service mode: cryptad --service",
      "  Force user mode:    cryptad --user",
    ],
  versionProvider = NodeCli.CryptadVersionProvider::class,
)
class NodeCli {

  /** Optional explicit config file path (flag). */
  @Option(
    names = ["-c", "--config-file"],
    paramLabel = "FILE",
    description = ["Path to configuration file (cryptad.ini). Overrides --config-dir."],
  )
  var configFileOpt: java.io.File? = null

  /** Optional explicit config file path (positional). */
  @Parameters(
    arity = "0..1",
    paramLabel = "FILE",
    description = ["Optional positional configuration file (cryptad.ini). Same as --config-file."],
  )
  var configFilePositional: java.io.File? = null

  /** Override the config directory where cryptad.ini is located. */
  @Option(
    names = ["-C", "--config-dir"],
    paramLabel = "PATH",
    description = ["Override configuration directory where cryptad.ini is located."],
  )
  var configDir: String? = null

  /** Override the data directory. */
  @Option(
    names = ["-d", "--data-dir"],
    paramLabel = "PATH",
    description = ["Override data directory (datastores, persistent state)."],
  )
  var dataDir: String? = null

  /** Override the cache directory. */
  @Option(
    names = ["-x", "--cache-dir"],
    paramLabel = "PATH",
    description = ["Override cache directory (temporary files, caches)."],
  )
  var cacheDir: String? = null

  /** Override the run directory (PID, sockets, etc.). */
  @Option(
    names = ["-r", "--run-dir"],
    paramLabel = "PATH",
    description = ["Override run directory (PID, sockets, runtime files)."],
  )
  var runDir: String? = null

  /** Override the logs directory. */
  @Option(
    names = ["-L", "--logs-dir"],
    paramLabel = "PATH",
    description = ["Override logs directory (log files destination)."],
  )
  var logsDir: String? = null

  /** Choose service mode explicitly. */
  @Option(
    names = ["-m", "--service-mode"],
    paramLabel = "MODE",
    description =
      [
        "Service mode selection: 'service' or 'user'.",
        "If omitted, mode is auto-detected from environment.",
      ],
  )
  var serviceMode: String? = null

  /** Shortcut flags for service/user modes. */
  @ArgGroup(exclusive = true, multiplicity = "0..1") var modeShortcuts: ModeShortcuts? = null

  class ModeShortcuts {
    @Option(
      names = ["--service", "--daemon"],
      description = ["Shortcut for --service-mode=service"],
    )
    var service: Boolean = false
    @Option(names = ["--user", "--app"], description = ["Shortcut for --service-mode=user"])
    var user: Boolean = false
  }

  /** Resolve the explicit config file if provided via either channel. */
  fun explicitConfigFile(): java.io.File? = configFileOpt ?: configFilePositional

  /** Copy directory overrides into a mutable map for AppDirs. */
  fun directoryOverrides(): MutableMap<String, String> =
    mutableMapOf<String, String>().apply {
      configDir?.let { put("configDir", it) }
      dataDir?.let { put("dataDir", it) }
      cacheDir?.let { put("cacheDir", it) }
      runDir?.let { put("runDir", it) }
      logsDir?.let { put("logsDir", it) }
    }

  /** Compute the service mode override based on flags, or null. */
  fun serviceModeOverride(): String? {
    serviceMode?.let { mode ->
      val m = mode.lowercase()
      if (m == "service" || m == "user") return m
      throw ParameterException(
        CommandLine(this),
        "--service-mode must be either 'service' or 'user'",
      )
    }
    modeShortcuts?.let { sc ->
      if (sc.service) return "service"
      if (sc.user) return "user"
    }
    return null
  }

  /** Provides a richer, dynamic version string. */
  class CryptadVersionProvider : IVersionProvider {
    override fun getVersion(): Array<String> =
      arrayOf(
        "$NODE_NAME ${currentBuildNumber()} (${gitRevision()})",
        "Protocol: $LAST_GOOD_FRED_PROTOCOL_VERSION",
        "Wire: ${getVersionString()}",
      )
  }

  /** Pretty exception handler for picocli usage errors. */
  class PrettyExceptionHandler : IExecutionExceptionHandler {
    override fun handleExecutionException(
      ex: Exception?,
      commandLine: CommandLine?,
      parseResult: ParseResult?,
    ): Int {
      val out: PrintWriter = commandLine?.err ?: PrintWriter(System.err)
      out.println("Error: ${ex?.message}")
      out.println()
      commandLine?.usage(out)
      out.flush()
      return ExitCode.USAGE
    }
  }
}
