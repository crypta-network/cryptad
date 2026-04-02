package network.crypta.runtime.admin;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import network.crypta.node.Node;
import network.crypta.runtime.spi.WelcomePagePort;
import network.crypta.runtime.spi.WelcomePageSnapshot;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.LineReadingInputStream;

/**
 * Adapts the welcome-page read SPI to the legacy daemon runtime.
 *
 * <p>This adapter keeps the remaining welcome-page GET-only configuration and file-system reads in
 * the daemon root module, where the legacy {@link Node} APIs still live. The HTTP layer can then
 * consume a detached {@link WelcomePagePort} without knowing how configuration is stored or where
 * log files live on disk. That split keeps this migration conservative: the welcome page moves its
 * read path first, while POST and action handlers can continue to use the live daemon until later
 * PRs detach them.
 *
 * <p>The adapter preserves the daemon's existing behavior. It reads the {@code
 * fproxy.fetchKeyBoxAboveBookmarks} flag, resolves the logger directory from the current node
 * configuration, prefers {@code crypta-latest.log}, falls back to {@code freenet-latest.log}, and
 * uses the same tail truncation helper that the legacy welcome page used directly.
 */
final class LegacyWelcomePagePort implements WelcomePagePort {
  /** Limits log output to the same byte window used by the legacy welcome-page handler. */
  private static final long LOG_TAIL_BYTE_LIMIT = 100000L;

  /** Live daemon node that remains the source of truth for config and log discovery. */
  private final Node node;

  /**
   * Creates a legacy adapter backed by the live daemon node.
   *
   * <p>The supplied node remains the source of truth for configuration lookup and log-file
   * discovery. The adapter itself is stateless apart from that reference and may be reused across
   * multiple welcome-page requests.
   *
   * @param node live daemon node that supplies config access and logger-directory resolution
   */
  LegacyWelcomePagePort(Node node) {
    this.node = Objects.requireNonNull(node, "node");
  }

  /** {@inheritDoc} */
  @Override
  public WelcomePageSnapshot snapshot() {
    return new WelcomePageSnapshot(
        node.getConfig().get("fproxy").getBoolean("fetchKeyBoxAboveBookmarks"));
  }

  /** {@inheritDoc} */
  @Override
  public String latestNodeLogTail() throws IOException {
    File logDir = new File(node.getConfig().get("logger").getString("dirname"));
    File crypta = new File(logDir, "crypta-latest.log");
    File freenet = new File(logDir, "freenet-latest.log");
    return readLogTail(crypta.exists() ? crypta : freenet);
  }

  /**
   * Reads the truncated tail for the selected log file.
   *
   * @param logfile log file chosen by the legacy filename preference rules
   * @return decoded text from the legacy tail reader for that file
   * @throws IOException if the log file cannot be opened or decoded
   */
  private static String readLogTail(File logfile) throws IOException {
    try (LineReadingInputStream stream = FileUtil.getLogTailReader(logfile, LOG_TAIL_BYTE_LIMIT)) {
      return FileUtil.readUTF(stream).toString();
    }
  }
}
