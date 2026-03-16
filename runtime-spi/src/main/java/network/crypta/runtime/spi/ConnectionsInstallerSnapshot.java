package network.crypta.runtime.spi;

import java.io.File;
import java.util.Objects;

/**
 * Detached metadata for one add-friend installer download target.
 *
 * <p>This snapshot preserves the legacy installer behavior used by the add-friend HTTP page while
 * keeping daemon-only updater types out of the runtime SPI. Callers receive the short download
 * filename, an optional already-downloaded local file, and the legacy fallback source text used to
 * build a freenet-relative link such as {@code "/" + sourceUriText}.
 *
 * @param filename short installer filename served from {@code /addfriend/}
 * @param localFile existing readable local installer file, or {@code null} when the installer is
 *     not currently cached on disk
 * @param sourceUriText legacy fallback source text used to build the installer link when no local
 *     file is available
 */
public record ConnectionsInstallerSnapshot(String filename, File localFile, String sourceUriText) {
  /**
   * Creates an immutable installer snapshot.
   *
   * @throws NullPointerException if {@code filename} or {@code sourceUriText} is {@code null}
   */
  public ConnectionsInstallerSnapshot {
    Objects.requireNonNull(filename, "filename");
    Objects.requireNonNull(sourceUriText, "sourceUriText");
  }
}
