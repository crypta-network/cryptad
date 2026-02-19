package network.crypta.node.updater;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable model describing an update "core info" edition fetched from USK `.../info/<N>`.
 *
 * <p>The descriptor lists OS/arch-specific packages that can be offered to the user and optional
 * links to human-readable release notes/changelogs.
 */
public record CoreInfo(
    String version,
    String releasePageUrl,
    Map<String, PackageSpec> packages,
    String changelogChk,
    String fullChangelogChk) {

  public CoreInfo {
    packages = Map.copyOf(new LinkedHashMap<>(packages));
  }
}
