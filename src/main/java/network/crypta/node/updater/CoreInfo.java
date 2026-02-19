package network.crypta.node.updater;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable model describing an update "core info" edition fetched from USK `.../info/<N>`.
 *
 * <p>The descriptor lists OS/arch-specific packages that can be offered to the user and optional
 * links to human-readable release notes/changelogs.
 */
public final class CoreInfo {
  private final String version;
  private final String releasePageUrl;
  private final Map<String, PackageSpec> packages;
  private final String changelogChk;
  private final String fullChangelogChk;

  public CoreInfo(
      String version,
      String releasePageUrl,
      Map<String, PackageSpec> packages,
      String changelogChk,
      String fullChangelogChk) {
    this.version = version;
    this.releasePageUrl = releasePageUrl;
    this.packages = Map.copyOf(new LinkedHashMap<>(packages));
    this.changelogChk = changelogChk;
    this.fullChangelogChk = fullChangelogChk;
  }

  public String getVersion() {
    return version;
  }

  public String getReleasePageUrl() {
    return releasePageUrl;
  }

  public Map<String, PackageSpec> getPackages() {
    return packages;
  }

  public String getChangelogChk() {
    return changelogChk;
  }

  public String getFullChangelogChk() {
    return fullChangelogChk;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof CoreInfo coreInfo)) {
      return false;
    }
    return Objects.equals(version, coreInfo.version)
        && Objects.equals(releasePageUrl, coreInfo.releasePageUrl)
        && Objects.equals(packages, coreInfo.packages)
        && Objects.equals(changelogChk, coreInfo.changelogChk)
        && Objects.equals(fullChangelogChk, coreInfo.fullChangelogChk);
  }

  @Override
  public int hashCode() {
    return Objects.hash(version, releasePageUrl, packages, changelogChk, fullChangelogChk);
  }

  @Override
  public String toString() {
    return "CoreInfo{"
        + "version='"
        + version
        + '\''
        + ", releasePageUrl='"
        + releasePageUrl
        + '\''
        + ", packages="
        + packages
        + ", changelogChk='"
        + changelogChk
        + '\''
        + ", fullChangelogChk='"
        + fullChangelogChk
        + '\''
        + '}';
  }
}
