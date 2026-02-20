package network.crypta.node.updater;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Immutable descriptor for one core-update information edition.
 *
 * <p>Instances represent parsed metadata fetched from updater info editions under the core update
 * USK path (for example, {@code .../info/N}). The descriptor lists packages by platform key and
 * includes optional references to release-note resources so UI and updater flows can present the
 * right artifacts for the current environment.
 *
 * @param version version string advertised by this info edition
 * @param releasePageUrl optional human-readable release page URL
 * @param packages package descriptors keyed by platform selector
 * @param changelogChk optional short changelog CHK reference
 * @param fullChangelogChk optional full changelog CHK reference
 */
public record CoreInfo(
    String version,
    String releasePageUrl,
    Map<String, PackageSpec> packages,
    String changelogChk,
    String fullChangelogChk) {

  /**
   * Creates an immutable core-info descriptor.
   *
   * <p>The package map is defensively copied to preserve insertion order and then wrapped in an
   * unmodifiable view.
   */
  public CoreInfo {
    packages = Map.copyOf(new LinkedHashMap<>(packages));
  }
}
