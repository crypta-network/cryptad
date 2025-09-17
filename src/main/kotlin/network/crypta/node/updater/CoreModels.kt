package network.crypta.node.updater

/**
 * Immutable model describing an update “core info” edition fetched from USK `.../info/<N>`.
 *
 * The descriptor lists OS/arch‑specific packages that can be offered to the user and optional links
 * to human‑readable release notes/changelogs.
 *
 * @property version Optional semantic or project version string.
 * @property releasePageUrl Optional URL with full release notes (opened via ExternalLinkToadlet).
 * @property packages Map keyed by "<arch>.<ext>" (e.g. "amd64.deb", "arm64.dmg").
 * @property changelogChk Optional CHK for a short changelog.
 * @property fullChangelogChk Optional CHK for a detailed developer changelog.
 */
data class CoreInfo(
  val version: String?,
  val releasePageUrl: String?,
  val packages: Map<String, PackageSpec>,
  val changelogChk: String?,
  val fullChangelogChk: String?,
)

/**
 * Package metadata for a single distributable artifact.
 *
 * @property chk Optional CHK of the file to download into the node’s updates directory.
 * @property size Optional size hint in bytes, used for UI only.
 * @property storeUrl Optional OS “store” URL (e.g., Flatpak/Snap) to open instead of a direct file.
 */
data class PackageSpec(val chk: String?, val size: Long?, val storeUrl: String?)
