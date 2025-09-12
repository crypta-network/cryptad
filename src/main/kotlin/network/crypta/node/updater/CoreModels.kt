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
 * @property size Optional size hint in bytes, used for UI and validation.
 * @property sha256 Optional lowercase hex SHA‑256; not required because CHK already provides
 *   content integrity, but used when available for UI consistency and belt‑and‑suspenders checks.
 * @property storeUrl Optional OS “store” URL (e.g., Flatpak/Snap) to open instead of a direct file.
 */
data class PackageSpec(
  val chk: String?,
  val size: Long?,
  val sha256: String?,
  val storeUrl: String?,
)

/** Minimal OS family used for selecting package preference/order. */
enum class OsKind {
  WINDOWS,
  MAC,
  LINUX,
  OTHER,
}

/**
 * Result of cheap, best‑effort environment detection.
 *
 * @property os Broad OS family.
 * @property arch CPU arch normalized to "amd64" or "arm64"; others fall back to "amd64".
 * @property availableManagers Present package managers on PATH (Linux only): e.g.
 *   ["flatpak", "rpm"].
 */
data class EnvDetection(
  val os: OsKind,
  val arch: String, // "amd64" or "arm64" (others map to amd64 fallback)
  val availableManagers: List<String>, // e.g., ["flatpak", "snap", "dpkg", "rpm"]
)
