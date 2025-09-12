package network.crypta.node.updater

/** Lightweight data model for core package info fetched from info/<edition>. */
data class CoreInfo(
  val version: String?,
  val releasePageUrl: String?,
  val packages: Map<String, PackageSpec>,
  val changelogChk: String?,
  val fullChangelogChk: String?,
)

data class PackageSpec(
  val chk: String?,
  val size: Long?,
  val sha256: String?,
  val storeUrl: String?,
)

enum class OsKind {
  WINDOWS,
  MAC,
  LINUX,
  OTHER,
}

data class EnvDetection(
  val os: OsKind,
  val arch: String, // "amd64" or "arm64" (others map to amd64 fallback)
  val availableManagers: List<String>, // e.g., ["flatpak", "snap", "dpkg", "rpm"]
)
