/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.node

import network.crypta.node.Version.buildNumber
import network.crypta.node.Version.cvsRevision
import network.crypta.node.Version.publicVersion
import network.crypta.support.Fields
import network.crypta.support.LogThresholdCallback
import network.crypta.support.Logger
import network.crypta.support.Logger.LogLevel

/**
 * Version information and helpers for the Cryptad node.
 *
 * This object centralizes everything related to versioning: human‑readable
 * versions, protocol versions, build numbers, compatibility checks, and
 * utilities for constructing and parsing version strings.
 *
 * Constants declared as `const val` are inlined by the Kotlin compiler at
 * call sites. To retrieve values at runtime (e.g., after a hot swap or when
 * only this file is recompiled), prefer calling the provided accessor
 * functions such as [buildNumber], [publicVersion], and [cvsRevision] rather
 * than reading the constants directly.
 *
 * Version string format used for peer communication is a comma‑separated list:
 * "<name>,<series>,<protocol>,<build>". In compatibility checks we retain the
 * historical identifiers from upstream Freenet (e.g., "Fred" as the name and
 * series identifiers) to interoperate with those nodes where applicable.
 */
object Version {

    /** Human‑readable product name of the node. */
    const val nodeName = "Cryptad"

    /**
     * Internal series (tree) version used for compatibility calculations.
     * Changing this affects wire‑compatibility; see [publicVersion] for
     * the human‑facing release version.
     */
    const val nodeVersion = "@node_ver@"

    /** Human‑facing release version used for display and logging. */
    const val publicVersion = "@pub_ver@"

    /** Protocol version the node speaks on the wire. */
    const val protocolVersion = "1.0"

    /** Sequential build number identifying this binary. */
    private const val buildNumber = 1503

    /** Minimum acceptable build number for peers in our series. */
    private const val lastGoodBuildNumber = 1475

    @Volatile
    private var logMINOR: Boolean = false

    @Volatile
    private var logDEBUG: Boolean = false

    init {
        Logger.registerLogThresholdCallback(object : LogThresholdCallback() {
            override fun shouldUpdate() {
                logMINOR = Logger.shouldLog(LogLevel.MINOR, this)
                logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this)
            }
        })
    }

    /**
     * Returns the build number at runtime (not inlined).
     * Use this instead of reading the `const val` to avoid inlining.
     */
    @JvmStatic
    fun buildNumber(): Int = buildNumber

    /** Runtime accessor for [publicVersion] to avoid inlining. */
    @JvmStatic
    fun publicVersion(): String = publicVersion

    /** Minimum build number we accept from peers in our series. */
    @JvmStatic
    fun lastGoodBuild(): Int = lastGoodBuildNumber

    /** Highest peer build observed during this process lifetime. */
    private var highestSeenBuild = buildNumber

    /** Current stable series identifier (historical compatibility with Freenet). */
    const val stableNodeVersion = "0.7"

    /** Series identifier used when comparing with peers (historical "Fred"). */
    private const val fredSeries = "0.7"

    /** Minimum acceptable build for stable series peers. */
    const val lastGoodStableBuild = 1

    /** Git revision (historically called CVS revision) embedded at build time. */
    const val cvsRevision = "@git_rev@"

    /** Runtime accessor for [cvsRevision] to avoid inlining. */
    @JvmStatic
    fun cvsRevision(): String = cvsRevision

    /** Returns version components as `[name, series, protocol, build]`. */
    @JvmStatic
    fun getVersion(): Array<String> =
        arrayOf(nodeName, nodeVersion, protocolVersion, buildNumber.toString())

    @JvmStatic
    fun getLastGoodVersion(): Array<String> =
        arrayOf(nodeName, nodeVersion, protocolVersion, lastGoodBuild().toString())

    /** Returns the comma‑separated version string for NodeReference. */
    @JvmStatic
    fun getVersionString(): String = Fields.commaList(getVersion())

    /** Returns the comma‑separated minimum acceptable version (used by tooling like Freeviz). */
    @JvmStatic
    fun getLastGoodVersionString(): String = Fields.commaList(getLastGoodVersion())

    /** True if the provided protocol identifier is acceptable. */
    private fun goodProtocol(prot: String): Boolean {
        // uncomment next line to accept stable, see also explainBadVersion() below
        //                      || prot.equals(stableProtocolVersion)
        return prot == protocolVersion
    }

    /**
     * Checks whether a peer version string is compatible.
     *
     * Requirements:
     * - protocol must match [protocolVersion]
     * - if peer is in our series, its build must be >= [lastGoodBuild]
     * - if peer is stable series, its build must be >= [lastGoodStableBuild]
     */
    @JvmStatic
    fun isCompatibleFredVersion(version: String?): Boolean {
        if (version == null) {
            Logger.error(Version::class.java, "version == null!", Exception("error"))
            return false
        }
        val v = Fields.commaList(version)
        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            return false
        }
        if (sameSeriesAsUs(v)) {
            try {
                val build = v[3].toInt()
                val req = lastGoodBuild()
                if (build < req) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting unstable from version: $version(lastGoodBuild=$req)"
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                if (logMINOR)
                    Logger.minor(
                        Version::class.java,
                        "Not accepting ($e) from $version"
                    )
                return false
            }
        }
        if (stableVersion(v)) {
            try {
                val build = v[3].toInt()
                if (build < lastGoodStableBuild) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting stable from version$version(lastGoodStableBuild=$lastGoodStableBuild)"
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                Logger.minor(
                    Version::class.java,
                    "Not accepting ($e) from $version"
                )
                return false
            }
        }
        if (logDEBUG)
            Logger.minor(Version::class.java, "Accepting: $version")
        return true
    }

    /**
     * Checks compatibility using a peer‑provided minimum acceptable version.
     *
     * Both [version] and [lastGoodVersion] must have matching protocol; if the
     * series also matches, the peer build must be at least the minimum build in
     * [lastGoodVersion]. Stable series rules apply as in [isCompatibleFredVersion].
     */
    @JvmStatic
    fun isCompatibleFredVersionWithMinimum(version: String?, lastGoodVersion: String?): Boolean {
        if (version == null) {
            Logger.error(Version::class.java, "version == null!", Exception("error"))
            return false
        }
        if (lastGoodVersion == null) {
            Logger.error(Version::class.java, "lastGoodVersion == null!", Exception("error"))
            return false
        }
        val v = Fields.commaList(version)
        val lgv = Fields.commaList(lastGoodVersion)

        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            return false
        }
        if (lgv == null || lgv.size < 3 || !goodProtocol(lgv[2])) {
            return false
        }
        if (sameSeries(v, lgv)) {
            try {
                val build = v[3].toInt()
                val minBuild = lgv[3].toInt()
                if (build < minBuild) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting unstable from version: $version(lastGoodVersion=$lastGoodVersion)"
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                if (logMINOR)
                    Logger.minor(
                        Version::class.java,
                        "Not accepting ($e) from $version and/or $lastGoodVersion"
                    )
                return false
            }
        }
        if (stableVersion(v)) {
            try {
                val build = v[3].toInt()
                if (build < lastGoodStableBuild) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting stable from version$version(lastGoodStableBuild=$lastGoodStableBuild)"
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                Logger.minor(
                    Version::class.java,
                    "Not accepting ($e) from $version"
                )
                return false
            }
        }
        if (logDEBUG)
            Logger.minor(Version::class.java, "Accepting: $version")
        return true
    }

    /** Returns a human‑readable reason why [version] would be rejected, or null if acceptable. */
    @JvmStatic
    fun explainBadVersion(version: String): String? {
        val v = Fields.commaList(version)

        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            return "Required protocol version is " +
                    protocolVersion
            // uncomment next line if accepting stable, see also goodProtocol() above
            // + " or " + stableProtocolVersion
        }
        if (sameSeriesAsUs(v)) {
            return try {
                val build = v[3].toInt()
                val req = lastGoodBuild()
                if (build < req)
                    "Build older than last good build $req"
                else null
            } catch (e: NumberFormatException) {
                "Build number not numeric."
            }
        }
        if (stableVersion(v)) {
            return try {
                val build = v[3].toInt()
                if (build < lastGoodStableBuild)
                    "Build older than last good stable build $lastGoodStableBuild"
                else null
            } catch (e: NumberFormatException) {
                "Build number not numeric."
            }
        }
        return null
    }

    /** Parses an arbitrary version string and returns its build number. */
    @JvmStatic
    @Throws(VersionParseException::class)
    fun getArbitraryBuildNumber(version: String?): Int {
        if (version == null) {
            Logger.error(Version::class.java, "version == null!", Exception("error"))
            throw VersionParseException("version == null")
        }
        val v = Fields.commaList(version)

        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            throw VersionParseException("not long enough or bad protocol: $version")
        }
        try {
            return v[3].toInt()
        } catch (e: NumberFormatException) {
            throw VersionParseException("Got NumberFormatException on " + v[3] + " : " + e + " for " + version).initCause(
                e
            ) as VersionParseException
        }
    }

    @JvmStatic
    fun getArbitraryBuildNumber(version: String?, defaultValue: Int): Int {
        return try {
            getArbitraryBuildNumber(version)
        } catch (e: VersionParseException) {
            defaultValue
        }
    }

    /** Records the highest build number observed among compatible peers. */
    @JvmStatic
    fun seenVersion(version: String?) {
        val v = Fields.commaList(version)

        if (v == null || v.size < 3)
            return  // bad, but that will be discovered elsewhere

        if (sameSeriesAsUs(v)) {
            val buildNo = try {
                v[3].toInt()
            } catch (e: NumberFormatException) {
                return
            }
            if (buildNo > highestSeenBuild) {
                if (logMINOR) {
                    Logger.minor(
                        Version::class.java,
                        "New highest seen build: $buildNo"
                    )
                }
                highestSeenBuild = buildNo
            }
        }
    }

    @JvmStatic
    fun getHighestSeenBuild(): Int = highestSeenBuild

    /** True if [v] refers to our series (build is ignored). */
    @JvmStatic
    fun sameSeriesAsUs(v: Array<String>): Boolean {
        return v[0] == "Fred" &&
                v[1] == fredSeries &&
                v.size >= 4
    }

    /** True if [v] and [lgv] are the same series (builds are ignored). */
    @JvmStatic
    fun sameSeries(v: Array<String>, lgv: Array<String>): Boolean {
        return v[0] == lgv[0] &&
                v[1] == lgv[1] &&
                v.size >= 4 &&
                lgv.size >= 4
    }

    /** True if [v] refers to the stable series. */
    private fun stableVersion(v: Array<String>): Boolean {
        return v[0] == "Fred" &&
                v[1] == stableNodeVersion &&
                v.size >= 4
    }
}
