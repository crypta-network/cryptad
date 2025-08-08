/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
@file:JvmName("Version")

package network.crypta.node

import network.crypta.support.Fields
import network.crypta.support.LogThresholdCallback
import network.crypta.support.Logger
import network.crypta.support.Logger.LogLevel

/**
 * Version information and helpers for the Cryptad node.
 *
 * This file centralizes everything related to versioning: human‑readable
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

/** Human‑readable product name of the node. */
const val nodeName: String = "Cryptad"

/**
 * Historical wire identifier used in version strings for compatibility with
 * upstream Freenet nodes. Many peers and tools expect the first component of
 * the comma‑separated Version field to be exactly "Fred". We therefore keep
 * using this value on the wire while retaining [nodeName] for human‑readable
 * contexts (logs, UI, etc.).
 */
private const val wireName: String = "Fred"

/**
 * Internal series (tree) version used for compatibility calculations.
 * Changing this affects wire‑compatibility; see [publicVersion] for
 * the human‑facing release version.
 */
const val nodeVersion: String = "@node_ver@"

/** Human‑facing release version used for display and logging. */
const val publicVersion: String = "@pub_ver@"

/** Protocol version the node speaks on the wire. */
const val protocolVersion: String = "1.0"

/** Sequential build number identifying this binary. */
private const val buildNumberConst: Int = 1503

/** Minimum acceptable build number for peers in our series. */
private const val lastGoodBuildNumber: Int = 1475

@Volatile
private var logMINOR: Boolean = false

@Volatile
private var logDEBUG: Boolean = false

// Ensure logger thresholds are tracked at runtime.
@Suppress("ObjectPropertyName", "unused")
private val _logInit: Unit = run {
    Logger.registerLogThresholdCallback(object : LogThresholdCallback() {
        override fun shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, this)
            logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this)
        }
    })
}

private object VersionLogTag

private val LOG_TAG: Class<*> = VersionLogTag::class.java

/**
 * Returns the build number at runtime (not inlined).
 * Use this instead of reading the `const val` to avoid inlining.
 */
fun buildNumber(): Int = buildNumberConst

/** Runtime accessor for [publicVersion] to avoid inlining. */
fun publicVersion(): String = publicVersion

/** Minimum build number we accept from peers in our series. */
fun lastGoodBuild(): Int = lastGoodBuildNumber

/** Highest peer build observed during this process lifetime. */
private var highestSeenBuild: Int = buildNumberConst

/** Current stable series identifier (historical compatibility with Freenet). */
const val stableNodeVersion: String = "0.7"

/** Series identifier used when comparing with peers (historical "Fred"). */
private const val fredSeries: String = "0.7"

/** Minimum acceptable build for stable series peers. */
const val lastGoodStableBuild: Int = 1

/** Git revision (historically called CVS revision) embedded at build time. */
const val cvsRevision: String = "@git_rev@"

/** Runtime accessor for [cvsRevision] to avoid inlining. */
fun cvsRevision(): String = cvsRevision

/** Returns version components as `[name, series, protocol, build]`. */
fun getVersion(): Array<String> =
    arrayOf(wireName, nodeVersion, protocolVersion, buildNumber().toString())

fun getLastGoodVersion(): Array<String> =
    arrayOf(wireName, nodeVersion, protocolVersion, lastGoodBuild().toString())

/** Returns the comma‑separated version string for NodeReference. */
fun getVersionString(): String = Fields.commaList(getVersion())

/** Returns the comma‑separated minimum acceptable version (used by tooling like Freeviz). */
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
fun isCompatibleFredVersion(version: String?): Boolean {
    val v = parseVersionOrNull(version) ?: return false

    if (rejectIfUnstableTooOld(v, version)) return false
    if (rejectIfStableTooOld(v, version)) return false

    if (logDEBUG) Logger.minor(LOG_TAG, "Accepting: $version")
    return true
}

/**
 * Checks compatibility using a peer‑provided minimum acceptable version.
 *
 * Both [version] and [lastGoodVersion] must have matching protocol; if the
 * series also matches, the peer build must be at least the minimum build in
 * [lastGoodVersion]. Stable series rules apply as in [isCompatibleFredVersion].
 */
fun isCompatibleFredVersionWithMinimum(version: String?, lastGoodVersion: String?): Boolean {
    val v = parseVersionOrNull(version) ?: return false
    val lgv = parseVersionOrNull(lastGoodVersion, label = "lastGoodVersion") ?: return false

    if (sameSeries(v, lgv)) {
        val build = v.getOrNull(3)?.toIntOrNull()
        val minBuild = lgv.getOrNull(3)?.toIntOrNull()
        if (build == null || minBuild == null) {
            if (logMINOR) Logger.minor(
                LOG_TAG,
                "Not accepting (NumberFormatException) from $version and/or $lastGoodVersion"
            )
            return false
        }
        if (build < minBuild) {
            if (logDEBUG) Logger.debug(
                LOG_TAG,
                "Not accepting unstable from version: $version(lastGoodVersion=$lastGoodVersion)"
            )
            return false
        }
    }

    if (rejectIfStableTooOld(v, version)) return false

    if (logDEBUG) Logger.minor(LOG_TAG, "Accepting: $version")
    return true
}

/**
 * Parses and validates a version string ensuring it has at least 3 parts and a good protocol.
 * Logs a helpful error when the input is null.
 *
 * @param version Version string like "Fred,0.7,1.0,1503".
 * @param label Optional label for logging context (e.g., "lastGoodVersion").
 * @return The split array if valid, or null if invalid.
 */
private fun parseVersionOrNull(version: String?, label: String = "version"): Array<String>? {
    if (version == null) {
        Logger.error(LOG_TAG, "$label == null!", Exception("error"))
        return null
    }
    val v = Fields.commaList(version)
    if (v == null || v.size < 3 || !goodProtocol(v[2])) return null
    return v
}

/** Returns true if the version should be rejected for being an old unstable build. */
private fun rejectIfUnstableTooOld(v: Array<String>, original: String?): Boolean {
    if (!sameSeriesAsUs(v)) return false
    val build = v.getOrNull(3)?.toIntOrNull()
    val req = lastGoodBuild()
    if (build == null) {
        if (logMINOR) Logger.minor(LOG_TAG, "Not accepting (NumberFormatException) from $original")
        return true
    }
    if (build < req) {
        if (logDEBUG) Logger.debug(LOG_TAG, "Not accepting unstable from version: $original(lastGoodBuild=$req)")
        return true
    }
    return false
}

/** Returns true if the version should be rejected for being an old stable build. */
private fun rejectIfStableTooOld(v: Array<String>, original: String?): Boolean {
    if (!stableVersion(v)) return false
    val build = v.getOrNull(3)?.toIntOrNull()
    if (build == null) {
        Logger.minor(LOG_TAG, "Not accepting (NumberFormatException) from $original")
        return true
    }
    if (build < lastGoodStableBuild) {
        if (logDEBUG) Logger.debug(
            LOG_TAG,
            "Not accepting stable from version$original(lastGoodStableBuild=$lastGoodStableBuild)"
        )
        return true
    }
    return false
}

/** Parses an arbitrary version string and returns its build number. */
@Throws(VersionParseException::class)
fun getArbitraryBuildNumber(version: String?): Int {
    if (version == null) {
        Logger.error(LOG_TAG, "version == null!", Exception("error"))
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

fun getArbitraryBuildNumber(version: String?, defaultValue: Int): Int {
    return try {
        getArbitraryBuildNumber(version)
    } catch (_: VersionParseException) {
        defaultValue
    }
}

/** Records the highest build number observed among compatible peers. */
fun seenVersion(version: String?) {
    val v = Fields.commaList(version)

    if (v == null || v.size < 3)
        return  // bad, but that will be discovered elsewhere

    if (sameSeriesAsUs(v)) {
        val buildNo = try {
            v[3].toInt()
        } catch (_: NumberFormatException) {
            return
        }
        if (buildNo > highestSeenBuild) {
            if (logMINOR) {
                Logger.minor(
                    LOG_TAG,
                    "New highest seen build: $buildNo"
                )
            }
            highestSeenBuild = buildNo
        }
    }
}

fun getHighestSeenBuild(): Int = highestSeenBuild

/** True if [v] refers to our series (build is ignored). */
fun sameSeriesAsUs(v: Array<String>): Boolean {
    return v[0] == wireName &&
            v[1] == fredSeries &&
            v.size >= 4
}

/** True if [v] and [lgv] are the same series (builds are ignored). */
fun sameSeries(v: Array<String>, lgv: Array<String>): Boolean {
    return v[0] == lgv[0] &&
            v[1] == lgv[1] &&
            v.size >= 4 &&
            lgv.size >= 4
}

/** True if [v] refers to the stable series. */
private fun stableVersion(v: Array<String>): Boolean {
    return v[0] == wireName &&
            v[1] == stableNodeVersion &&
            v.size >= 4
}
