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
 * versions, protocol versions, build numbers, compatibility checks,
 * and utilities for constructing and parsing version strings.
 *
 * ## Version Terminology
 * - **Build ID**: A single integer uniquely identifying this build
 *   (previously called versionNumber)
 * - **Version Components**: Array of strings containing
 *   [name, series/version, protocol, build]
 * - **Version String**: Comma-separated representation of version
 *   components for wire protocol
 *
 * ## Constants vs Runtime Access
 * Constants declared as `const val` are inlined by the Kotlin compiler at
 * call sites. To retrieve values at runtime (e.g., after a hot swap or
 * when only this file is recompiled), prefer calling the provided accessor
 * functions rather than reading the constants directly.
 *
 * ## Wire Protocol Format
 * Version string format used for peer communication is a comma‑separated
 * list: "<name>,<series>,<protocol>,<build>". In compatibility checks we
 * retain the historical identifiers from upstream Freenet (e.g., "Fred" as
 * the name and series identifiers) to interoperate with those nodes where
 * applicable.
 */

// Constants
/** Human‑readable product name of the node. */
const val NODE_NAME: String = "Cryptad"

/** Minimum acceptable build for stable Fred peers. */
const val LAST_GOOD_FRED_STABLE_BUILD: Int = 1

/** Protocol version the node speaks on the wire. */
const val LAST_GOOD_FRED_PROTOCOL_VERSION: String = "1.0"

/** Git revision (historically called CVS revision) embedded at build time. */
const val GIT_REVISION: String = "@git_rev@"

// Private constants
/**
 * Single integer build number for this binary.
 *
 * This is the canonical build number that uniquely identifies this
 * version. The token @build_number@ is replaced during build; fallback to
 * 0 if not replaced.
 */
private const val BUILD_NUMBER_STRING: String = "@build_number@"

/**
 * Historical wire identifier used in version strings for compatibility
 * with upstream Freenet nodes. Many peers and tools expect the first
 * component of the comma‑separated Version field to be exactly "Fred". We
 * therefore keep using this value on the wire while retaining [NODE_NAME]
 * for human‑readable contexts (logs, UI, etc.).
 */
private const val WIRE_NAME: String = "Fred"

/**
 * Current stable series identifier (historical compatibility with
 * Freenet).
 */
private const val STABLE_FRED_NODE_VERSION: String = "0.7"

/**
 * Minimum acceptable build number for Cryptad peers when checking
 * compatibility.
 */
const val MIN_ACCEPTABLE_CRYPTAD_BUILD_NUMBER: Int = 1

/**
 * Minimum acceptable build number for Freenet peers when checking
 * compatibility.
 */
const val MIN_ACCEPTABLE_FRED_BUILD_NUMBER: Int = 1475

// Runtime state
private val buildNumber: Int by lazy {
    when {
        BUILD_NUMBER_STRING.startsWith("@") && BUILD_NUMBER_STRING.endsWith("@") -> 0 // Fallback when token is not replaced
        else -> BUILD_NUMBER_STRING.toIntOrNull() ?: 0
    }
}

@Volatile
private var logMinor: Boolean = false

@Volatile
private var logDebug: Boolean = false

/** Highest peer build observed during this process lifetime. */
@Volatile
private var highestSeenBuild: Int = buildNumber

// Logger initialization
private object VersionLogTag

private val logTag: Class<*> = VersionLogTag::class.java

// Initialize logging callback - using lazy to ensure proper initialization
private val loggerCallbackInitializer = lazy {
    Logger.registerLogThresholdCallback(object : LogThresholdCallback() {
        override fun shouldUpdate() {
            logMinor = Logger.shouldLog(LogLevel.MINOR, this)
            logDebug = Logger.shouldLog(LogLevel.DEBUG, this)
        }
    })
}

// Ensure logger callback is initialized when first accessed
private fun ensureLoggerInitialized() {
    loggerCallbackInitializer.value
}

// Public API functions

/**
 * Returns the current build number at runtime (not inlined).
 *
 * This is the primary identifier for this build. Use this instead of
 * reading the constant directly to avoid inlining.
 *
 * @return The build number as an Int
 */
fun currentBuildNumber(): Int = buildNumber


/** Runtime accessor for [GIT_REVISION] to avoid inlining. */
fun gitRevision(): String = GIT_REVISION

/**
 * Returns the current node's version components as an array.
 *
 * Format: `[name, buildNumber, protocol, buildNumber]` where:
 * - name: The node name ("Cryptad")
 * - buildNumber: The current build number as string
 * - protocol: The protocol version for compatibility
 * - buildNumber: This prevents Fred nodes from throwing an
 *   `ArrayIndexOutOfBoundsException` when parsing the version string.
 *
 * @return Array containing version components
 */
fun getVersionComponents(): Array<String> =
    arrayOf(NODE_NAME, buildNumber.toString(), LAST_GOOD_FRED_PROTOCOL_VERSION, buildNumber.toString())


/**
 * Returns the minimum acceptable version components for Fred/Freenet
 * compatibility.
 *
 * Format: `[name, series, protocol, buildNumber]` where:
 * - name: "Fred" (for historical compatibility)
 * - series: The stable Fred version series ("0.7")
 * - protocol: The protocol version
 * - buildNumber: The minimum acceptable Fred build number
 *
 * @return Array containing minimum acceptable version components
 */
fun getMinAcceptableVersionComponents(): Array<String> =
    arrayOf(
        WIRE_NAME,
        STABLE_FRED_NODE_VERSION,
        LAST_GOOD_FRED_PROTOCOL_VERSION,
        MIN_ACCEPTABLE_FRED_BUILD_NUMBER.toString()
    )


/**
 * Returns the comma‑separated version string for wire protocol
 * communication.
 *
 * This string is used in NodeReference and peer communication. Format:
 * "<name>,<buildNumber>,<protocol>"
 *
 * @return Comma-separated version string
 */
fun getVersionString(): String = Fields.commaList(getVersionComponents())

/**
 * Returns the comma‑separated minimum acceptable version string.
 *
 * This is used by tooling like Freeviz and for compatibility checks.
 * Format: "Fred,0.7,<protocol>,<minBuildNumber>"
 *
 * @return Comma-separated minimum acceptable version string
 */
fun getMinAcceptableVersionString(): String = Fields.commaList(getMinAcceptableVersionComponents())


/**
 * Checks whether a peer version string is compatible with this node.
 *
 * Compatibility requirements:
 * - Protocol must match [LAST_GOOD_FRED_PROTOCOL_VERSION]
 * - For Cryptad peers: build number must
 *   be >= [MIN_ACCEPTABLE_CRYPTAD_BUILD_NUMBER]
 * - For Fred peers: build number must
 *   be >= [MIN_ACCEPTABLE_FRED_BUILD_NUMBER]
 *
 * @param version The version string to check
 * @return true if the version is compatible, false otherwise
 */
fun isCompatibleVersion(version: String?): Boolean {
    ensureLoggerInitialized()
    val v = parseVersionOrNull(version) ?: return false

    if (rejectIfCryptadTooOld(v, version)) return false
    if (rejectIfFredTooOld(v, version)) return false

    if (logDebug) Logger.minor(logTag, "Accepting: $version")
    return true
}

/**
 * Checks compatibility using a peer‑provided minimum acceptable version.
 *
 * This method validates that:
 * - Both version strings have matching protocols
 * - If series match, the peer's build meets the minimum requirement
 * - Stable series rules apply as in [isCompatibleVersion]
 *
 * @param versionStr The peer's version string
 * @param lastGoodVersionStr The peer's minimum acceptable version string
 * @return true if versions are mutually compatible, false otherwise
 */
fun isCompatibleVersionWithLastGood(versionStr: String?, lastGoodVersionStr: String?): Boolean {
    ensureLoggerInitialized()
    val v = parseVersionOrNull(versionStr) ?: return false
    val lgv = parseVersionOrNull(lastGoodVersionStr, label = "lastGoodVersion") ?: return false

    // Check Cryptad-to-Cryptad compatibility
    if (v[0] == NODE_NAME && lgv[0] == NODE_NAME &&
        !checkCryptadCompatibility(v, lgv, versionStr, lastGoodVersionStr)
    ) {
        return false
    } // else Cryptad is always compatible with Fred no matter what build it is

    // Check Fred-to-Fred compatibility
    if (v[0] == WIRE_NAME && !checkFredCompatibility(v, lgv, versionStr, lastGoodVersionStr)) {
        return false
    }

    if (logDebug) Logger.minor(logTag, "Accepting: $versionStr")
    return true
}

/**
 * Parses a version string and extracts its build number.
 *
 * Handles both Cryptad format (name,buildNumber,protocol) and Fred format
 * (name,series,protocol,buildNumber).
 *
 * @param version The version string to parse
 * @return The extracted build number
 * @throws VersionParseException if the version string is invalid
 */
@Throws(VersionParseException::class)
fun parseVersionNumberFromStr(version: String?): Int {
    version ?: run {
        Logger.error(logTag, "version == null!", Exception("error"))
        throw VersionParseException("version == null")
    }

    val v = Fields.commaList(version)
        ?: throw VersionParseException("not long enough or bad protocol: $version")

    if (v.size < 3 || !isValidProtocol(v[2])) {
        throw VersionParseException("not long enough or bad protocol: $version")
    }

    return try {
        when (v[0]) {
            NODE_NAME -> v[1].toInt()
            WIRE_NAME -> v.getOrNull(3)?.toInt()
                ?: throw VersionParseException("Fred version missing build number: $version")

            else -> throw VersionParseException("unknown node name: ${v[0]}")
        }
    } catch (e: NumberFormatException) {
        throw VersionParseException("Got NumberFormatException on ${v.getOrNull(3)} : $e for $version").apply {
            initCause(e)
        }
    }
}

/**
 * Parses a version string and returns its build number, with a default
 * fallback.
 *
 * @param version The version string to parse
 * @param defaultValue The value to return if parsing fails
 * @return The extracted build number or defaultValue if parsing fails
 */
fun parseVersionNumberFromStr(version: String?, defaultValue: Int): Int =
    runCatching { parseVersionNumberFromStr(version) }.getOrElse { defaultValue }

/**
 * Records the highest build number observed among compatible peers.
 *
 * This tracks the maximum build number seen during this node's lifetime,
 * useful for detecting newer versions in the network.
 *
 * @param versionStr The version string from a peer
 */
fun seenVersion(versionStr: String?) {
    ensureLoggerInitialized()
    val v = Fields.commaList(versionStr) ?: return
    if (v.size < 3) return  // bad, but that will be discovered elsewhere

    val version = runCatching {
        when (v[0]) {
            NODE_NAME -> v[1].toInt()
            WIRE_NAME -> v.getOrNull(3)?.toInt() ?: return
            else -> return
        }
    }.getOrElse { return }

    if (version > highestSeenBuild) {
        if (logMinor) {
            Logger.minor(logTag, "New highest seen build: $version")
        }
        highestSeenBuild = version
    }
}

/**
 * Returns the highest build number observed from peers.
 *
 * @return The highest build number seen during this node's lifetime
 */
fun getHighestSeenBuild(): Int = highestSeenBuild

/**
 * Checks if the version components refer to a Cryptad node.
 *
 * @param v Version components array
 * @return true if this is a Cryptad node, false otherwise
 */
fun isCryptad(v: Array<String>): Boolean = v.isNotEmpty() && v[0] == NODE_NAME && v.size >= 2

/**
 * Checks if two version component arrays represent compatible series.
 *
 * Currently unused but retained for potential future compatibility checks.
 *
 * @param v First version components array
 * @param lgv Second version components array (often minimum acceptable
 *    version)
 * @return true if the versions are from compatible series, false otherwise
 */
@Suppress("unused")
internal fun isCompatibleSeries(v: Array<String>, lgv: Array<String>): Boolean {
    if (v.size < 2 || lgv.size < 2) return false
    return when (v[0]) { // Check if the series are the same based on the node type
        NODE_NAME -> true // Cryptad is always compatible with Fred
        WIRE_NAME -> v[1] == lgv[1] && v.size >= 4 && lgv.size >= 4
        else -> false
    }
}

// Private helper functions

/** True if the provided protocol identifier is acceptable. */
private fun isValidProtocol(protocol: String): Boolean {
    // uncomment next line to accept stable, see also explainBadVersion() below
    //                      || prot.equals(stableProtocolVersion)
    return protocol == LAST_GOOD_FRED_PROTOCOL_VERSION
}

/** Checks compatibility between two Cryptad nodes. */
private fun checkCryptadCompatibility(
    v: Array<String>,
    lgv: Array<String>,
    versionStr: String?,
    lastGoodVersionStr: String?
): Boolean {
    val version = v.getOrNull(1)?.toIntOrNull()
    val minVersion = lgv.getOrNull(1)?.toIntOrNull()

    if (version == null || minVersion == null) {
        ensureLoggerInitialized()
        if (logMinor) Logger.minor(
            logTag,
            "Not accepting (NumberFormatException) from $versionStr and/or $lastGoodVersionStr"
        )
        return false
    }

    if (version < minVersion) {
        ensureLoggerInitialized()
        if (logDebug) Logger.debug(
            logTag,
            "Not accepting unstable from version: $versionStr(lastGoodVersion=$lastGoodVersionStr)"
        )
        return false
    }

    return true
}

/** Checks compatibility between Fred/Freenet nodes. */
private fun checkFredCompatibility(
    v: Array<String>,
    lgv: Array<String>,
    versionStr: String?,
    lastGoodVersionStr: String?
): Boolean {
    // Fred is not compatible with Cryptad minimum versions
    if (lgv.isNotEmpty() && lgv[0] == NODE_NAME) return false

    // Check if Fred version is too old
    if (rejectIfFredTooOld(v, versionStr)) return false

    val build = v.getOrNull(3)?.toIntOrNull()
    val minBuild = lgv.getOrNull(3)?.toIntOrNull()

    if (build == null || minBuild == null) {
        ensureLoggerInitialized()
        if (logMinor) Logger.minor(
            logTag,
            "Not accepting (NumberFormatException) from $versionStr and/or $lastGoodVersionStr"
        )
        return false
    }

    if (build < minBuild) {
        ensureLoggerInitialized()
        if (logDebug) Logger.debug(
            logTag,
            "Not accepting unstable from version: $versionStr(lastGoodVersion=$lastGoodVersionStr)"
        )
        return false
    }

    return true
}

/**
 * Parses and validates a version string ensuring it has at least 3 parts
 * and a good protocol. Logs a helpful error when the input is null.
 *
 * @param version Version string like "Fred,0.7,1.0,1503".
 * @param label Optional label for logging context (e.g.,
 *    "lastGoodVersion").
 * @return The split array if valid, or null if invalid.
 */
private fun parseVersionOrNull(version: String?, label: String = "version"): Array<String>? {
    version ?: run {
        Logger.error(logTag, "$label == null!", Exception("error"))
        return null
    }

    val v = Fields.commaList(version) ?: return null
    return if (v.size < 3 || !isValidProtocol(v[2])) null else v
}

/**
 * Checks if a Cryptad peer's version should be rejected for being too old.
 *
 * @param v Version components array from the peer
 * @param original Original version string for logging
 * @return true if the version should be rejected, false if acceptable
 */
private fun rejectIfCryptadTooOld(v: Array<String>, original: String?): Boolean {
    if (!isCryptad(v)) return false

    val version = v.getOrNull(1)?.toIntOrNull()
    val req = MIN_ACCEPTABLE_CRYPTAD_BUILD_NUMBER

    if (version == null) {
        ensureLoggerInitialized()
        if (logMinor) Logger.minor(logTag, "Not accepting (NumberFormatException) from $original")
        return true
    }

    if (version < req) {
        ensureLoggerInitialized()
        if (logDebug) Logger.debug(
            logTag,
            "Not accepting unstable from version: $original(minAcceptableCryptadBuildNumber=$req)"
        )
        return true
    }

    return false
}

/**
 * Checks if a Fred/Freenet peer's version should be rejected for being too
 * old.
 *
 * @param v Version components array from the peer
 * @param original Original version string for logging
 * @return true if the version should be rejected, false if acceptable
 */
private fun rejectIfFredTooOld(v: Array<String>, original: String?): Boolean {
    if (!isFredStableVersion(v)) return false

    val build = v.getOrNull(3)?.toIntOrNull()
    if (build == null) {
        Logger.minor(logTag, "Not accepting (NumberFormatException) from $original")
        return true
    }

    if (build < LAST_GOOD_FRED_STABLE_BUILD) {
        ensureLoggerInitialized()
        if (logDebug) Logger.debug(
            logTag,
            "Not accepting stable from version $original(lastGoodStableBuild=$LAST_GOOD_FRED_STABLE_BUILD)"
        )
        return true
    }

    return false
}

/**
 * Checks if the version components refer to a stable Fred/Freenet node.
 *
 * @param v Version components array
 * @return true if this is a stable Fred node, false otherwise
 */
private fun isFredStableVersion(v: Array<String>): Boolean =
    v.size >= 4 && v[0] == WIRE_NAME && v[1] == STABLE_FRED_NODE_VERSION
