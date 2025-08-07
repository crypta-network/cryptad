/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package network.crypta.node

import network.crypta.support.Fields
import network.crypta.support.LogThresholdCallback
import network.crypta.support.Logger
import network.crypta.support.Logger.LogLevel
import java.util.Calendar
import java.util.TimeZone

/**
 * Central spot for stuff related to the versioning of the codebase.
 *
 * Note: when using the fields of this class, you must note that the Java
 * compiler compiles **constant final static** fields into the class
 * definitions of classes that use them. This might not be the most appropriate
 * behaviour when, eg. creating a class that reports statistics.
 *
 * A final static field can be made "non-constant" in the eyes of the compiler
 * by initialising it with the results of a method, eg `T identity(T o) { T o; }`;
 * however the "constant" behaviour might be required in some cases. A more
 * flexible solution is to add a method that returns the field, eg
 * [publicVersion], and choose between the method and the field as necessary.
 */
object Version {

    /** Crypta Daemon */
    const val nodeName = "Cryptad"

    /**
     * The current tree version.
     * FIXME: This is part of the node compatibility computations, so cannot be
     * safely changed!!! Hence publicVersion ...
     */
    const val nodeVersion = "@node_ver@"

    /**
     * The version for publicity purposes i.e. the version of the node that has
     * been released.
     */
    const val publicVersion = "@pub_ver@"

    /** The protocol version supported */
    const val protocolVersion = "1.0"

    /** The build number of the current revision */
    private const val buildNumber = 1503

    /** Oldest build of fred we will talk to *before* _cal */
    private const val oldLastGoodBuild = 1474

    /** Oldest build of fred we will talk to *after* _cal */
    private const val newLastGoodBuild = 1475

    val transitionTime: Long

    @Volatile
    private var logMINOR: Boolean = false
    @Volatile
    private var logDEBUG: Boolean = false

    init {
        val _cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"))
        // year, month - 1 (or constant), day, hour, minute, second
        _cal.set(2016, Calendar.JULY, 15, 0, 0, 0)
        transitionTime = _cal.timeInMillis

        Logger.registerLogThresholdCallback(object : LogThresholdCallback() {
            override fun shouldUpdate() {
                logMINOR = Logger.shouldLog(LogLevel.MINOR, this)
                logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this)
            }
        })
    }

    /**
     * Use this method when you want the value returned to be the run-time
     * version, not the build-time version.
     *
     * For example, if you compile your class, then modify this class and
     * compile it (the build script does this automatically), but don't
     * re-compile your original class, then that will still have the old
     * version compiled into it, since it is a static constant.
     *
     * @return The build number (not SVN revision number) of this node.
     */
    @JvmStatic
    fun buildNumber(): Int = buildNumber

    /** Analogous to [buildNumber] but for [publicVersion]. */
    @JvmStatic
    fun publicVersion(): String = publicVersion

    /** Analogous to [buildNumber] but for [transitionTime]. */
    @JvmStatic
    fun transitionTime(): Long = transitionTime

    /**
     * @return The lowest build number with which the node will connect and exchange
     * data normally.
     */
    @JvmStatic
    fun lastGoodBuild(): Int =
        if (System.currentTimeMillis() >= transitionTime) newLastGoodBuild else oldLastGoodBuild

    /** The highest reported build of fred */
    private var highestSeenBuild = buildNumber

    /** The current stable tree version */
    const val stableNodeVersion = "0.7"

    /** The stable protocol version supported */
    const val stableProtocolVersion = "STABLE-0.7"

    /** Oldest stable build of Fred we will talk to */
    const val lastGoodStableBuild = 1

    /** Revision number of Version.java as read from CVS */
    const val cvsRevision = "@git_rev@"

    /** Analogous to [buildNumber] but for [cvsRevision]. */
    @JvmStatic
    fun cvsRevision(): String = cvsRevision

    /** @return the node's version designators as an array */
    @JvmStatic
    fun getVersion(): Array<String> =
        arrayOf(nodeName, nodeVersion, protocolVersion, buildNumber.toString())

    @JvmStatic
    fun getLastGoodVersion(): Array<String> =
        arrayOf(nodeName, nodeVersion, protocolVersion, lastGoodBuild().toString())

    /** @return the version string that should be presented in the NodeReference */
    @JvmStatic
    fun getVersionString(): String = Fields.commaList(getVersion())

    /** @return is needed for the freeviz */
    @JvmStatic
    fun getLastGoodVersionString(): String = Fields.commaList(getLastGoodVersion())

    /** @return true if requests should be accepted from nodes brandishing this protocol version string */
    private fun goodProtocol(prot: String): Boolean {
        // uncomment next line to accept stable, see also explainBadVersion() below
        //                      || prot.equals(stableProtocolVersion)
        return prot == protocolVersion
    }

    /**
     * @return true if requests should be accepted from nodes brandishing this
     * version string
     */
    @JvmStatic
    fun checkGoodVersion(version: String?): Boolean {
        if (version == null) {
            Logger.error(Version::class.java, "version == null!", Exception("error"))
            return false
        }
        val v = Fields.commaList(version)
        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            return false
        }
        if (sameVersion(v)) {
            try {
                val build = v[3].toInt()
                val req = lastGoodBuild()
                if (build < req) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting unstable from version: " + version + "(lastGoodBuild=" + req + ')'
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                if (logMINOR)
                    Logger.minor(Version::class.java,
                        "Not accepting (" + e + ") from " + version)
                return false
            }
        }
        if (stableVersion(v)) {
            try {
                val build = v[3].toInt()
                if (build < lastGoodStableBuild) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting stable from version" + version + "(lastGoodStableBuild=" + lastGoodStableBuild + ')'
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                Logger.minor(
                    Version::class.java,
                    "Not accepting (" + e + ") from " + version
                )
                return false
            }
        }
        if (logDEBUG)
            Logger.minor(Version::class.java, "Accepting: " + version)
        return true
    }

    /**
     * @return true if requests should be accepted from nodes brandishing this
     * version string, given an arbitrary lastGoodVersion
     */
    @JvmStatic
    fun checkArbitraryGoodVersion(version: String?, lastGoodVersion: String?): Boolean {
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
        if (sameArbitraryVersion(v, lgv)) {
            try {
                val build = v[3].toInt()
                val minBuild = lgv[3].toInt()
                if (build < minBuild) {
                    if (logDEBUG) Logger.debug(
                        Version::class.java,
                        "Not accepting unstable from version: " + version + "(lastGoodVersion=" + lastGoodVersion + ')'
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                if (logMINOR)
                    Logger.minor(
                        Version::class.java,
                        "Not accepting (" + e + ") from " + version + " and/or " + lastGoodVersion
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
                        "Not accepting stable from version" + version + "(lastGoodStableBuild=" + lastGoodStableBuild + ')'
                    )
                    return false
                }
            } catch (e: NumberFormatException) {
                Logger.minor(
                    Version::class.java,
                    "Not accepting (" + e + ") from " + version
                )
                return false
            }
        }
        if (logDEBUG)
            Logger.minor(Version::class.java, "Accepting: " + version)
        return true
    }

    /**
     * @return string explaining why a version string is rejected
     */
    @JvmStatic
    fun explainBadVersion(version: String): String? {
        val v = Fields.commaList(version)

        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            return "Required protocol version is " +
                protocolVersion
            // uncomment next line if accepting stable, see also goodProtocol() above
            // + " or " + stableProtocolVersion
        }
        if (sameVersion(v)) {
            return try {
                val build = v[3].toInt()
                val req = lastGoodBuild()
                if (build < req)
                    "Build older than last good build " + req
                else null
            } catch (e: NumberFormatException) {
                "Build number not numeric."
            }
        }
        if (stableVersion(v)) {
            return try {
                val build = v[3].toInt()
                if (build < lastGoodStableBuild)
                    "Build older than last good stable build " + lastGoodStableBuild
                else null
            } catch (e: NumberFormatException) {
                "Build number not numeric."
            }
        }
        return null
    }

    /**
     * @return the build number of an arbitrary version string
     */
    @JvmStatic
    @Throws(VersionParseException::class)
    fun getArbitraryBuildNumber(version: String?): Int {
        if (version == null) {
            Logger.error(Version::class.java, "version == null!", Exception("error"))
            throw VersionParseException("version == null")
        }
        val v = Fields.commaList(version)

        if (v == null || v.size < 3 || !goodProtocol(v[2])) {
            throw VersionParseException("not long enough or bad protocol: " + version)
        }
        try {
            return v[3].toInt()
        } catch (e: NumberFormatException) {
            throw VersionParseException("Got NumberFormatException on " + v[3] + " : " + e + " for " + version).initCause(e) as VersionParseException
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

    /**
     * Update static variable highestSeenBuild anytime we encounter
     * a new node with a higher version than we've seen before
     */
    @JvmStatic
    fun seenVersion(version: String?) {
        val v = Fields.commaList(version)

        if (v == null || v.size < 3)
            return  // bad, but that will be discovered elsewhere

        if (sameVersion(v)) {
            val buildNo = try {
                v[3].toInt()
            } catch (e: NumberFormatException) {
                return
            }
            if (buildNo > highestSeenBuild) {
                if (logMINOR) {
                    Logger.minor(
                        Version::class.java,
                        "New highest seen build: " + buildNo
                    )
                }
                highestSeenBuild = buildNo
            }
        }
    }

    @JvmStatic
    fun getHighestSeenBuild(): Int = highestSeenBuild

    /**
     * @return true if the string describes the same node version as ours.
     * Note that the build number may be different, and is ignored.
     */
    @JvmStatic
    fun sameVersion(v: Array<String>): Boolean {
        return v[0] == "Fred" &&
            v[1] == "0.7" &&
            v.size >= 4
    }

    /**
     * @return true if the string describes the same node version as an arbitrary one.
     * Note that the build number may be different, and is ignored.
     */
    @JvmStatic
    fun sameArbitraryVersion(v: Array<String>, lgv: Array<String>): Boolean {
        return v[0] == lgv[0] &&
            v[1] == lgv[1] &&
            v.size >= 4 &&
            lgv.size >= 4
    }

    /**
     * @return true if the string describes a stable node version
     */
    private fun stableVersion(v: Array<String>): Boolean {
        return v[0] == "Fred" &&
            v[1] == stableNodeVersion &&
            v.size >= 4
    }
}
