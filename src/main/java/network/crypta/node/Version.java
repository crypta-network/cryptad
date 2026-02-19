package network.crypta.node;

import java.util.Arrays;
import network.crypta.support.Fields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Version information and helpers for the Cryptad node.
 *
 * <p>Centralizes version strings, protocol constants, compatibility checks, and parsing helpers.
 */
public final class Version {
  /** Human-readable product name of the node. */
  public static final String NODE_NAME = "Cryptad";

  /** Minimum acceptable build for stable Fred peers. */
  public static final int LAST_GOOD_FRED_STABLE_BUILD = 1;

  /** Protocol version the node speaks on the wire. */
  public static final String LAST_GOOD_FRED_PROTOCOL_VERSION = "1.0";

  /** Git revision embedded at build time. */
  public static final String GIT_REVISION = "@git_rev@";

  /** Minimum acceptable build number for Cryptad peers. */
  public static final int MIN_ACCEPTABLE_CRYPTAD_BUILD_NUMBER = 1;

  /** Minimum acceptable build number for Freenet peers. */
  public static final int MIN_ACCEPTABLE_FRED_BUILD_NUMBER = 1475;

  // Private constants
  private static final String BUILD_NUMBER_STRING = "@build_number@";
  private static final String WIRE_NAME = "Fred";
  private static final String STABLE_FRED_NODE_VERSION = "0.7";

  private static final int BUILD_NUMBER = computeBuildNumber();
  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.node.Version");

  private static volatile int highestSeenBuild = BUILD_NUMBER;

  private static final String[] CACHED_VERSION_COMPONENTS = {
    NODE_NAME,
    Integer.toString(BUILD_NUMBER),
    LAST_GOOD_FRED_PROTOCOL_VERSION,
    Integer.toString(BUILD_NUMBER)
  };

  private static final String[] CACHED_MIN_ACCEPTABLE_VERSION_COMPONENTS = {
    WIRE_NAME,
    STABLE_FRED_NODE_VERSION,
    LAST_GOOD_FRED_PROTOCOL_VERSION,
    Integer.toString(MIN_ACCEPTABLE_FRED_BUILD_NUMBER)
  };

  private Version() {}

  /** Returns the current build number at runtime (not inlined). */
  public static int currentBuildNumber() {
    return BUILD_NUMBER;
  }

  /** Runtime accessor for {@link #GIT_REVISION}. */
  public static String gitRevision() {
    return GIT_REVISION;
  }

  /** Returns current node version components. */
  public static String[] getVersionComponents() {
    return Arrays.copyOf(CACHED_VERSION_COMPONENTS, CACHED_VERSION_COMPONENTS.length);
  }

  /** Returns minimum acceptable version components for Fred compatibility. */
  public static String[] getMinAcceptableVersionComponents() {
    return Arrays.copyOf(
        CACHED_MIN_ACCEPTABLE_VERSION_COMPONENTS, CACHED_MIN_ACCEPTABLE_VERSION_COMPONENTS.length);
  }

  /** Returns the comma-separated version string used on the wire. */
  public static String getVersionString() {
    return Fields.commaList(getVersionComponents());
  }

  /** Returns the comma-separated minimum acceptable version string. */
  public static String getMinAcceptableVersionString() {
    return Fields.commaList(getMinAcceptableVersionComponents());
  }

  /** Checks whether a peer version string is compatible with this node. */
  public static boolean isCompatibleVersion(String version) {
    String[] v = parseVersionOrNull(version);
    if (v == null) {
      return false;
    }
    if (rejectIfCryptadTooOld(v, version)) {
      return false;
    }
    if (rejectIfFredTooOld(v, version)) {
      return false;
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Accepting peer version string: {}", version);
    }
    return true;
  }

  /** Checks compatibility using a peer-provided minimum acceptable version. */
  public static boolean isCompatibleVersionWithLastGood(
      String versionStr, String lastGoodVersionStr) {
    String[] v = parseVersionOrNull(versionStr);
    if (v == null) {
      return false;
    }
    String[] lgv = parseVersionOrNull(lastGoodVersionStr, "lastGoodVersion");
    if (lgv == null) {
      return false;
    }

    if (NODE_NAME.equals(v[0])
        && NODE_NAME.equals(lgv[0])
        && !checkCryptadCompatibility(v, lgv, versionStr, lastGoodVersionStr)) {
      return false;
    }

    if (WIRE_NAME.equals(v[0]) && !checkFredCompatibility(v, lgv, versionStr, lastGoodVersionStr)) {
      return false;
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("Accepting peer version with lastGood: {}", versionStr);
    }
    return true;
  }

  /**
   * Parses a version string and extracts its build number.
   *
   * @throws VersionParseException if the version string is invalid.
   */
  public static int parseBuildNumberFromVersionStr(String version) throws VersionParseException {
    if (version == null) {
      LOG.error("version == null!", new Exception("error"));
      throw new IllegalArgumentException("version == null");
    }

    String[] v = Fields.commaList(version);
    if (v.length < 3 || !isValidProtocol(v[2])) {
      throw new VersionParseException("not long enough or bad protocol: " + version);
    }

    try {
      if (NODE_NAME.equals(v[0])) {
        return Integer.parseInt(v[1]);
      }
      if (WIRE_NAME.equals(v[0])) {
        if (v.length <= 3) {
          throw new VersionParseException("Fred version missing build number: " + version);
        }
        return Integer.parseInt(v[3]);
      }
      throw new VersionParseException("unknown node name: " + v[0]);
    } catch (NumberFormatException e) {
      String bad = v.length > 3 ? v[3] : null;
      VersionParseException wrapped =
          new VersionParseException(
              "Got NumberFormatException on " + bad + " : " + e + " for " + version);
      wrapped.initCause(e);
      throw wrapped;
    }
  }

  /** Parses build number with a default fallback. */
  public static int parseBuildNumberFromVersionStr(String version, int defaultValue) {
    try {
      return parseBuildNumberFromVersionStr(version);
    } catch (Throwable ignored) {
      return defaultValue;
    }
  }

  /** Records the highest build number observed among peers. */
  public static void seenVersion(String versionStr) {
    String[] v = Fields.commaList(versionStr);
    if (v.length < 3) {
      return;
    }

    Integer version = null;
    try {
      if (NODE_NAME.equals(v[0])) {
        version = Integer.parseInt(v[1]);
      } else if (WIRE_NAME.equals(v[0])) {
        if (v.length <= 3) {
          return;
        }
        version = Integer.parseInt(v[3]);
      } else {
        return;
      }
    } catch (Throwable ignored) {
      return;
    }

    if (version > highestSeenBuild) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("New highest seen build: {}", version);
      }
      highestSeenBuild = version;
    }
  }

  /** Returns the highest build number observed from peers. */
  public static int getHighestSeenBuild() {
    return highestSeenBuild;
  }

  /** Returns true if version components refer to a Cryptad node. */
  public static boolean isCryptad(String[] v) {
    return v.length >= 2 && NODE_NAME.equals(v[0]);
  }

  /** Returns true when two version arrays represent compatible series. */
  public static boolean isCompatibleSeries(String[] v, String[] lgv) {
    if (v.length < 2 || lgv.length < 2) {
      return false;
    }
    return switch (v[0]) {
      case NODE_NAME -> true; // Cryptad compatible with Fred
      case WIRE_NAME -> v[1].equals(lgv[1]) && v.length >= 4 && lgv.length >= 4;
      default -> false;
    };
  }

  private static boolean isValidProtocol(String protocol) {
    return LAST_GOOD_FRED_PROTOCOL_VERSION.equals(protocol);
  }

  private static boolean checkCryptadCompatibility(
      String[] v, String[] lgv, String versionStr, String lastGoodVersionStr) {
    Integer version = parseIntOrNull(getOrNull(v, 1));
    Integer minVersion = parseIntOrNull(getOrNull(lgv, 1));
    return isNumberAtLeast(version, minVersion, versionStr, lastGoodVersionStr);
  }

  private static boolean checkFredCompatibility(
      String[] v, String[] lgv, String versionStr, String lastGoodVersionStr) {
    if (lgv.length > 0 && NODE_NAME.equals(lgv[0])) {
      return false;
    }
    if (rejectIfFredTooOld(v, versionStr)) {
      return false;
    }
    Integer build = parseIntOrNull(getOrNull(v, 3));
    Integer minBuild = parseIntOrNull(getOrNull(lgv, 3));
    return isNumberAtLeast(build, minBuild, versionStr, lastGoodVersionStr);
  }

  private static String[] parseVersionOrNull(String version) {
    return parseVersionOrNull(version, "version");
  }

  private static String[] parseVersionOrNull(String version, String label) {
    if (version == null) {
      LOG.error("{} == null!", label, new Exception("error"));
      return null;
    }
    String[] v = Fields.commaList(version);
    if (v.length < 3 || !isValidProtocol(v[2])) {
      return null;
    }
    return v;
  }

  private static boolean isNumberAtLeast(
      Integer actual, Integer min, String versionStr, String lastGoodVersionStr) {
    if (actual == null || min == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Rejecting version due to non-numeric build (compat check): version={}"
                + " lastGoodVersion={}",
            versionStr,
            lastGoodVersionStr);
      }
      return false;
    }

    if (actual < min) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Rejecting version below minimum (compat check): version={} lastGoodVersion={}",
            versionStr,
            lastGoodVersionStr);
      }
      return false;
    }

    return true;
  }

  private static boolean rejectIfCryptadTooOld(String[] v, String original) {
    if (!isCryptad(v)) {
      return false;
    }
    Integer version = parseIntOrNull(getOrNull(v, 1));
    int req = MIN_ACCEPTABLE_CRYPTAD_BUILD_NUMBER;

    if (version == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Rejecting Cryptad version with non-numeric build: {}", original);
      }
      return true;
    }
    if (version < req) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Rejecting Cryptad version below minimum build: {}"
                + " (minAcceptableCryptadBuildNumber={})",
            original,
            req);
      }
      return true;
    }
    return false;
  }

  private static boolean rejectIfFredTooOld(String[] v, String original) {
    if (!isFredStableVersion(v)) {
      return false;
    }

    Integer build = parseIntOrNull(getOrNull(v, 3));
    if (build == null) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Rejecting Fred stable version with non-numeric build: {}", original);
      }
      return true;
    }

    if (build < LAST_GOOD_FRED_STABLE_BUILD) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Rejecting Fred stable version below last good build: {} (lastGoodStableBuild={})",
            original,
            LAST_GOOD_FRED_STABLE_BUILD);
      }
      return true;
    }
    return false;
  }

  private static boolean isFredStableVersion(String[] v) {
    return v.length >= 4 && WIRE_NAME.equals(v[0]) && STABLE_FRED_NODE_VERSION.equals(v[1]);
  }

  /**
   * Compares two build numbers considering node names first.
   *
   * <p>Cryptad nodes are always considered newer than Fred nodes.
   */
  public static int compareBuildNumbers(
      String nodeName1, int buildNumber1, String nodeName2, int buildNumber2) {
    if (nodeName1 == null || nodeName2 == null) {
      return Integer.compare(buildNumber1, buildNumber2);
    }

    if (NODE_NAME.equals(nodeName1) && WIRE_NAME.equals(nodeName2)) {
      return 1;
    }
    if (WIRE_NAME.equals(nodeName1) && NODE_NAME.equals(nodeName2)) {
      return -1;
    }
    return Integer.compare(buildNumber1, buildNumber2);
  }

  /**
   * Checks if a peer's build is at least the specified minimum build number, considering node name.
   */
  public static boolean isBuildAtLeast(String nodeName, int buildNumber, int minBuildNumber) {
    if (NODE_NAME.equals(nodeName)) {
      return true;
    }
    return buildNumber >= minBuildNumber;
  }

  /** Extracts the node name from a version string, or null when absent/invalid. */
  public static String parseNodeNameFromVersionStr(String version) {
    if (version == null) {
      return null;
    }
    String[] parts = Fields.commaList(version);
    return parts.length > 0 ? parts[0] : null;
  }

  private static int computeBuildNumber() {
    if (BUILD_NUMBER_STRING.startsWith("@") && BUILD_NUMBER_STRING.endsWith("@")) {
      return 0;
    }
    try {
      return Integer.parseInt(BUILD_NUMBER_STRING);
    } catch (NumberFormatException ignored) {
      return 0;
    }
  }

  private static Integer parseIntOrNull(String s) {
    if (s == null) {
      return null;
    }
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  private static String getOrNull(String[] arr, int index) {
    return index >= 0 && index < arr.length ? arr[index] : null;
  }
}
