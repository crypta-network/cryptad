package network.crypta.node;

import java.util.Arrays;
import network.crypta.support.Fields;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Version information and helpers for the Cryptad node.
 *
 * <p>This class is the canonical source for node identity values, wire-version descriptors, and
 * compatibility decisions used during peer negotiation. It exposes both static constants and helper
 * methods that parse and compare serialized version strings exchanged by peers. Callers use these
 * helpers to answer whether a remote peer is acceptable, to extract build identifiers from
 * user-visible version text, and to track the highest build observed in the network.
 *
 * <p>All methods are static and side effects are intentionally limited to updating a single
 * in-process "highest seen build" counter. Returned version component arrays are defensive copies,
 * so callers cannot mutate internal cached values. Logging is used for rejection diagnostics but
 * does not alter compatibility outcomes.
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
  private static final String[] EMPTY_VERSION_COMPONENTS = new String[0];

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

  /**
   * Returns the build number embedded at runtime.
   *
   * @return current node build number resolved during class initialization
   */
  public static int currentBuildNumber() {
    return BUILD_NUMBER;
  }

  /**
   * Returns the Git revision string embedded at build time.
   *
   * @return build-time Git revision token for this runtime
   */
  public static String gitRevision() {
    return GIT_REVISION;
  }

  /**
   * Returns the current node version tuple as components.
   *
   * @return a new array containing node name, build, protocol, and compatibility build fields
   */
  public static String[] getVersionComponents() {
    return Arrays.copyOf(CACHED_VERSION_COMPONENTS, CACHED_VERSION_COMPONENTS.length);
  }

  /**
   * Returns minimum acceptable peer-version components for Fred compatibility.
   *
   * @return a new array containing the minimum acceptable wire peer descriptor components
   */
  public static String[] getMinAcceptableVersionComponents() {
    return Arrays.copyOf(
        CACHED_MIN_ACCEPTABLE_VERSION_COMPONENTS, CACHED_MIN_ACCEPTABLE_VERSION_COMPONENTS.length);
  }

  /**
   * Returns the current node version in serialized wire format.
   *
   * @return comma-separated version string advertised to remote peers
   */
  public static String getVersionString() {
    return Fields.commaList(getVersionComponents());
  }

  /**
   * Returns the serialized minimum acceptable peer-version descriptor.
   *
   * @return comma-separated minimum acceptable version string
   */
  public static String getMinAcceptableVersionString() {
    return Fields.commaList(getMinAcceptableVersionComponents());
  }

  /**
   * Checks whether a peer version string is compatible with this node.
   *
   * @param version peer-reported serialized version string to validate
   * @return {@code true} when the version parses successfully and passes compatibility checks
   */
  public static boolean isCompatibleVersion(String version) {
    String[] v = parseVersionOrNull(version);
    if (v.length == 0) {
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

  /**
   * Checks compatibility using the peer version and its stated minimum acceptable version.
   *
   * @param versionStr peer-reported serialized version string
   * @param lastGoodVersionStr peer-reported minimum acceptable version string
   * @return {@code true} when both descriptors parse and satisfy compatibility rules
   */
  public static boolean isCompatibleVersionWithLastGood(
      String versionStr, String lastGoodVersionStr) {
    String[] v = parseVersionOrNull(versionStr);
    if (v.length == 0) {
      return false;
    }
    String[] lgv = parseVersionOrNull(lastGoodVersionStr, "lastGoodVersion");
    if (lgv.length == 0) {
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
   * @param version serialized peer version string to parse
   * @return parsed build number extracted from the provided version descriptor
   * @throws VersionParseException if the version string format is invalid
   */
  public static int parseBuildNumberFromVersionStr(String version) throws VersionParseException {
    if (version == null) {
      LOG.error("version == null!", new Exception("error"));
      throw new IllegalArgumentException("version == null");
    }

    String[] v = Fields.commaList(version);
    if (v.length < 3 || hasInvalidProtocol(v[2])) {
      throw new VersionParseException("not long enough or bad protocol: " + version);
    }

    try {
      if (NODE_NAME.equals(v[0])) {
        return Integer.parseInt(v[1]);
      }
      if (WIRE_NAME.equals(v[0])) {
        if (v.length == 3) {
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

  /**
   * Parses a build number and falls back to a default when parsing fails.
   *
   * @param version serialized peer version string to parse
   * @param defaultValue fallback value returned when parsing fails
   * @return parsed build number, or {@code defaultValue} if parsing throws
   */
  public static int parseBuildNumberFromVersionStr(String version, int defaultValue) {
    try {
      return parseBuildNumberFromVersionStr(version);
    } catch (Exception _) {
      return defaultValue;
    }
  }

  /**
   * Records a peer version and updates the highest seen build when applicable.
   *
   * @param versionStr serialized peer version string observed from the network
   */
  public static void seenVersion(String versionStr) {
    String[] v = Fields.commaList(versionStr);
    if (v.length < 3) {
      return;
    }

    int version;
    try {
      if (NODE_NAME.equals(v[0])) {
        version = Integer.parseInt(v[1]);
      } else if (WIRE_NAME.equals(v[0])) {
        if (v.length == 3) {
          return;
        }
        version = Integer.parseInt(v[3]);
      } else {
        return;
      }
    } catch (Exception _) {
      return;
    }

    if (version > highestSeenBuild) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("New highest seen build: {}", version);
      }
      highestSeenBuild = version;
    }
  }

  /**
   * Returns the highest peer build number observed in this process.
   *
   * @return highest build number accepted by {@link #seenVersion(String)}
   */
  public static int getHighestSeenBuild() {
    return highestSeenBuild;
  }

  /**
   * Returns whether parsed version components identify a Cryptad node.
   *
   * @param v parsed version components array to inspect
   * @return {@code true} when the first component identifies {@link #NODE_NAME}
   */
  public static boolean isCryptad(String[] v) {
    return v.length >= 2 && NODE_NAME.equals(v[0]);
  }

  /**
   * Returns whether two parsed version arrays belong to compatible release series.
   *
   * @param v parsed peer version components
   * @param lgv parsed peer "last good" version components
   * @return {@code true} when both arrays represent a compatible version family
   */
  @SuppressWarnings("unused")
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

  private static boolean hasInvalidProtocol(String protocol) {
    return !LAST_GOOD_FRED_PROTOCOL_VERSION.equals(protocol);
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
      return EMPTY_VERSION_COMPONENTS;
    }
    String[] v = Fields.commaList(version);
    if (v.length < 3 || hasInvalidProtocol(v[2])) {
      return EMPTY_VERSION_COMPONENTS;
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
   *
   * @param nodeName1 node-name component for the first build number
   * @param buildNumber1 first build number to compare
   * @param nodeName2 node-name component for the second build number
   * @param buildNumber2 second build number to compare
   * @return a negative value, zero, or a positive value following {@link Integer#compare(int, int)}
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
   *
   * @param nodeName peer node-name component
   * @param buildNumber peer build number
   * @param minBuildNumber minimum acceptable build number for non-Cryptad peers
   * @return {@code true} when the peer satisfies minimum build requirements
   */
  public static boolean isBuildAtLeast(String nodeName, int buildNumber, int minBuildNumber) {
    if (NODE_NAME.equals(nodeName)) {
      return true;
    }
    return buildNumber >= minBuildNumber;
  }

  /**
   * Extracts the node-name component from a serialized version string.
   *
   * @param version serialized version string to parse
   * @return first version component, or {@code null} when missing or input is {@code null}
   */
  public static String parseNodeNameFromVersionStr(String version) {
    if (version == null) {
      return null;
    }
    String[] parts = Fields.commaList(version);
    return parts.length > 0 ? parts[0] : null;
  }

  @SuppressWarnings("DataFlowIssue")
  private static int computeBuildNumber() {
    try {
      return Integer.parseInt(BUILD_NUMBER_STRING);
    } catch (NumberFormatException _) {
      return 0;
    }
  }

  private static Integer parseIntOrNull(String s) {
    if (s == null) {
      return null;
    }
    try {
      return Integer.parseInt(s);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  private static String getOrNull(String[] arr, int index) {
    return index >= 0 && index < arr.length ? arr[index] : null;
  }
}
