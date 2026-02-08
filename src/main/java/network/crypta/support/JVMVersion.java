package network.crypta.support;

import com.sun.jna.Platform;

/**
 * Utilities for interrogating and comparing the running JVM version.
 *
 * <p>This class normalizes Java version strings across the historical formats used by pre‑9 and
 * post‑9 releases and provides simple comparison and capability checks based on project-defined
 * thresholds. It is stateless and thread-safe.
 *
 * <p>Version string references:
 *
 * <ul>
 *   <li>Pre‑9 (legacy) format: {@code <major>.<feature>[.<maintenance>[_<update>]][-ident]}
 *   <li>Post‑9 (JEP 223) format: {@code <major>[.<minor>[.<security>[.<...>]]][-ident]}
 * </ul>
 *
 * Non-numeric identifiers (e.g., {@code -ea}, {@code -rc}) are ignored for comparison purposes.
 *
 * <p>See also: Oracle versioning note and JEP 223 — <a
 * href="http://www.oracle.com/technetwork/java/javase/versioning-naming-139433.html">pre‑9</a> and
 * <a href="http://openjdk.java.net/jeps/223">post‑9</a>.
 */
public class JVMVersion {

  private JVMVersion() {}

  /**
   * Java version below which the runtime is considered end-of-life for this application.
   *
   * <p>Versions are compared numerically using {@link #compareVersion(String, String)}; values
   * strictly less than this threshold are considered EOL. The constant is expressed using standard
   * Java version notation and may be a major-only version (for example, {@code "21"}).
   */
  public static final String EOL_THRESHOLD = "21";

  /**
   * Java version below which the legacy updater mechanism should be used.
   *
   * <p>Compared strictly using {@link #compareVersion(String, String)}; values below this threshold
   * require the legacy updater, while values at or above use the current updater.
   */
  public static final String UPDATER_THRESHOLD = "21";

  /**
   * Oldest Java version considered supporting the Java Platform Module System (JPMS).
   *
   * <p>Used by {@link #supportsModules()} to decide whether modules are available. The check is a
   * numeric comparison performed against the current runtime version.
   */
  public static final String SUPPORTS_MODULES_THRESHOLD = "1.9";

  /*
   * Parser notes:
   * The original regex-based parser was replaced by a small numeric tokenizer for readability,
   * maintainability, and to avoid backtracking pitfalls. See {@link #parse(String)} for details.
   */
  public static boolean isEOL() {
    // On Android, version policy is enforced at the App level; do not check here.
    return !Platform.isAndroid() && isEOL(getCurrent());
  }

  /**
   * Returns the current runtime's Java version string.
   *
   * <p>The value is read directly from the {@code java.version} system property and is not
   * normalized.
   *
   * @return the {@code java.version} system property; may be {@code null} if unset.
   */
  public static String getCurrent() {
    return System.getProperty("java.version");
  }

  /**
   * Reports whether a supplied Java version is below {@link #EOL_THRESHOLD}.
   *
   * @param version Java version string; {@code null} returns {@code false}.
   * @return {@code true} if {@code version} is strictly less than {@link #EOL_THRESHOLD}; otherwise
   *     {@code false}.
   */
  static boolean isEOL(String version) {
    if (version == null) {
      return false;
    }

    return compareVersion(version, EOL_THRESHOLD) < 0;
  }

  /**
   * Reports whether a supplied Java version should use the legacy updater path.
   *
   * @param version Java version string; {@code null} returns {@code false}.
   * @return {@code true} if {@code version} is strictly less than {@link #UPDATER_THRESHOLD};
   *     otherwise {@code false}.
   */
  static boolean needsLegacyUpdater(String version) {
    if (version == null) {
      return false;
    }

    return compareVersion(version, UPDATER_THRESHOLD) < 0;
  }

  /**
   * Detects whether the current JVM is a 32‑bit runtime.
   *
   * <p>Heuristic:
   *
   * <ul>
   *   <li>If {@code sun.arch.data.model} starts with {@code "32"}, returns {@code true}.
   *   <li>Otherwise, returns {@code true} when {@code os.arch} equals {@code "x86"}
   *       (case-insensitive).
   * </ul>
   *
   * The method avoids throwing exceptions if either property is missing.
   *
   * @return {@code true} for 32‑bit runtimes, {@code false} otherwise.
   */
  public static boolean is32Bit() {
    String arch = System.getProperty("os.arch");
    boolean is32bitOS = "x86".equalsIgnoreCase(arch);
    String model = System.getProperty("sun.arch.data.model");
    return (model != null && model.startsWith("32")) || is32bitOS;
  }

  /**
   * Checks whether the current runtime is new enough to support JPMS modules.
   *
   * <p>Reads {@code java.version} and compares it to {@link #SUPPORTS_MODULES_THRESHOLD}. Versions
   * equal to or greater than the threshold are considered to support modules.
   *
   * @return {@code true} if modules are supported; {@code false} if the version is unknown
   *     (property missing) or below the threshold.
   */
  public static boolean supportsModules() {
    String currentVersion = getCurrent();
    if (currentVersion == null) {
      return false;
    }

    return compareVersion(SUPPORTS_MODULES_THRESHOLD, currentVersion) <= 0;
  }

  /**
   * Parses a Java version string into four numeric parts.
   *
   * <p>The parser scans left-to-right and extracts up to the first four integer tokens it finds,
   * ignoring any non-numeric separators or identifiers (such as {@code .}, {@code _}, or {@code
   * -ea}). The components map to: {@code [major, minor/feature, maintenance/security, update]}.
   * Missing components default to {@code 0}. If a token cannot be parsed (overflow or invalid),
   * that component is treated as {@code 0} and parsing continues.
   *
   * <p>Examples:
   *
   * <ul>
   *   <li>{@code "1.7.1_09"} → {@code [1, 7, 1, 9]}
   *   <li>{@code "9.0.1.1.0.1-ea"} → {@code [9, 0, 1, 1]}
   *   <li>{@code "21"} → {@code [21, 0, 0, 0]}
   * </ul>
   *
   * @param version Java version string; may be {@code null}.
   * @return an array of size 4 containing the parsed components; returns all zeros for {@code null}
   *     or when no numeric tokens are found.
   */
  static int[] parse(String version) {
    int[] parsed = new int[4];
    if (version == null) {
      return parsed;
    }
    int count = 0;
    int i = 0;
    final int len = version.length();
    while (i < len && count < 4) {
      char ch = version.charAt(i);
      if (Character.isDigit(ch)) {
        int start = i;
        do {
          i++;
        } while (i < len && Character.isDigit(version.charAt(i)));
        try {
          parsed[count] = Integer.parseInt(version.substring(start, i));
        } catch (NumberFormatException _) {
          // Treat overflow or unexpected content as zero for this component
          parsed[count] = 0;
        }
        count++;
      } else {
        i++;
      }
    }
    return parsed;
  }

  /**
   * Compares two Java version strings numerically.
   *
   * <p>Both inputs are parsed with {@link #parse(String)} and compared component-wise (major,
   * minor/feature, maintenance/security, update). Identifiers and additional trailing components in
   * the original string are ignored.
   *
   * @param version1 first version string; may be {@code null}.
   * @param version2 second version string; may be {@code null}.
   * @return a negative value if {@code version1} is less than {@code version2}, zero if they are
   *     equal, and a positive value otherwise.
   */
  static int compareVersion(String version1, String version2) {
    int[] parsed1 = parse(version1);
    int[] parsed2 = parse(version2);
    for (int i = 0; i < 4; i++) {
      if (parsed1[i] < parsed2[i]) {
        return -1;
      }
      if (parsed1[i] > parsed2[i]) {
        return 1;
      }
    }
    return 0;
  }
}
