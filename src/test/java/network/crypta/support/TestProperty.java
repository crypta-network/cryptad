package network.crypta.support;

/**
 * Provides property-backed flags and paths that control unit test behavior.
 *
 * <p>This class centralizes the small set of JVM system properties used by the test suite so that
 * individual tests do not need to repeat property keys or defaults. Typical usage is to read the
 * public constants directly in test setup or assertions, relying on the JVM's {@code -D} flags to
 * control behavior. The values are computed once when the class is loaded and then treated as
 * immutable constants for the lifetime of the test run.
 *
 * <p>Because these constants are derived from JVM properties, they are thread-safe and effectively
 * read-only. There is no mutable state, and no lifecycle beyond class initialization. Changing a
 * system property after class loading will not be reflected here, which keeps test behavior stable
 * for the duration of a run but means late changes are ignored.
 *
 * <ul>
 *   <li>Consolidates property keys and default values for test configuration.
 *   <li>Encodes file system locations used by localization-related tests.
 *   <li>Exposes boolean feature flags for optional or verbose test modes.
 * </ul>
 *
 * @author infinity0
 * @see Boolean#getBoolean(String)
 * @see System#getProperty(String, String)
 */
public final class TestProperty {

  /**
   * Enables benchmark-style tests that are normally disabled for fast, repeatable runs.
   *
   * <p>This value is {@code true} only when the JVM system property {@code test.benchmark} is set
   * to {@code true}. It is intended for long-running or performance-focused tests and should be
   * treated as a fixed, read-only flag after class initialization.
   */
  public static final boolean BENCHMARK = Boolean.getBoolean("test.benchmark");

  /**
   * Enables verbose test logging and extra assertions intended for interactive debugging.
   *
   * <p>This value reflects the JVM system property {@code test.verbose}. When enabled, tests may
   * emit additional diagnostic output or perform extra checks. The flag is read once at class load
   * time and remains constant for the duration of the test JVM.
   */
  public static final boolean VERBOSE = Boolean.getBoolean("test.verbose");

  /**
   * Enables broader or more exhaustive test coverage that may take longer to run.
   *
   * <p>This value is {@code true} only if the JVM system property {@code test.extensive} is set to
   * {@code true}. It should be used to gate optional tests or larger test data sets while
   * preserving deterministic behavior within a single run.
   */
  public static final boolean EXTENSIVE = Boolean.getBoolean("test.extensive");

  /**
   * Path to the test localization resources directory used by l10n tests.
   *
   * <p>The value comes from the JVM system property {@code test.l10npath_test}, falling back to
   * {@code test/network/crypta/l10n/} when unspecified. It is a fixed, read-only path string and
   * should be treated as a directory location rather than a file.
   */
  public static final String L10N_PATH_TEST =
      System.getProperty("test.l10npath_test", "test/network/crypta/l10n/");

  /**
   * Path to the main localization resources directory used by l10n tests.
   *
   * <p>The value comes from the JVM system property {@code test.l10npath_main}, falling back to
   * {@code src/network/crypta/l10n/} when unspecified. It is an immutable directory path string
   * intended for reading baseline localization resources.
   */
  public static final String L10N_PATH_MAIN =
      System.getProperty("test.l10npath_main", "src/network/crypta/l10n/");

  private TestProperty() {}
}
