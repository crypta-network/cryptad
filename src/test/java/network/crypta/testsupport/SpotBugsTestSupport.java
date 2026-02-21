package network.crypta.testsupport;

/** Test-only helpers used to consume return values in assertion/verification flows. */
@SuppressWarnings({"java:S1186", "java:S1172"})
public final class SpotBugsTestSupport {

  private SpotBugsTestSupport() {}

  public static void ignoreValue(Object ignored) {
    // Intentionally empty: explicit sink for return values in test-only assertion paths.
  }
}
