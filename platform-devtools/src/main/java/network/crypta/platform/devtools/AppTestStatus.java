package network.crypta.platform.devtools;

/**
 * Stable status values for {@code crypta-app test} reports.
 *
 * <p>The enum is shared by individual checks and the aggregate report status. The JSON spelling is
 * lower-case and intentionally decoupled from the Java enum name so CLI reports can remain stable
 * if Java naming conventions or internal grouping change later. Strict mode does not introduce a
 * separate status; it promotes warning checks to a failed aggregate report before serialization.
 */
enum AppTestStatus {
  /** The check or aggregate report completed without warnings or failures. */
  PASS("pass"),

  /** The check found a developer-visible issue that is non-fatal unless strict mode promotes it. */
  WARN("warn"),

  /** The check or aggregate report failed and should produce a non-zero CLI exit. */
  FAIL("fail");

  /** Stable lower-case token written into JSON reports and human summaries. */
  private final String jsonValue;

  /**
   * Creates one status value.
   *
   * @param jsonValue stable lower-case value serialized in schema version {@code 1}
   */
  AppTestStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the schema-stable JSON spelling for this status.
   *
   * @return lower-case status token used by {@link AppTestReportJson}
   */
  String jsonValue() {
    return jsonValue;
  }
}
