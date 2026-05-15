package network.crypta.platform.devtools;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppTestReportJsonTest {
  @Test
  void write_whenReportContainsPathsAndControls_expectEscapedRedactedJson() {
    AppTestReport report =
        new AppTestReport(
            1,
            "/Users/alice/My Keys/app.properties",
            "0.1.0",
            AppTestStatus.WARN,
            List.of(
                new AppTestCheck(
                    "fixture.path",
                    AppTestStatus.WARN,
                    "Missing C:\\Users\\Alice Keys\\trusted.pem \"quoted\"\nnext\tfield")));

    String json = AppTestReportJson.write(report);

    assertTrue(json.contains("\"appId\": \"[REDACTED_PATH]\""));
    assertTrue(json.contains("\\\"quoted\\\"\\nnext\\tfield"));
    assertFalse(json.contains("My Keys"));
    assertFalse(json.contains("Alice Keys"));
    assertFalse(json.contains("trusted.pem"));
  }

  @Test
  void constructor_whenSchemaVersionUnsupported_expectFailure() {
    List<AppTestCheck> checks = List.of();

    assertThrows(
        IllegalArgumentException.class,
        () -> new AppTestReport(2, "sample", "0.1.0", AppTestStatus.PASS, checks));
  }
}
