package network.crypta.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CryptadConfigExpandEdgeCasesTest {

  @TempDir Path tmp;

  private Map<String, String> base() {
    Map<String, String> b = new HashMap<>();
    Path root = tmp;
    b.put("configDir", root.resolve("cfg").toString());
    b.put("dataDir", root.resolve("data").toString());
    b.put("stateDir", root.resolve("data").toString());
    b.put("cacheDir", root.resolve("cache").toString());
    b.put("runDir", root.resolve("run").toString());
    b.put("logsDir", root.resolve("logs").toString());
    b.put("home", root.resolve("home").toString());
    b.put("tmp", root.resolve("tmp").toString());
    return b;
  }

  @Test
  void leadingToken_backslashes_normalizesWithinBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("dataDir\\foo\\..\\bar", b);
    assertEquals(out, Path.of(b.get("dataDir"), "bar").toString());
  }

  @Test
  void leadingToken_posixSegments_normalizesWithinBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("cacheDir/./tmp/../persist", b);
    assertEquals(out, Path.of(b.get("cacheDir"), "persist").toString());
  }

  // Mixed separators after a leading token should be handled uniformly.
  // This verifies cross-platform behavior when '/' and '\\' are interleaved.
  @Test
  void leadingToken_mixedSeparators_normalizesWithinBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("dataDir/foo\\bar/baz", b);
    assertEquals(out, Path.of(b.get("dataDir"), "foo", "bar", "baz").toString());
  }

  @Test
  void placeholder_equality_resolvesToBase() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("${logsDir}", b);
    assertEquals(out, Path.of(b.get("logsDir")).normalize().toString());
  }

  @Test
  void placeholder_windowsTraversal_rejectedWhenAnchored() {
    Map<String, String> b = base();
    assertThrows(
        IOException.class, () -> CryptadConfig.expandValue("${dataDir}\\..\\..\\etc\\passwd", b));
  }

  @Test
  void placeholder_inMiddle_isReplaced() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("prefix-${cacheDir}-suffix", b);
    assertEquals(out, "prefix-" + b.get("cacheDir") + "-suffix");
  }

  @Test
  void placeholder_inMiddle_withTraversal_rejected() {
    Map<String, String> b = base();
    assertThrows(
        IOException.class,
        () -> CryptadConfig.expandValue("prefix-${dataDir}/../../etc/passwd", b));
  }

  @Test
  void leadingToken_backslashDot_normalizes() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue("runDir\\.", b);
    assertEquals(out, Path.of(b.get("runDir")).normalize().toString());
  }

  // When the configured base looks like a Windows path, inputs that mix
  // Windows ('\\') and POSIX ('/') separators should still anchor and
  // normalize correctly under that base.
  @Test
  void anchored_mixedSeparators_withWindowsStyleBase_normalizes() {
    Map<String, String> b = new HashMap<>();
    b.put("dataDir", "C:\\base\\dir");
    String out = CryptadConfig.expandValue("C:/base/dir\\x/y\\z", b);
    // Expect it to anchor to the provided base and resolve the mixed remainder
    assertEquals(out, Path.of(b.get("dataDir"), "x", "y", "z").toString());
  }

  // Even with a POSIX-looking base, incoming backslashes are normalized in
  // comparisons and resolution so that anchoring and normalization are consistent.
  @Test
  void anchored_mixedSeparators_withPosixBase_normalizes() {
    Map<String, String> b = base();
    String out = CryptadConfig.expandValue(b.get("dataDir") + "\\x\\y", b);
    assertEquals(out, Path.of(b.get("dataDir"), "x", "y").toString());
  }

  // Mixed traversal using interleaved separators must be rejected when it would
  // escape the base directory after normalization.
  @Test
  void leadingToken_mixedTraversal_rejected() {
    Map<String, String> b = base();
    assertThrows(IOException.class, () -> CryptadConfig.expandValue("dataDir/..\\..\\evil", b));
  }
}
