package network.crypta.crypt;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;
import javax.crypto.KeyAgreement;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S106", "java:S112"})
class JceLoaderTest {

  private static final String PROP_FALSE = "false";

  @Test
  @DisplayName("defaultLoad_whenNoProps_expectBCSunPresentAndNSSAbsent")
  void defaultLoad_whenNoProps_expectBCSunPresentAndNSSAbsent() throws Exception {
    ProcessResult res = runProbe(Map.of());

    assertEquals(0, res.exitCode, "child JVM must exit cleanly");
    assertTrue(res.stdout.contains("BouncyCastle=true"), res.stdout);
    assertTrue(res.stdout.contains("SUN=true"), res.stdout);
    assertTrue(res.stdout.contains("SunJCE=true"), res.stdout);
    // NSS defaults to disabled unless explicitly enabled via -Dcrypta.jce.use.NSS=true
    assertTrue(res.stdout.contains("NSS=false"), res.stdout);
    // Algorithms from BC must be usable when BC is present
    assertTrue(res.stdout.contains("BC_ECDH_ALG_OK=true"), res.stdout);
    assertTrue(res.stdout.contains("BC_ECDSA_SHA256_ALG_OK=true"), res.stdout);
  }

  @Test
  @DisplayName("disabledProviders_whenPropsFalse_expectAllProvidersNull")
  void disabledProviders_whenPropsFalse_expectAllProvidersNull() throws Exception {
    ProcessResult res =
        runProbe(
            Map.of(
                "crypta.jce.use.BC.I.know.what.I.am.doing",
                PROP_FALSE,
                "crypta.jce.use.SunJCE",
                PROP_FALSE,
                "crypta.jce.use.SUN",
                PROP_FALSE,
                "crypta.jce.use.NSS",
                PROP_FALSE));

    assertEquals(0, res.exitCode, "child JVM must exit cleanly");
    assertTrue(res.stdout.contains("BouncyCastle=false"), res.stdout);
    assertTrue(res.stdout.contains("SUN=false"), res.stdout);
    assertTrue(res.stdout.contains("SunJCE=false"), res.stdout);
    assertTrue(res.stdout.contains("NSS=false"), res.stdout);
    assertTrue(res.stdout.contains("BC_ECDH_ALG_OK=false"), res.stdout);
    assertTrue(res.stdout.contains("BC_ECDSA_SHA256_ALG_OK=false"), res.stdout);
  }

  @Test
  @DisplayName("dumpLoaded_whenCalled_expectFourPrefixedLines")
  void dumpLoaded_whenCalled_expectFourPrefixedLines() {
    // Arrange: use the in-process class (default configuration). The class may have already
    // been loaded by other tests; we only check the dump format here.
    var out = new StringBuilder();
    var ps =
        new PrintStream(
            new OutputStream() {
              @Override
              public void write(int b) {
                out.append((char) b);
              }
            },
            true,
            StandardCharsets.UTF_8);

    var old = System.out;
    try {
      System.setOut(ps);
      JceLoader.dumpLoaded();
    } finally {
      System.setOut(old);
    }

    String s = out.toString();
    assertTrue(s.contains("BouncyCastle:"), s);
    assertTrue(s.contains("SunPKCS11-NSS:"), s);
    assertTrue(s.contains("SUN:"), s);
    assertTrue(s.contains("SunJCE:"), s);
  }

  @Test
  @EnabledOnJre({JRE.JAVA_21, JRE.JAVA_22, JRE.JAVA_23})
  @DisplayName("bouncyCastleAlgorithms_whenLoaded_expectRequiredAlgorithmsAvailable")
  void bouncyCastleAlgorithms_whenLoaded_expectRequiredAlgorithmsAvailable() throws Exception {
    // If another test/JVM setting disabled BC, skip this test deterministically.
    Assumptions.assumeTrue(
        JceLoader.BouncyCastle != null, "BouncyCastle provider unexpectedly disabled in this JVM");

    assertNotNull(KeyAgreement.getInstance("ECDH", JceLoader.BouncyCastle));
    assertNotNull(Signature.getInstance("SHA256withECDSA", JceLoader.BouncyCastle));
  }

  private static ProcessResult runProbe(Map<String, String> sysProps) throws Exception {
    String javaHome = System.getProperty("java.home");
    String exe = isWindows() ? "java.exe" : "java";
    File javaBin = new File(new File(javaHome, "bin"), exe);

    // Use the current test classpath so the child can see both main and test classes
    String classpath = System.getProperty("java.class.path");

    List<String> cmd = new ArrayList<>();
    cmd.add(javaBin.getAbsolutePath());
    cmd.add("-cp");
    cmd.add(classpath);
    for (Map.Entry<String, String> e : sysProps.entrySet()) {
      cmd.add("-D" + e.getKey() + "=" + e.getValue());
    }
    cmd.add(JceLoaderTest.ProbeMain.class.getName());

    ProcessBuilder pb = new ProcessBuilder(cmd);
    pb.redirectErrorStream(true);
    Process p = pb.start();
    StringBuilder out = new StringBuilder();
    try (BufferedReader br =
        new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = br.readLine()) != null) {
        out.append(line).append('\n');
      }
    }
    int code = p.waitFor();
    return new ProcessResult(code, out.toString());
  }

  private static boolean isWindows() {
    return System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
  }

  private record ProcessResult(int exitCode, String stdout) {
    @Override
    public @NotNull String toString() {
      return new StringJoiner(", ", ProcessResult.class.getSimpleName() + "[", "]")
          .add("exitCode=" + exitCode)
          .add("stdout=\n" + stdout)
          .toString();
    }
  }

  /**
   * A tiny helper with a {@code main} entry to load {@link JceLoader} in an isolated JVM with
   * system properties controlled by the parent test.
   */
  public static class ProbeMain {
    static void main() {
      boolean bc = JceLoader.BouncyCastle != null;
      boolean nss = JceLoader.NSS != null;
      boolean sun = JceLoader.SUN != null;
      boolean sunjce = JceLoader.SunJCE != null;
      System.out.println("BouncyCastle=" + bc);
      System.out.println("NSS=" + nss);
      System.out.println("SUN=" + sun);
      System.out.println("SunJCE=" + sunjce);

      boolean ecdhOk = false;
      boolean ecdsaOk = false;
      try {
        if (JceLoader.BouncyCastle != null) {
          KeyAgreement.getInstance("ECDH", JceLoader.BouncyCastle);
          Signature.getInstance("SHA256withECDSA", JceLoader.BouncyCastle);
          ecdhOk = true;
          ecdsaOk = true;
        }
      } catch (Exception _) {
        // keep flags false
      }
      System.out.println("BC_ECDH_ALG_OK=" + ecdhOk);
      System.out.println("BC_ECDSA_SHA256_ALG_OK=" + ecdsaOk);

      System.out.println("--dump--");
      JceLoader.dumpLoaded();
    }
  }
}
