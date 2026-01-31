package network.crypta.crypt;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Set;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads and exposes the cryptographic JCA providers used by Crypta.
 *
 * <p>The static initializer evaluates system properties to decide which providers to enable and in
 * which order, then publishes them as immutable fields. When a provider cannot be loaded or lacks
 * required algorithms, the failure is logged and the corresponding field is left {@code null} to
 * preserve graceful degradation.
 *
 * <p>System properties (all prefixed with {@code crypta.jce.}):
 *
 * <ul>
 *   <li>{@code use.NSS} – enable the SunPKCS11 provider configured for NSS (default: {@code
 *       false}).
 *   <li>{@code prefer.NSS} – when NSS is enabled, insert it at position 1 to prefer it over other
 *       providers.
 *   <li>{@code use.BC.I.know.what.I.am.doing} – enable the BouncyCastle provider. Required
 *       algorithms {@code ECDH} and {@code SHA256withECDSA} are probed. If probing fails, the
 *       failure is logged and BouncyCastle remains {@code null}.
 *   <li>{@code use.SunJCE} – enable the JDK {@code SunJCE} provider.
 *   <li>{@code use.SUN} – enable the JDK {@code SUN} provider.
 * </ul>
 *
 * <p>Thread-safety: fields are {@code static final} and become visible after class initialization.
 * There is no subsequent mutation.
 */
public class JceLoader {
  private static final Logger LOG = LoggerFactory.getLogger(JceLoader.class);

  /**
   * BouncyCastle provider instance, or {@code null} if disabled, unavailable, or missing required
   * algorithms. Loaded during class initialization.
   */
  protected static final Provider BouncyCastle;

  /**
   * SunPKCS11 provider configured for NSS, or {@code null} when not enabled or unavailable. When
   * present, the provider name typically starts with {@code SunPKCS11-NSS}.
   */
  protected static final Provider NSS; // optional, may be null

  /** JDK {@code SUN} provider, or {@code null} when disabled by property. */
  protected static final Provider SUN; // optional, may be null

  /** JDK {@code SunJCE} provider, or {@code null} when disabled by property. */
  protected static final Provider SunJCE; // optional, may be null

  private JceLoader() {
    throw new IllegalStateException("Utility class");
  }

  static {
    Provider p;
    // Attempt NSS first so it can be inserted ahead of other providers if requested.
    p = null;
    if (checkUse("use.NSS", "false")) {
      try {
        p = new NSSLoader().load(checkUse("prefer.NSS"));
      } catch (Exception e) {
        // Note: The SunPKCS11-NSS provider may be unavailable on some platforms.
        final String msg =
            "Unable to load SunPKCS11-NSScrypto provider. "
                + "This is NOT fatal error, Crypta will work, but some performance "
                + "degradation possible. Consider installing libnss3 package.";
        LOG.warn(msg, e);
      }
      if (p != null) {
        try {
          KeyGenerator kgen = KeyGenerator.getInstance("AES", "SunPKCS11-NSS");
          kgen.init(256);
        } catch (GeneralSecurityException e) {
          final String msg = "Error with SunPKCS11-NSS. " + "Unlimited policy file not installed.";
          LOG.warn(msg, e);
        }
      }
    }
    NSS = p;
    p = null;
    if (checkUse("use.BC.I.know.what.I.am.doing")) {
      try {
        p = new BouncyCastleLoader().load();
      } catch (Exception e) {
        // Catch reflective loading issues and runtime failures from algorithm probes inside
        // BouncyCastleLoader (e.g., IllegalStateException when ECDH/ECDSA are missing) so we
        // degrade to "BC = null" instead of aborting class initialization.
        final String msg = "SERIOUS PROBLEM: Unable to load or use BouncyCastle provider.";
        LOG.error(msg, e);
      }
    }
    BouncyCastle = p;
    // optional
    if (checkUse("use.SunJCE")) {
      try {
        KeyGenerator kgen = KeyGenerator.getInstance("AES", "SunJCE");
        kgen.init(256);
      } catch (GeneralSecurityException e) {
        LOG.warn("Error with SunJCE. Unlimited policy file not installed.", e);
      }
      SunJCE = Security.getProvider("SunJCE");
    } else {
      SunJCE = null;
    }

    SUN = checkUse("use.SUN") ? Security.getProvider("SUN") : null;
  }

  /**
   * Emits a one-line summary for each provider.
   *
   * <p>If {@code System.out} is a {@link PrintStream}, lines are written there; otherwise, messages
   * are logged at {@code INFO} level via SLF4J.
   */
  public static void dumpLoaded() {
    PrintStream out = getSystemOut();
    if (out != null) {
      out.println("BouncyCastle: " + BouncyCastle);
      out.println("SunPKCS11-NSS: " + NSS);
      out.println("SUN: " + SUN);
      out.println("SunJCE: " + SunJCE);
    } else {
      LOG.info("BouncyCastle: {}", BouncyCastle);
      LOG.info("SunPKCS11-NSS: {}", NSS);
      LOG.info("SUN: {}", SUN);
      LOG.info("SunJCE: {}", SunJCE);
    }
  }

  /**
   * Returns the BouncyCastle provider.
   *
   * @return the provider instance, or {@code null} when disabled, unavailable, or missing required
   *     algorithms
   */
  public static Provider getBouncyCastle() {
    return BouncyCastle;
  }

  /**
   * Returns the SunPKCS11 provider configured for NSS.
   *
   * @return the provider instance, or {@code null} when NSS is disabled or could not be loaded
   */
  @SuppressWarnings("unused")
  public static Provider getNSS() {
    return NSS;
  }

  /**
   * Returns the JDK {@code SUN} provider.
   *
   * @return the provider instance, or {@code null} when disabled by property
   */
  @SuppressWarnings("unused")
  public static Provider getSUN() {
    return SUN;
  }

  /**
   * Returns the JDK {@code SunJCE} provider.
   *
   * @return the provider instance, or {@code null} when disabled by property
   */
  public static Provider getSunJCE() {
    return SunJCE;
  }

  // Avoid a hard reference that could be redirected or replaced in unusual environments.
  private static PrintStream getSystemOut() {
    try {
      Field f = System.class.getField("out");
      Object ps = f.get(null);
      return (ps instanceof PrintStream printStream) ? printStream : null;
    } catch (NoSuchFieldException | IllegalAccessException _) {
      return null;
    }
  }

  private static boolean checkUse(String prop) {
    return checkUse(prop, "true");
  }

  private static boolean checkUse(String prop, String def) {
    return "true".equalsIgnoreCase(System.getProperty("crypta.jce." + prop, def));
  }

  private static class BouncyCastleLoader {
    private BouncyCastleLoader() {}

    /**
     * Loads BouncyCastle and verifies minimal capability.
     *
     * <p>When BC is already present in {@link Security}, it is reused. Otherwise, it is created and
     * added. The method probes {@code ECDH} and {@code SHA256withECDSA} to ensure the provider is
     * actually usable for Crypta’s needs.
     *
     * @throws ReflectiveOperationException if the provider class cannot be instantiated
     * @throws IllegalStateException if required algorithms are missing
     */
    private Provider load() throws ReflectiveOperationException {
      Provider p = Security.getProvider("BC");
      if (p == null) {
        Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
        p = (Provider) c.getDeclaredConstructor().newInstance();
        Security.addProvider(p);
        LOG.trace("Loaded BouncyCastle provider: {}", p);
      } else {
        LOG.trace("Found BouncyCastle provider: {}", p);
      }
      try {
        // Ensure the provider supplies required algorithms; otherwise treat it as unusable.
        KeyAgreement.getInstance("ECDH", p);
        Signature.getInstance("SHA256withECDSA", p);
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(
            "Cannot use required algorithm from BouncyCastle provider", e);
      }
      return p;
    }
  }

  private static class NSSLoader {
    private NSSLoader() {}

    /**
     * Loads a {@code SunPKCS11} instance configured for NSS.
     *
     * @param atfirst when {@code true}, inserts the configured provider at position {@code 1}
     * @return the configured provider (never {@code null})
     * @throws IOException if the temporary configuration file cannot be created
     * @throws IllegalStateException if the {@code SunPKCS11} base provider is unavailable
     */
    private Provider load(boolean atfirst) throws IOException {
      Provider nssProvider = null;
      for (Provider p : Security.getProviders()) {
        if (p.getName().matches("^SunPKCS11-(?i)NSS.*$")) {
          nssProvider = p;
          break;
        }
      }
      if (nssProvider == null) {
        File nssFile = createNssConfigFile();

        // JDK 9+: use the public Provider.configure API. No legacy fallbacks.
        Provider base = Security.getProvider("SunPKCS11");
        if (base == null) {
          throw new IllegalStateException("SunPKCS11 base provider is unavailable");
        }
        nssProvider = base.configure(nssFile.getPath());
        if (atfirst) {
          Security.insertProviderAt(nssProvider, 1);
        } else {
          Security.addProvider(nssProvider);
        }
        LOG.trace("Loaded NSS provider {}", nssProvider);
      } else {
        LOG.trace("Found NSS provider {}", nssProvider);
      }
      return nssProvider;
    }

    private static File createNssConfigFile() throws IOException {
      Path nssPath;
      try {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
        nssPath = Files.createTempFile("nss", ".cfg", attr);
      } catch (UnsupportedOperationException | IOException _) {
        Path base =
            Paths.get(System.getProperty("user.home", System.getProperty("java.io.tmpdir")));
        Path secureDir = base.resolve(".crypta-tmp");
        Files.createDirectories(secureDir);
        nssPath = Files.createTempFile(secureDir, "nss", ".cfg");
      }
      return writeNssConfig(nssPath);
    }

    private static File writeNssConfig(Path nssPath) throws IOException {
      File nssFile = nssPath.toFile();
      nssFile.deleteOnExit();
      try (OutputStream os = new FileOutputStream(nssFile);
          OutputStreamWriter osw = new OutputStreamWriter(os, StandardCharsets.ISO_8859_1);
          BufferedWriter bw = new BufferedWriter(osw)) {
        // Use explicit streams instead of PrintWriter(file) to avoid silent failures when disk is
        // full and to control the charset.
        bw.write("name=NSScrypto\n");
        bw.write("nssDbMode=noDb\n");
        bw.write("attributes=compatibility\n");
      }
      return nssFile;
    }
  }
}
