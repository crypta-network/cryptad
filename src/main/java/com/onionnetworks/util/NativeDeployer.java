package com.onionnetworks.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import network.crypta.fs.AppEnv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Deploys native libraries that are packaged inside JAR resources into an executable location on
 * the local filesystem.
 *
 * <p>This utility discovers platform-appropriate native binaries via {@code lib/native.properties}
 * descriptors bundled in dependent JARs, normalizes the current operating system and architecture,
 * and extracts the selected resource to a temporary file with restrictive permissions. It favors
 * minimal state: every invocation performs a fresh extraction instead of caching, which keeps
 * behavior predictable for short-lived processes and avoids stale binaries at the cost of repeated
 * I/O when used frequently. Callers typically invoke {@link #getLibraryPath(ClassLoader, String)}
 * before loading a JNI library so the JVM can link against the extracted file path.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Detecting a normalized {@code os-arch} token compatible with bundled property files.
 *   <li>Locating the matching resource path for the requested library name.
 *   <li>Extracting the native library into a secure, temporary location with best-effort owner-only
 *       permissions.
 * </ul>
 *
 * <p>The class is stateless and thread-safe through synchronization on extraction methods. It does
 * not manage library unloading and assumes the caller controls lifetime and later cleanup.
 *
 * @author Justin F. Chapweske
 * @see AppEnv
 */
public class NativeDeployer {

  private static final Logger LOGGER = LoggerFactory.getLogger(NativeDeployer.class);

  /**
   * Normalized operating system and architecture token (for example, {@code linux-x86_64} or {@code
   * win32-arm64}) used to match entries in {@code lib/native.properties}.
   *
   * <p>The value is derived once at class initialization based on {@link AppEnv} heuristics and the
   * JVM-reported {@code os.arch}. It remains constant for the life of the JVM and is safe to reuse
   * when selecting platform-specific native artifacts.
   */
  public static final String OS_ARCH;

  private static final String NATIVE_PROPERTIES_PATH = "lib/native.properties";
  private static final String NATIVE_PROPERTY_PREFIX = "com.onionnetworks.native.";

  static {
    AppEnv env = new AppEnv();
    final String baseOS;
    if (env.isWindows()) {
      baseOS = "win32";
    } else if (env.isMac()) {
      baseOS = "mac os x";
    } else if (env.isLinux()) {
      baseOS = "linux";
    } else {
      baseOS = env.osNameRaw().toLowerCase(Locale.ROOT);
    }
    final String sysArch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
    final String detectedArch = env.arch(); // "amd64" or "arm64"
    if ("amd64".equals(detectedArch) || sysArch.matches("(i?[x0-9]86_64|amd64)")) {
      OS_ARCH = baseOS + "-x86_64";
    } else if ("arm64".equals(detectedArch)) {
      OS_ARCH = baseOS + "-arm64";
    } else if (sysArch.contains("86")) {
      OS_ARCH = baseOS + "-x86";
    } else {
      OS_ARCH = baseOS + "-" + sysArch;
    }
    LOGGER.info("Attempting to deploy Native FEC for {}", OS_ARCH);
  }

  private NativeDeployer() {}

  /**
   * Locates and extracts a named native library for the current platform.
   *
   * <p>This method resolves the platform-specific path described in bundled {@code
   * lib/native.properties} files, copies the resource to a secure temporary location, and returns
   * the absolute file system path. The method is synchronized to avoid concurrent extractions of
   * the same artifact and to keep temporary file naming deterministic. Callers typically pass the
   * class loader that owns the native resources so lookup works in shaded, plugin, or container
   * environments.
   *
   * <pre>{@code
   * String extracted =
   *     NativeDeployer.getLibraryPath(MyPlugin.class.getClassLoader(), "fec8");
   * if (extracted != null) {
   *   System.load(extracted);
   * }
   * }</pre>
   *
   * @param cl class loader used to locate {@code lib/native.properties} and the native resource;
   *     must not be {@code null} and should match the JAR containing the library.
   * @param libName logical library key defined in {@code lib/native.properties}; value is
   *     case-sensitive and should correspond to a configured {@code name} entry.
   * @return absolute path to the extracted library, or {@code null} when none matches the platform.
   */
  public static synchronized String getLibraryPath(ClassLoader cl, String libName) {
    long start = System.currentTimeMillis();
    try {
      String libPath = findLibraries(cl).get(libName);
      if (libPath == null) {
        return null;
      }
      String localPath = getLocalResourcePath(cl, libPath);
      LOGGER.info("Extracted {} in {} ms", libName, System.currentTimeMillis() - start);
      return localPath;
    } catch (IOException e) {
      LOGGER.warn("Unable to deploy native library {}", libName, e);
      return null;
    }
  }

  /**
   * Extracts a classpath resource to a secure temporary file and returns its absolute path.
   *
   * <p>The method creates a temporary file with best-effort owner-only permissions, streams the
   * resource content into it, and preserves the restrictive permissions after the copy. Synchronize
   * calls to serialize concurrent extractions, reducing duplicate work when multiple threads
   * request the same native binary. Each call writes a fresh copy; callers are responsible for any
   * reuse or cleanup semantics.
   *
   * @param cl class loader used to resolve the resource; should be non-null and aligned to the JAR
   *     containing the native binary.
   * @param resourcePath classpath-relative path (e.g., {@code lib/linux/x86/libfec8.so}) referenced
   *     in {@code lib/native.properties}; must correspond to an existing bundled resource.
   * @return absolute path to the copied resource suitable for {@link System#load(String)}, or
   *     {@code null} if the resource is missing.
   * @throws IOException if the resource cannot be read, or the temporary file cannot be written
   *     with the required permissions.
   */
  public static synchronized String getLocalResourcePath(ClassLoader cl, String resourcePath)
      throws IOException {

    Path tempPath = createSecureTempFile();
    URL url = cl.getResource(resourcePath);
    if (url == null) {
      return null;
    }
    try (InputStream is = url.openStream();
        OutputStream os =
            Files.newOutputStream(
                tempPath,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE)) {

      byte[] b = new byte[1024];
      int c;
      while ((c = is.read(b)) != -1) {
        os.write(b, 0, c);
      }
      os.flush();
      return tempPath.toString();
    }
  }

  /**
   * Parses bundled {@code lib/native.properties} resources and returns a mapping of library names
   * to platform-specific resource paths for the detected {@link #OS_ARCH}.
   *
   * @param cl class loader used to list property resources; must supply access to bundled {@code
   *     lib/native.properties} files.
   * @return map of logical library names to resource paths scoped to the current platform; entries
   *     are trimmed but not validated for existence.
   * @throws IOException if any property file cannot be opened or read from the supplied class
   *     loader.
   */
  private static Map<String, String> findLibraries(ClassLoader cl) throws IOException {

    Map<String, String> libMap = new HashMap<>();
    // loop through all the properties files.
    Enumeration<URL> resources = cl.getResources(NATIVE_PROPERTIES_PATH);
    while (resources.hasMoreElements()) {
      Properties p = new Properties();
      URL resource = resources.nextElement();
      try (InputStream stream = resource.openStream()) {
        p.load(stream);
      }
      // Extract the keys and loop through all the libs.
      for (StringTokenizer st =
              new StringTokenizer(p.getProperty(NATIVE_PROPERTY_PREFIX + "keys"), ",");
          st.hasMoreTokens(); ) {
        String key = st.nextToken().trim();
        // If it matches the os and arch, then add it.
        if (p.getProperty(NATIVE_PROPERTY_PREFIX + key + ".osarch").trim().equals(OS_ARCH)) {

          libMap.put(
              p.getProperty(NATIVE_PROPERTY_PREFIX + key + ".name").trim(),
              p.getProperty(NATIVE_PROPERTY_PREFIX + key + ".path").trim());
        }
      }
    }
    return libMap;
  }

  private static Path createSecureTempFile() throws IOException {
    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      FileAttribute<Set<PosixFilePermission>> attr =
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
      return Files.createTempFile("libfec", ".tmp", attr);
    }
    Path userTempRoot = Path.of(System.getProperty("user.home"), ".cryptad-temp");
    Files.createDirectories(userTempRoot);
    Path tempPath = Files.createTempFile(userTempRoot, "libfec", ".tmp");
    File tempFile = tempPath.toFile();
    boolean readable = tempFile.setReadable(true, true);
    boolean writable = tempFile.setWritable(true, true);
    if (!readable || !writable) {
      LOGGER.warn("Failed to restrict permissions on temporary file {}", tempPath);
    }
    return tempPath;
  }
}
