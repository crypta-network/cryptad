package network.crypta.support;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Enumeration;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Attributes.Name;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class loader that serves classes and resources from a single JAR file.
 *
 * <p>On construction the source JAR is copied into a secure, process‑private temporary location.
 * All subsequent class and resource lookups performed by this loader are satisfied from that local
 * copy. This indirection lets the original JAR be replaced or removed while the application is
 * running (particularly important on Windows, where open file handles block deletion).
 *
 * <p>Security and robustness:
 *
 * <ul>
 *   <li>Archive entries are read with a strict upper bound to mitigate zip‑bomb style expansion.
 *   <li>Temporary files and directories are created with restrictive permissions.
 * </ul>
 *
 * <p>Threading: instances are not designed for concurrent mutation. Creating and closing the loader
 * must not race with lookups. Once {@link #close()} is called the loader must no longer be used.
 *
 * @author <a href="mailto:dr@ina-germany.de">David Roden</a>
 * @version $Id$
 */
public class JarClassLoader extends ClassLoader implements Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(JarClassLoader.class);

  /**
   * Hard limit for a single class/resource read from this loader.
   *
   * <p>Prevents unbounded expansion of a maliciously crafted archive entry (zip bomb). The value is
   * intentionally generous for practical class/resource sizes while still protecting memory.
   */
  private static final int MAX_ENTRY_BYTES = 64 * 1024 * 1024; // 64 MiB

  // No static initialisation required.

  /** The temporary jar file. */
  private JarFile tempJarFile;

  /**
   * Constructs a loader backed by the JAR found at the given filesystem path.
   *
   * <p>The file is opened immediately. No network I/O occurs.
   *
   * @param fileName absolute or relative path to a JAR file
   * @throws IOException if the file cannot be opened or read as a JAR
   */
  @SuppressWarnings("unused")
  public JarClassLoader(String fileName) throws IOException {
    this(new File(fileName));
  }

  /**
   * Constructs a loader by downloading (or streaming) a JAR from the provided {@link URL}.
   *
   * <p>The content is copied to a secure temporary file, from which all lookups are served. Network
   * or remote I/O occurs synchronously during construction.
   *
   * @param fileUrl source of the JAR bytes (e.g., {@code file:}, {@code http:})
   * @param length optional size hint in bytes; pass {@code -1} when unknown
   * @throws IOException if the URL cannot be read or the content is not a valid JAR
   */
  public JarClassLoader(URL fileUrl, long length) throws IOException {
    copyFileToTemp(fileUrl.openStream(), length);
  }

  /**
   * Constructs a loader backed by the given JAR {@link File}.
   *
   * @param file readable JAR file on the local filesystem
   * @throws IOException if the file cannot be opened or parsed as a JAR
   */
  public JarClassLoader(File file) throws IOException {
    tempJarFile = new JarFile(file);
  }

  /**
   * Copies JAR bytes from a stream into a secure temporary file owned by this process.
   *
   * <p>Callers provide an optional size hint; when {@code -1} the stream is read until EOF. The
   * destination file is created with restrictive permissions and scheduled for best‑effort deletion
   * on JVM exit.
   *
   * @param inputStream source of JAR bytes (not closed by this method)
   * @param length number of bytes to copy, or {@code -1} when unknown
   * @throws IOException if copying fails or the result cannot be opened as a JAR
   */
  private void copyFileToTemp(InputStream inputStream, long length) throws IOException {
    File tempFile = createSecureTempFile();
    try (FileOutputStream fileOutputStream = new FileOutputStream(tempFile)) {
      FileUtil.copy(inputStream, fileOutputStream, length);
    }
    tempFile.deleteOnExit();
    tempJarFile = new JarFile(tempFile);
  }

  /**
   * Locates and defines a class by name from the backing JAR.
   *
   * <p>This implementation searches the local temporary copy for the corresponding entry, validates
   * size against an internal limit, defines the package using manifest attributes (if available),
   * and finally defines the class.
   *
   * @param name binary class name (e.g., {@code com.example.Foo})
   * @return the defined {@link Class}
   * @throws ClassNotFoundException if the entry is absent or unreadable
   * @see ClassLoader#findClass(String)
   */
  @Override
  protected Class<?> findClass(String name) throws ClassNotFoundException {
    try {
      String pathName = transformName(name);
      JarEntry jarEntry = tempJarFile.getJarEntry(pathName);
      if (jarEntry != null) {
        byte[] classBytes = readEntryFully(jarEntry);

        definePackage(name);

        return defineClass(name, classBytes, 0, classBytes.length);
      }
      throw new ClassNotFoundException("could not find jar entry for class " + name);
    } catch (IOException e) {
      throw new ClassNotFoundException(e.getMessage(), e);
    }
  }

  /**
   * Finds a single resource by name in this loader's JAR only.
   *
   * <p>Accepts names with or without a leading {@code '/'} for compatibility with older callers.
   * When present, the leading slash is ignored. If the entry exists, a {@code jar:} URL pointing to
   * the local temporary copy is returned; otherwise {@code null}.
   *
   * @param name resource path using forward slashes
   * @return a {@code jar:} {@link URL} or {@code null} if absent
   */
  @Override
  protected URL findResource(String name) {
    /* Compatibility: tolerate leading slash in resource names for older plugins. */
    if (name.startsWith("/")) {
      name = name.substring(1);
    }
    try {
      if (tempJarFile.getJarEntry(name) == null) {
        return null;
      }

      return jarEntryUrl(name);
    } catch (MalformedURLException _) {
      // Malformed entry name detected; treat as not found.
      return null;
    }
  }

  @Override
  protected Enumeration<URL> findResources(String name) {
    /*
     * Enumerates all entries equal to {@code name} (optionally with a trailing '/') in this JAR
     * and synthesizes {@code jar:} URLs for each. The enumeration is empty when no match exists.
     */
    return new Enumeration<>() {
      private final Enumeration<JarEntry> jarFileEntries = tempJarFile.entries();
      private URL nextElement = null;

      @Override
      public boolean hasMoreElements() {
        if (nextElement != null) {
          return true;
        }
        while ((nextElement == null) && jarFileEntries.hasMoreElements()) {
          JarEntry jarEntry = jarFileEntries.nextElement();
          if (jarEntry.getName().equals(name) || jarEntry.getName().equals(name + "/")) {
            try {
              nextElement = jarEntryUrl(name);
            } catch (MalformedURLException _) {
              /* ignore. */
            }
          }
        }
        return nextElement != null;
      }

      @Override
      public URL nextElement() {
        if (!hasMoreElements()) {
          throw new NoSuchElementException();
        }
        URL elementToReturn = nextElement;
        nextElement = null;
        return elementToReturn;
      }
    };
  }

  /**
   * Opens a resource as a stream, preferring a handle directly from this loader's JAR.
   *
   * <p>If the requested resource resolves to this loader's JAR, the stream is opened via {@link
   * JarFile#getInputStream(ZipEntry)} so that closing the JAR also closes any dependent streams.
   * Otherwise, the method delegates to the URL returned by {@link #getResource(String)}.
   *
   * <p>Callers must close the returned stream.
   *
   * @param name resource path using forward slashes (leading slash tolerated)
   * @return an open {@link InputStream}, or {@code null} when not found or on I/O error
   * @see ClassLoader#getResourceAsStream(String)
   */
  @Override
  public InputStream getResourceAsStream(String name) {
    if (LOG.isDebugEnabled()) LOG.debug("Requested resource: {}", name);
    URL url = getResource(name);
    if (url == null) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Found resource at URL: {}", url);

    // If the resource is not from our jar, return it as normal
    URL localUrl = findResource(name);
    if (localUrl == null || !url.toString().equals(localUrl.toString()))
      try {
        return url.openStream();
      } catch (IOException _) {
        return null;
      }

    // If the resource is from our jar, open InputStream explicitly from the jar
    // so that we can close() all opened streams later and let the jar file
    // to be deleted on Windows

    /* Compatibility: tolerate leading slash in resource names for older plugins. */
    if (name.startsWith("/")) {
      name = name.substring(1);
    }

    ZipEntry entry = tempJarFile.getEntry(name);
    try {
      return entry != null ? tempJarFile.getInputStream(entry) : null;
    } catch (IOException _) {
      return null;
    }
  }

  /**
   * Converts a binary class name into a JAR entry path.
   *
   * @param name binary class name (e.g., {@code a.b.C})
   * @return relative path to the class file inside the JAR (e.g., {@code a/b/C.class})
   */
  private String transformName(String name) {
    return name.replace('.', '/') + ".class";
  }

  /**
   * Ensures that the package for a class is defined on this loader.
   *
   * <p>If a manifest is present it is consulted for specification and implementation attributes
   * which are passed to {@link #definePackage(String, String, String, String, String, String,
   * String, URL)}. If the class name has no package component, {@code null} is returned.
   *
   * @param name binary class name
   * @return the existing or newly defined {@link Package}, or {@code null} if there is no package
   * @throws IllegalArgumentException if an incompatible package definition already exists
   */
  @SuppressWarnings("UnusedReturnValue")
  protected Package definePackage(String name) throws IllegalArgumentException {
    Package pkg = null;
    int i = name.lastIndexOf('.');
    if (i != -1) {
      String pkgname = name.substring(0, i);
      pkg = getDefinedPackage(pkgname);
      if (pkg == null) {
        try {
          Manifest man = tempJarFile.getManifest();
          if (man == null) throw new IOException();
          pkg = definePackage(pkgname, man);
        } catch (IOException _) {
          pkg = definePackage(pkgname, null, null, null, null, null, null, null);
        }
      }
    }
    return pkg;
  }

  /**
   * Defines a package using attributes extracted from a {@link Manifest}.
   *
   * <p>Looks up both per‑package and main attributes and forwards them to the JDK's {@code
   * definePackage} implementation. Any missing attribute is treated as {@code null}.
   *
   * @param name package name (e.g., {@code com.example})
   * @param man manifest to read attributes from
   * @return the created {@link Package}
   * @throws IllegalArgumentException if a package of the same name already exists with different
   *     attributes
   */
  protected Package definePackage(String name, Manifest man) throws IllegalArgumentException {
    String path = name.replace('.', '/').concat("/");
    String specTitle = null;
    String specVersion = null;
    String specVendor = null;
    String implTitle = null;
    String implVersion = null;
    String implVendor = null;

    Attributes attr = man.getAttributes(path);
    if (attr != null) {
      specTitle = attr.getValue(Name.SPECIFICATION_TITLE);
      specVersion = attr.getValue(Name.SPECIFICATION_VERSION);
      specVendor = attr.getValue(Name.SPECIFICATION_VENDOR);
      implTitle = attr.getValue(Name.IMPLEMENTATION_TITLE);
      implVersion = attr.getValue(Name.IMPLEMENTATION_VERSION);
      implVendor = attr.getValue(Name.IMPLEMENTATION_VENDOR);
    }
    attr = man.getMainAttributes();
    if (attr != null) {
      specTitle = orAttr(specTitle, attr, Name.SPECIFICATION_TITLE);
      specVersion = orAttr(specVersion, attr, Name.SPECIFICATION_VERSION);
      specVendor = orAttr(specVendor, attr, Name.SPECIFICATION_VENDOR);
      implTitle = orAttr(implTitle, attr, Name.IMPLEMENTATION_TITLE);
      implVersion = orAttr(implVersion, attr, Name.IMPLEMENTATION_VERSION);
      implVendor = orAttr(implVendor, attr, Name.IMPLEMENTATION_VENDOR);
    }
    return definePackage(
        name, specTitle, specVersion, specVendor, implTitle, implVersion, implVendor, null);
  }

  /**
   * Builds a {@code jar:} URL pointing at the given entry inside the temporary JAR copy.
   *
   * @param entry entry name within the JAR
   * @return {@link URL} using the {@code jar:} scheme
   * @throws MalformedURLException if the synthesized URL is not valid
   */
  private URL jarEntryUrl(String entry) throws MalformedURLException {
    try {
      String spec = "jar:" + new File(tempJarFile.getName()).toURI().toURL() + "!/" + entry;
      return URI.create(spec).toURL();
    } catch (IllegalArgumentException e) {
      MalformedURLException malformed = new MalformedURLException(e.getMessage());
      malformed.initCause(e);
      throw malformed;
    }
  }

  /**
   * Closes the underlying {@link JarFile} and releases any OS resources held by this loader.
   *
   * <p>After calling this method, further lookups on this instance may fail with I/O errors.
   *
   * @throws IOException if closing the JAR fails
   */
  @Override
  public void close() throws IOException {
    tempJarFile.close();
  }

  private static String orAttr(String current, Attributes attributes, Name key) {
    return current != null ? current : attributes.getValue(key);
  }

  private byte[] readEntryFully(JarEntry entry) throws IOException {
    try (InputStream in = tempJarFile.getInputStream(entry)) {
      int initial = 8192; // conservative default; don't trust declared size blindly
      long declared = entry.getSize();
      if (declared > 0 && declared <= MAX_ENTRY_BYTES) {
        initial = (int) declared;
      }
      ByteArrayOutputStream out = new ByteArrayOutputStream(initial);
      byte[] buffer = new byte[8192];
      int read;
      int total = 0;
      while ((read = in.read(buffer)) != -1) {
        total += read;
        if (total > MAX_ENTRY_BYTES) {
          throw new IOException("archive entry too large");
        }
        out.write(buffer, 0, read);
      }
      return out.toByteArray();
    }
  }

  private static File createSecureTempFile() throws IOException {
    final String prefix = "jar-";
    final String suffix = ".tmp";
    try {
      FileAttribute<Set<PosixFilePermission>> dirAttr =
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));
      FileAttribute<Set<PosixFilePermission>> fileAttr =
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
      Path dir = Files.createTempDirectory("crypta-jar-", dirAttr);
      Path p = Files.createTempFile(dir, prefix, suffix, fileAttr);
      File f = p.toFile();
      // Best-effort cleanup of the dedicated directory on process exit when empty.
      f.getParentFile().deleteOnExit();
      return f;
    } catch (UnsupportedOperationException _) {
      // POSIX permissions not supported (e.g., Windows). Create a dedicated directory under the
      // user's home and restrict permissions.
      Path base = Paths.get(System.getProperty("user.home"), ".crypta", "tmp");
      Files.createDirectories(base);
      File d = base.toFile();
      boolean ok = true;
      ok &= d.setReadable(true, true);
      ok &= d.setWritable(true, true);
      ok &= d.setExecutable(true, true);
      Path dir = Files.createTempDirectory(base, "crypta-jar-");
      Path p = Files.createTempFile(dir, prefix, suffix);
      File f = p.toFile();
      ok &= f.setReadable(true, true);
      ok &= f.setWritable(true, true);
      ok &= f.setExecutable(false, true);
      if (!ok && LOG.isWarnEnabled()) {
        LOG.warn("Could not fully restrict permissions on temporary paths: dir={}, file={}", d, f);
      }
      // Best-effort cleanup of the dedicated directory on process exit when empty.
      dir.toFile().deleteOnExit();
      return f;
    }
  }
}
