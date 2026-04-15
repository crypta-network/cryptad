package network.crypta.support.io;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import network.crypta.fs.AppEnv;

/**
 * Provides the small legacy file-utility subset that leaf modules still need after the runtime
 * split.
 *
 * <p>This class exists so code such as the legacy HTTP admin UI can keep a handful of historical
 * behaviors without depending on the much larger runtime-owned {@code FileUtil}. The exported
 * surface is intentionally narrow: it covers filename suggestions used in download headers,
 * canonical-path normalization for human-readable status pages, bounded stream copying for FCP
 * payload drains, temp-file creation with legacy prefix padding, UTF-8 file reads, tail reading for
 * wrapper logs, and stable operating-system naming for localized UI copy. Callers should treat
 * these helpers as compatibility shims rather than as a new general-purpose file API.
 *
 * <p>The implementation favors behavioral continuity over abstraction purity. It preserves the old
 * filename and log-tail semantics closely enough that existing admin pages and tests do not need to
 * change, while still moving the logic into a leaf-safe module. Platform detection starts with
 * {@link AppEnv}, then uses limited fallbacks only where older labels such as {@code FREE_BSD} or
 * {@code GENERIC_UNIX} still matter to visible UI text.
 *
 * <ul>
 *   <li>Methods are static and process-global.
 *   <li>Return values are compatibility-oriented suggestions, not policy decisions.
 *   <li>Filesystem reads and canonicalization are best-effort and may still reflect concurrent
 *       external changes.
 * </ul>
 */
public final class LegacyFileSupport {
  private static final int COPY_BUFFER_SIZE = 32 * 1024;

  private enum LegacyOperatingSystem {
    UNKNOWN(false, false, false),
    MAC_OS(false, true, true),
    LINUX(false, false, true),
    FREE_BSD(false, false, true),
    GENERIC_UNIX(false, false, true),
    WINDOWS(true, false, false);

    final boolean windowsLike;
    final boolean macLike;
    final boolean unixLike;

    LegacyOperatingSystem(boolean windowsLike, boolean macLike, boolean unixLike) {
      this.windowsLike = windowsLike;
      this.macLike = macLike;
      this.unixLike = unixLike;
    }
  }

  private LegacyFileSupport() {
    throw new AssertionError("No instances");
  }

  /**
   * Produces a filename suggestion for the current platform while replacing the supplied extra
   * characters.
   *
   * <p>The behavior matches the historical legacy of utility. The input is first normalized through
   * the process filename charset, then platform-specific reserved characters and any
   * caller-specified extra characters are replaced with a stable fallback character. This keeps
   * generated download names predictable across Windows, macOS, Linux, and generic Unix-like
   * environments without exposing callers to the rest of the legacy file helper surface.
   *
   * <p>This method does not probe the filesystem, avoid collisions, or guarantee that the result is
   * safe in every downstream context. Callers should treat the return value as a display-friendly
   * suggestion for a single path segment, then layer any directory, uniqueness, or policy checks on
   * top.
   *
   * @param fileName input filename candidate to sanitize into a filesystem-safe suggestion for one
   *     path segment
   * @param extraChars additional characters to replace regardless of platform-specific reserved
   *     character rules
   * @return a sanitized filename suggestion derived from {@code fileName} using the current
   *     process-wide platform view
   */
  public static String sanitizeFileNameWithExtras(String fileName, String extraChars) {
    AppEnv env = new AppEnv();
    return sanitizeFileNameWithExtras(env, fileName, extraChars);
  }

  static String sanitizeFileNameWithExtras(AppEnv env, String fileName, String extraChars) {
    LegacyOperatingSystem operatingSystem = detectOperatingSystem(env);
    return FilenameSanitizer.sanitizeFileName(
        fileName,
        fileNameCharset(),
        operatingSystem.windowsLike,
        operatingSystem.macLike,
        operatingSystem.unixLike,
        extraChars);
  }

  /**
   * Returns the canonical form of a file while preserving the legacy path normalization quirks.
   *
   * <p>The implementation rebuilds the {@link File} from its path string before canonicalization so
   * the result matches the historical handling of paths that may already contain repeated or
   * differently cased prefixes. On Windows-style paths, the string form is normalized to lower case
   * before canonicalization because the old helper treated a drive-letter and separator case as
   * cosmetic. If canonicalization fails, the method falls back to the absolute path exactly as the
   * legacy utility did.
   *
   * <p>Use this when the caller needs a stable, display-ready path for diagnostics or admin pages.
   * It is not a security boundary by itself; callers still need their own path allow-listing and
   * authorization checks when a path controls real I/O.
   *
   * @param file file reference whose canonical or absolute representation should be returned
   * @return canonical or absolute file reference, never {@code null}, with legacy normalization
   *     rules preserved
   */
  public static File getCanonicalFile(File file) {
    String name = file.getPath();
    if (File.pathSeparatorChar == '\\') {
      name = name.toLowerCase(Locale.ROOT);
    }
    file = new File(name);
    try {
      return file.getAbsoluteFile().getCanonicalFile();
    } catch (IOException _) {
      return file.getAbsoluteFile();
    }
  }

  /**
   * Copies bytes from {@code source} to {@code destination} with legacy bounded-length semantics.
   *
   * <p>When {@code length == -1}, the copy runs until end-of-stream. Otherwise, the method copies
   * exactly {@code length} bytes and throws an {@link EOFException} if the source ends too early.
   * This method closes neither stream.
   *
   * @param source input stream to read from
   * @param destination output stream to write to
   * @param length number of bytes to copy, or {@code -1} to copy until EOF
   * @throws IOException if reading, writing, or the exact-length EOF contract fails
   */
  public static void copy(InputStream source, OutputStream destination, long length)
      throws IOException {
    long remaining = length == -1 ? Long.MAX_VALUE : length;
    byte[] buffer = new byte[(int) Math.min(remaining, COPY_BUFFER_SIZE)];
    int read;
    while (remaining > 0
        && (read = source.read(buffer, 0, (int) Math.min(remaining, COPY_BUFFER_SIZE))) != -1) {
      destination.write(buffer, 0, read);
      remaining -= read;
    }
    if (remaining > 0 && length != -1) {
      throw new EOFException("stream reached eof");
    }
  }

  /**
   * Creates a temporary file while preserving the legacy short-prefix padding behavior.
   *
   * <p>When {@code directory} is {@code null}, the current working directory is used. If the
   * supplied prefix is shorter than three characters, {@code -TMP} is appended before delegating to
   * {@link File#createTempFile(String, String, File)} so historical callers continue to satisfy the
   * JDK's minimum prefix requirement.
   *
   * @param prefix filename prefix
   * @param suffix filename suffix
   * @param directory directory in which to create the file, or {@code null} for the current working
   *     directory
   * @return the created temporary file
   * @throws IOException if the file cannot be created
   */
  public static File createTempFile(String prefix, String suffix, File directory)
      throws IOException {
    if (directory == null) {
      directory = new File(".");
    }
    if (prefix.length() < 3) {
      prefix += "-TMP";
    }
    return File.createTempFile(prefix, suffix, directory);
  }

  /**
   * Reads an entire file as UTF-8 into a {@link StringBuilder}.
   *
   * @param file file to read
   * @return decoded UTF-8 content
   * @throws IOException if the file cannot be opened or read
   */
  public static StringBuilder readUTF(File file) throws IOException {
    try (FileInputStream fis = new FileInputStream(file)) {
      return readUTF(fis);
    }
  }

  private static StringBuilder readUTF(InputStream stream) throws IOException {
    try (InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
      StringBuilder result = new StringBuilder();
      char[] buf = new char[4096];
      int length;
      while ((length = reader.read(buf)) > 0) {
        result.append(buf, 0, length);
      }
      return result;
    }
  }

  /**
   * Opens a line-aware stream positioned on the trailing portion of a log file.
   *
   * <p>The returned reader exposes at most {@code byteLimit} bytes from the end of the file. When
   * the requested window begins in the middle of a line, the method discards that first partial
   * line so callers only see complete lines. This matches the startup-page behavior that shows the
   * most recent wrapper-log context without rendering half a log entry at the top of the page.
   *
   * <p>The method tolerates concurrent truncation and other short reads by skipping as much as is
   * available and then dropping the potential partial line. The caller owns the returned stream and
   * must close it. The method performs no synchronization, so concurrent writers may still change
   * the visible tail between the size check and the actual read.
   *
   * @param logfile file to open and position near its trailing content
   * @param byteLimit maximum number of bytes of trailing content to expose before dropping a
   *     possible leading partial line
   * @return a line-aware input stream over the tail of {@code logfile}, ready for caller-owned
   *     reads
   * @throws IOException if opening the file or positioning the returned stream fails
   */
  public static LineReadingInputStream getLogTailReader(File logfile, long byteLimit)
      throws IOException {
    long length = logfile.length();
    long skip = 0;
    if (length > byteLimit) {
      skip = length - byteLimit;
    }

    FileInputStream fis = null;
    LineReadingInputStream lis = null;
    try {
      fis = new FileInputStream(logfile);
      lis = new LineReadingInputStream(fis);
      if (skip > 0) {
        long remaining = skip;
        while (remaining > 0) {
          long s = lis.skip(remaining);
          if (s <= 0) break;
          remaining -= s;
        }
        lis.readLine(100000, 200, true);
      }
      return lis;
    } catch (IOException | RuntimeException e) {
      IOUtils.closeQuietly(lis);
      IOUtils.closeQuietly(fis);
      throw e;
    }
  }

  /**
   * Returns the legacy localization key suffix for the current operating system.
   *
   * <p>The result is suitable for lookups such as {@code OperatingSystemName.<suffix>} in the
   * legacy HTTP admin UI. Modern Windows, macOS, and Linux runtimes map directly from {@link
   * AppEnv}. Older or less specific environments fall back to the historical labels used by the
   * legacy file utility so that existing translations, conditional UI copy, and screenshots do not
   * unexpectedly drift after the runtime dependency split.
   *
   * @return the legacy operating-system key suffix used by the HTTP admin UI and related localized
   *     messages
   */
  public static String operatingSystemNameKey() {
    return operatingSystemNameKey(new AppEnv());
  }

  static String operatingSystemNameKey(AppEnv env) {
    return detectOperatingSystem(env).name();
  }

  /**
   * Reports whether the current platform should be treated as Windows for UI branching.
   *
   * <p>This helper exists for callers that only need the historical Windows/non-Windows split used
   * by a few admin pages. It intentionally shares the same detection path as {@link
   * #operatingSystemNameKey()} so branching logic and localized labels stay aligned.
   *
   * @return {@code true} when the current runtime should follow the legacy Windows-family branch
   *     for UI behavior
   */
  public static boolean isWindows() {
    return detectOperatingSystem(new AppEnv()) == LegacyOperatingSystem.WINDOWS;
  }

  private static Charset fileNameCharset() {
    try {
      return Charset.forName(Charset.defaultCharset().displayName());
    } catch (Exception _) {
      return Charset.defaultCharset();
    }
  }

  private static LegacyOperatingSystem detectOperatingSystem(AppEnv env) {
    if (env.isWindows()) {
      return LegacyOperatingSystem.WINDOWS;
    }
    if (env.isMac()) {
      return LegacyOperatingSystem.MAC_OS;
    }

    String lowered = env.osNameRaw().toLowerCase(Locale.ROOT);
    if (lowered.contains("freebsd")) {
      return LegacyOperatingSystem.FREE_BSD;
    }
    if (lowered.contains("linux")) {
      return LegacyOperatingSystem.LINUX;
    }
    if (lowered.contains("unix")) {
      return LegacyOperatingSystem.GENERIC_UNIX;
    }
    if (File.separatorChar == '\\') {
      return LegacyOperatingSystem.WINDOWS;
    }
    if (File.separatorChar == '/') {
      return LegacyOperatingSystem.GENERIC_UNIX;
    }
    return LegacyOperatingSystem.UNKNOWN;
  }
}
