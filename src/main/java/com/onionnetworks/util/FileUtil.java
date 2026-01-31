package com.onionnetworks.util;

import java.io.*;
import java.net.URL;
import java.util.BitSet;
import java.util.StringTokenizer;

/**
 * Utility helpers for safe file handling inside Crypta/Onion-based directories.
 *
 * <p>This class provides sanitization, path construction, and small convenience helpers around
 * {@link File} so callers can create or reference files without leaking unsafe characters or
 * accidentally writing outside the expected working tree. All methods are static and side-effect
 * free beyond the explicit filesystem interactions they perform. The helpers focus on predictable
 * behavior for user-provided paths, ensure idempotent directory creation, and centralize decisions
 * about where temporary and persistent files should live within a user's home directory.
 *
 * <p>Thread-safety: the class maintains no mutable static state beyond an immutable lookup table of
 * safe characters, so methods can be invoked concurrently. File creation helpers are defensive
 * against normal race conditions where multiple threads attempt to create the same file or
 * directory. Callers should still synchronize higher-level workflows when they require stronger
 * atomicity than the file system provides.
 *
 * <ul>
 *   <li>Responsibilities: sanitize user-visible names, build .onion-scoped paths, create
 *       directories/files, and perform reliable stream skipping.
 *   <li>Notable behaviors: avoids absolute paths in {@link #safeOnionFile(String)}, falls back to
 *       safe defaults for empty filenames, and prefers the user's home temp space to system-wide
 *       temp when available.
 * </ul>
 *
 * @see #safeOnionFile(String)
 * @see #createTempFile(File)
 */
public class FileUtil {

  private FileUtil() {
    throw new IllegalStateException("Utility class");
  }

  // safe characters for file name sanitization
  static BitSet safeChars = new BitSet(256);

  static {
    // a-z
    for (int i = 'a'; i <= 'z'; i++) {
      safeChars.set(i);
    }
    // A-Z
    for (int i = 'A'; i <= 'Z'; i++) {
      safeChars.set(i);
    }
    // 0-9
    for (int i = '0'; i <= '9'; i++) {
      safeChars.set(i);
    }
    safeChars.set('-');
    safeChars.set('_');
    safeChars.set(' ');
    safeChars.set('.');
  }

  /**
   * Removes characters not considered safe for local filesystem names and collapses duplicate dots.
   *
   * <p>The resulting string contains only letters, digits, dash, underscore, space, and period
   * characters. Consecutive periods are reduced to a single period to avoid hidden or parent path
   * semantics on some platforms. The method is deterministic and does not attempt locale-specific
   * normalization.
   *
   * @param name input filename fragment to sanitize; null values are not permitted
   * @return sanitized filename containing only safe characters; may be empty if all characters were
   *     removed
   */
  public static String sanitizeFileName(String name) {
    StringBuilder result = new StringBuilder();
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      // squish multiple '.'s into a single one.
      if (c == '.' && i < name.length() - 1 && name.charAt(i + 1) == '.') {
        continue;
      }
      if (safeChars.get(c)) {
        result.append(c);
      }
    }
    return result.toString();
  }

  /**
   * Derives a sanitized filename from a URL, defaulting to {@code index.html} when empty.
   *
   * <p>This helper extracts the last path component from the URL, runs it through {@link
   * #sanitizeFileName(String)}, and substitutes a predictable fallback when the sanitized result is
   * blank. It is intended for saving fetched resources without exposing raw URL content directly to
   * the filesystem.
   *
   * @param url source URL whose last path segment will be used as the basis for the filename; must
   *     not be null
   * @return non-empty sanitized filename safe for local storage, using {@code index.html} when the
   *     sanitized component would otherwise be empty
   */
  public static String pickSafeFileName(URL url) {
    String name = sanitizeFileName(new File(url.getFile()).getName());
    if (name.isEmpty()) {
      name = "index.html";
    }
    return name;
  }

  /**
   * Creates a file beneath the user's {@code .onion} directory after sanitizing every path segment.
   *
   * <p>The provided path must be relative; absolute inputs are rejected to avoid writing outside
   * the sandboxed area. Each segment is sanitized with {@link #sanitizeFileName(String)}, and empty
   * results trigger an {@link IllegalArgumentException} to prevent ambiguous or collapsed paths.
   * The helper ensures the target file exists, creating missing parent directories and the file
   * itself when needed. File creation is tolerant of concurrent callers that race to create the
   * same path.
   *
   * <pre>{@code
   * // Example: place a downloaded resource under .onion/cache
   * File cached = FileUtil.safeOnionFile("cache/page.dat");
   * }</pre>
   *
   * @param rel relative path (using platform separators) to sanitize and place under {@code .onion}
   *     ; must not be absolute or resolve to empty segments after cleaning
   * @return existing or newly created file located under the user's {@code .onion} directory
   * @throws IllegalArgumentException if the supplied path is absolute or collapses to an empty
   *     segment after sanitization
   * @throws IllegalStateException if filesystem creation fails after sanitization and validation
   */
  public static File safeOnionFile(String rel) {
    if (new File(rel).isAbsolute()) {
      throw new IllegalArgumentException(rel + " isn't relative");
    }
    StringBuilder safe = new StringBuilder();
    for (StringTokenizer st = new StringTokenizer(rel, File.separator); st.hasMoreTokens(); ) {
      String tok = sanitizeFileName(st.nextToken());
      if (tok.isEmpty()) {
        throw new IllegalArgumentException("collapsed element");
      }
      if (safe.isEmpty()) {
        safe.append(tok);
      } else {
        safe.append(File.separator).append(tok);
      }
    }

    File result = new File(getOnionDir(), safe.toString());

    try {
      ensureExists(result);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to ensure that file exists: " + e.getMessage());
    }

    return result;
  }

  /**
   * Ensures the target file and its parent directories exist, tolerating concurrent creators.
   *
   * <p>If parents do not exist they are created. When the file already exists, the method returns
   * immediately without modifying timestamps. If creation is attempted and {@link
   * File#createNewFile()} returns {@code false} because another thread or process created the file
   * in the interim, the method treats that as success. Only failures to create parents or the file
   * itself result in an {@link IOException}.
   *
   * @param f absolute or relative file reference to materialize on disk; must not be null
   * @throws IOException if parent directories cannot be created or the file cannot be created and
   *     does not already exist afterwards
   */
  public static void ensureExists(File f) throws IOException {
    File parent = f.getParentFile();
    if (parent != null && !parent.exists() && !parent.mkdirs()) {
      throw new IOException("Couldn't create parent dirs: " + f);
    }

    if (f.exists()) {
      return;
    }

    if (!f.createNewFile()) {
      if (f.exists()) {
        return; // another thread/process created it
      }
      throw new IOException("Couldn't create file: " + f);
    }
  }

  /**
   * Returns the user's {@code .onion} directory, creating it on demand when possible.
   *
   * <p>The directory lives directly under the current user's home. If the home property is absent
   * or directory creation fails, the method returns {@code null} to signal callers that persistence
   * is unavailable. The returned {@link File} may already exist or may be newly created.
   *
   * @return {@link File} pointing to the {@code .onion} directory when resolvable; {@code null} if
   *     the home directory is missing or the folder cannot be created
   */
  public static File getOnionDir() {
    String s = System.getProperty("user.home");
    if (s == null) {
      return null;
    }
    File f = new File(s, ".onion"); // FIX hardcoded name.
    if (!f.exists() && !f.mkdirs()) {
      return null;
    }
    return f;
  }

  /**
   * Provides a temp directory under {@code .onion}, preferring user space over system temp.
   *
   * <p>The directory name is {@code tmp}. If it does not exist, this method attempts to create it
   * and returns {@code null} on failure. Callers can use this path for temporary files that should
   * remain co-located with other per-user Crypta data instead of system-wide temp locations.
   *
   * @return {@link File} pointing to {@code .onion/tmp} when available; {@code null} if creation
   *     fails or the base directory is unavailable
   */
  public static File getUserTempDir() {

    File f = new File(getOnionDir(), "tmp"); // FIX hardcoded name
    if (!f.exists() && !f.mkdirs()) {
      return null;
    }
    return f;
  }

  /**
   * Creates a temporary file near a reference file, with fallbacks to user and system temp spaces.
   *
   * <p>When {@code f} is non-null, the temp file is placed alongside it using a prefix derived from
   * its name (extended to at least three characters). When {@code f} is null, the method prefers
   * the user temp directory returned by {@link #getUserTempDir()}, falling back to the system temp
   * directory if needed. If any creation attempt fails, the method retries in progressively broader
   * locations before ultimately throwing.
   *
   * @param f reference file whose directory and name will influence the temp location; may be null
   *     to request automatic placement
   * @return newly created temporary {@link File} that already exists on disk and is writable by the
   *     current process
   * @throws IOException if all attempts to create the temporary file fail across preferred
   *     directories
   */
  public static File createTempFile(File f) throws IOException {
    File parent;
    String name;
    if (f == null) {
      // null parent causes it to use the system temp dir.
      parent = getUserTempDir();
      name = "onion";
    } else {
      parent = f.getAbsoluteFile().getParentFile();
      name = f.getName();
      // createTempFile requires a suffix length of at least 3
      if (name.length() < 3) {
        name += "onion";
      }
    }

    try {
      return File.createTempFile(name, null, parent);
    } catch (IOException _) {
      if (f != null) {
        // try the user's temp dir
        return createTempFile(null);
      } else if (parent != null) {
        // try the system temp dir
        return File.createTempFile(name, null, null);
      } else {
        throw new IOException("Unable to create temp file");
      }
    }
  }

  /**
   * Skips exactly {@code count} bytes from the input stream, blocking until satisfied or EOF.
   *
   * <p>This method repeatedly calls {@link InputStream#skip(long)} and, when necessary, falls back
   * to buffered reads to guarantee forward progress. It throws {@link EOFException} if the stream
   * ends before the requested number of bytes are consumed. The input stream is not closed.
   *
   * @param is input stream to advance; must support blocking reads; not closed by this method
   * @param count number of bytes to skip; must be non-negative and typically small enough to fit in
   *     memory for intermediary buffers
   * @throws EOFException if the stream ends before the requested byte count is skipped
   * @throws IOException if underlying stream operations fail while skipping or reading
   */
  public static void skipFully(InputStream is, long count) throws IOException {

    byte[] b = null;

    long left = count;
    while (left > 0) {
      long skipped = is.skip(left);
      if (skipped == 0) {
        // We couldn't skip any bytes, lets try reading some.
        if (b == null) {
          b = new byte[1024];
        }
        // (int) cast is safe due to min(int,long)
        int c = is.read(b, 0, (int) Math.min(b.length, left));
        if (c == -1) {
          throw new EOFException();
        } else {
          skipped = c;
        }
      }
      left -= skipped;
    }
  }
}
