package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.node.NodeStarter;
import network.crypta.support.StringValidityChecker;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for common file and stream operations.
 *
 * <p>This class provides helpers for safe filename sanitization across operating systems,
 * consistent reading/writing of byte and character streams, directory removal, best‑effort secure
 * deletion, and a few portability probes (detected OS/architecture). All methods are static and
 * side‑effect free except where they perform explicit filesystem I/O.
 *
 * <p>Unless otherwise stated, methods do not perform synchronization and are not inherently
 * thread‑safe. Callers are responsible for coordinating concurrent access to the same files.
 */
public final class FileUtil {
  private static final Logger LOG = LoggerFactory.getLogger(FileUtil.class);

  /**
   * Default buffer size (bytes) used for stream copy and comparison operations. The current value
   * is {@code 32 * 1024} (32 KiB).
   */
  public static final int BUFFER_SIZE = 32 * 1024;

  private static final int REPLACE_MOVE_MAX_ATTEMPTS = 5;
  private static final long REPLACE_MOVE_BASE_BACKOFF_MILLIS = 50;
  private static final long REPLACE_MOVE_MAX_BACKOFF_MILLIS = 400;

  private static final Random SEED_GENERATOR =
      MersenneTwister.createSynchronized(NodeStarter.getGlobalSecureRandom().generateSeed(32));

  /**
   * Opens a {@link LineReadingInputStream} positioned to read the tail of a log file.
   *
   * <p>The returned stream exposes at most {@code byteLimit} bytes from the end of {@code logfile}.
   * When truncating, the method skips an initial partial line so consumers see complete lines only.
   * The caller owns the returned stream and must close it.
   *
   * @param logfile file to open
   * @param byteLimit maximum number of bytes of trailing content to expose
   * @return a line‑aware input stream over the tail of {@code logfile}
   * @throws IOException on I/O failure opening or positioning the stream
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
        // Skip up to the requested number of bytes, but tolerate concurrent truncation.
        long remaining = skip;
        while (remaining > 0) {
          long s = lis.skip(remaining);
          if (s <= 0) break; // EOF or no progress
          remaining -= s;
        }
        // Drop a potential partial first line after skipping whatever was available.
        lis.readLine(100000, 200, true);
      }
      // Success - return the stream to the caller
      return lis;
    } catch (IOException | RuntimeException e) {
      // Clean up resources if setup failed
      IOUtils.closeQuietly(lis);
      IOUtils.closeQuietly(fis);
      throw e;
    }
  }

  /**
   * Coarse‑grained operating system categories used for portability decisions such as filename
   * sanitization and path handling.
   */
  public enum OperatingSystem {
    UNKNOWN(false, false, false), // Special-cased in filename sanitising code.
    MAC_OS(false, true, true), // OS/X in that it can run scripts.
    LINUX(false, false, true),
    FREE_BSD(false, false, true),
    GENERIC_UNIX(false, false, true),
    WINDOWS(true, false, false);

    /** Whether the platform behaves like Windows for path and filename rules. */
    public final boolean isWindows;

    /** Whether the platform is macOS (a Unix that historically had its own filename rules). */
    public final boolean isMac;

    /** Whether the platform is a Unix/POSIX derivative (Linux, *BSD, etc.). */
    public final boolean isUnix;

    OperatingSystem(boolean win, boolean mac, boolean unix) {
      this.isWindows = win;
      this.isMac = mac;
      this.isUnix = unix;
    }
  }

  /**
   * CPU architectures recognized by legacy runtime logic. Values are the best effort and may not
   * distinguish word sizes in all cases.
   */
  public enum CPUArchitecture {
    UNKNOWN,
    X86,
    X86_64,
    PPC_32,
    PPC_64,
    ARM,
    SPARC,
    IA64
  }

  /**
   * Best‑effort detection of the current operating system at class initialization time.
   *
   * <p>See {@link #detectOperatingSystem()} for the algorithm. This value is process‑global and not
   * expected to change while the JVM is running.
   */
  public static final OperatingSystem detectedOS;

  /**
   * Best‑effort detection of the current CPU architecture at class initialization time.
   *
   * <p>Warnings: This may not be entirely accurate. The JVM may not expose enough details to
   * distinguish 32‑bit from 64‑bit in all cases, a mismatched JVM may be running (e.g., x86 JVM on
   * IA64 hardware), and the legacy enum does not encode some modern variants (e.g., ARM64 is mapped
   * to {@link CPUArchitecture#ARM}). The value reflects what the JVM reports for the current
   * process.
   */
  public static final CPUArchitecture detectedArch;

  private static final Charset fileNameCharset;

  static {
    detectedOS = detectOperatingSystem();

    detectedArch = detectCPUArchitecture();

    /*
     * There is no reliable cross‑platform API to get the filesystem's filename charset,
     * so use the process default encoding as a pragmatic approximation. On Windows and many
     * Linux setups, this tracks the configured locale and is typically suitable.
     *
     * Mis‑detecting the charset may cause invalid filenames to be rejected; this is acceptable
     * because path and separator characters are rejected independently, preventing placement
     * outside intended directories.
     */
    fileNameCharset = getFileEncodingCharset();
  }

  private static char chooseDefaultReplacement(String extraChars) {
    if (extraChars.indexOf(' ') == -1) return ' ';
    if (extraChars.indexOf('_') == -1) return '_';
    if (extraChars.indexOf('-') == -1) return '-';
    throw new IllegalArgumentException("What do you want me to use instead of spaces???");
  }

  private static boolean isReservedForAnyOS(char c) {
    return StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c)
        || StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c)
        || StringValidityChecker.isUnixReservedPrintableFilenameCharacter(c);
  }

  private static boolean isReservedForOS(OperatingSystem targetOS, char c) {
    if (targetOS == OperatingSystem.UNKNOWN) return isReservedForAnyOS(c);
    if (targetOS.isWindows && StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c))
      return true;
    if (targetOS.isMac && StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c))
      return true;
    return targetOS.isUnix && StringValidityChecker.isUnixReservedPrintableFilenameCharacter(c);
  }

  private static boolean shouldReplaceChar(char c, OperatingSystem targetOS, String extraChars) {
    return extraChars.indexOf(c) != -1
        || Character.getType(c) == Character.CONTROL
        || Character.isWhitespace(c)
        || isReservedForOS(targetOS, c);
  }

  private static void trimWindowsTrailingSpaceDot(StringBuilder sb, OperatingSystem targetOS) {
    if (targetOS == OperatingSystem.UNKNOWN || targetOS.isWindows) {
      int lastCharIndex = sb.length() - 1;
      while (lastCharIndex >= 0) {
        char lastChar = sb.charAt(lastCharIndex);
        if (lastChar == ' ' || lastChar == '.') sb.deleteCharAt(lastCharIndex--);
        else break;
      }
    }
  }

  private static void fixWindowsReservedBasename(StringBuilder sb, OperatingSystem targetOS) {
    if ((targetOS == OperatingSystem.UNKNOWN || targetOS.isWindows)
        && StringValidityChecker.isWindowsReservedFilename(sb.toString())) {
      sb.insert(0, '_');
    }
  }

  /**
   * Detects the operating system in which the JVM is running. Returns {@link
   * OperatingSystem#UNKNOWN} if the OS is unknown or an error occurred. This method never throws.
   */
  private static OperatingSystem detectOperatingSystem() { // Now delegates to AppEnv first
    try {
      network.crypta.fs.AppEnv env = new network.crypta.fs.AppEnv();
      OperatingSystem detected =
          switch (env.osKind()) {
            case WINDOWS -> OperatingSystem.WINDOWS;
            case MAC -> OperatingSystem.MAC_OS;
            case LINUX -> {
              // AppEnv groups all non-Windows/non-macOS here, which includes FreeBSD and other
              // Unix.
              // Only return LINUX when the JVM reports actual Linux; otherwise fall through, so
              // FreeBSD keeps its legacy mapping.
              // Keep the legacy os.name fallback until AppEnv distinguishes BSD variants to avoid
              // misclassifying FreeBSD as Linux.
              final String n =
                  String.valueOf(System.getProperty("os.name")).toLowerCase(Locale.ROOT);
              if (n.contains("linux")) {
                yield OperatingSystem.LINUX;
              }
              yield null;
            }
            default -> null;
          };
      if (detected != null) {
        return detected;
      }
    } catch (Exception e) {
      // If AppEnv is unavailable (e.g., restricted env), fall back to legacy detection below
      LOG.error("Operating system detection via AppEnv failed", e);
    }
    // Legacy fallback to preserve FreeBSD/GenericUnix behavior and work in restricted envs
    final String name = String.valueOf(System.getProperty("os.name")).toLowerCase(Locale.ROOT);
    if (name.contains("freebsd")) return OperatingSystem.FREE_BSD;
    if (name.contains("linux")) return OperatingSystem.LINUX;
    if (name.contains("unix")) return OperatingSystem.GENERIC_UNIX;
    else if (File.separatorChar == '/') return OperatingSystem.GENERIC_UNIX;
    else if (File.separatorChar == '\\') return OperatingSystem.WINDOWS;
    LOG.error("Unknown operating system:{}", name);
    return OperatingSystem.UNKNOWN;
  }

  private static CPUArchitecture detectCPUArchitecture() { // Prefer AppEnv, fall back for legacy
    try {
      network.crypta.fs.AppEnv env = new network.crypta.fs.AppEnv();
      String a = env.arch(); // "amd64" or "arm64"
      if ("amd64".equals(a)) return CPUArchitecture.X86_64;
      if ("arm64".equals(a)) return CPUArchitecture.ARM; // legacy enum has no ARM64
    } catch (Exception e) {
      LOG.error("CPU architecture detection via AppEnv failed", e);
    }
    try {
      final String name = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
      if (name.equals("x86") || name.equals("i386") || name.matches("i[3-9]86"))
        return CPUArchitecture.X86;
      if (name.equals("amd64")
          || name.equals("x86-64")
          || name.equals("x86_64")
          || name.equals("em64t")
          || name.equals("x8664")
          || name.equals("8664")) return CPUArchitecture.X86_64;
      if (name.startsWith("arm")) return CPUArchitecture.ARM; // legacy mapping
      if (name.equals("ppc") || name.equals("powerpc")) return CPUArchitecture.PPC_32;
      if (name.equals("ppc64")) return CPUArchitecture.PPC_64;
      if (name.startsWith("ia64")) return CPUArchitecture.IA64;
    } catch (Exception e) {
      LOG.error("CPU architecture detection failed", e);
    }
    return CPUArchitecture.UNKNOWN;
  }

  /**
   * Returns the charset corresponding to the JVM's default file encoding.
   *
   * <p>On Windows and many Linux distributions this typically follows the user's locale. If the
   * charset cannot be resolved, the platform default as returned by {@link
   * Charset#defaultCharset()} is used. This method never throws.
   *
   * @return a non-null {@link Charset} suitable for interpreting filenames
   */
  public static Charset getFileEncodingCharset() {
    try {
      return Charset.forName(Charset.defaultCharset().displayName());
    } catch (Exception _) {
      return Charset.defaultCharset();
    }
  }

  /**
   * Tests whether {@code poss} is an ancestor directory of {@code filename}.
   *
   * <p>Both arguments are also checked after canonicalization to account for symlinks and relative
   * segments. The check walks parent directories and does not touch the filesystem beyond resolving
   * canonical paths.
   *
   * @param poss potential ancestor directory
   * @param filename file or directory to test
   * @return {@code true} if {@code poss} is {@code filename} or one of its parents
   */
  public static boolean isParent(File poss, File filename) {
    File canon = FileUtil.getCanonicalFile(poss);
    File canonFile = FileUtil.getCanonicalFile(filename);

    if (isParentInner(poss, filename)) return true;
    if (isParentInner(poss, canonFile)) return true;
    if (isParentInner(canon, filename)) return true;
    return isParentInner(canon, canonFile);
  }

  private static boolean isParentInner(File possParent, File filename) {
    while (true) {
      if (filename.equals(possParent)) return true;
      filename = filename.getParentFile();
      if (filename == null) return false;
    }
  }

  public static File getCanonicalFile(File file) {
    // Rebuild from the path string before canonicalization to avoid historical double‑prefix
    // issues observed with some persistence layers.
    String name = file.getPath();
    if (File.pathSeparatorChar == '\\') {
      name = name.toLowerCase(Locale.ROOT);
    }
    file = new File(name);
    File result;
    try {
      result = file.getAbsoluteFile().getCanonicalFile();
    } catch (IOException _) {
      result = file.getAbsoluteFile();
    }
    return result;
  }

  /**
   * Reads the entire contents of a file as UTF‑8 into a {@link StringBuilder}.
   *
   * @param file file to read
   * @return a buffer containing the decoded characters
   * @throws IOException on I/O failure opening or reading the file
   */
  public static StringBuilder readUTF(File file) throws IOException {
    return readUTF(file, 0);
  }

  /**
   * Reads a file as UTF‑8 starting at a byte offset into a {@link StringBuilder}.
   *
   * @param file file to read
   * @param offset number of bytes to skip from the start before decoding
   * @return a buffer containing the decoded characters from {@code offset}
   * @throws IOException on I/O failure opening or reading the file
   */
  public static StringBuilder readUTF(File file, long offset) throws IOException {
    try (FileInputStream fis = new FileInputStream(file)) {
      return readUTF(fis, offset);
    }
  }

  /**
   * Reads the entire contents of a stream as UTF‑8 into a {@link StringBuilder}.
   *
   * <p>The provided stream is consumed and closed by this method.
   *
   * @param stream input to read (consumed and closed)
   * @return a buffer containing the decoded characters
   * @throws IOException on I/O failure while reading
   */
  public static StringBuilder readUTF(InputStream stream) throws IOException {
    return readUTF(stream, 0);
  }

  /**
   * Reads a stream as UTF‑8 starting at a byte offset into a {@link StringBuilder}.
   *
   * <p>The provided stream is consumed and closed by this method.
   *
   * @param stream input to read (consumed and closed)
   * @param offset number of bytes to skip before decoding
   * @return a buffer containing the decoded characters from {@code offset}
   * @throws IOException on I/O failure while reading
   */
  public static StringBuilder readUTF(InputStream stream, long offset) throws IOException {
    skipFully(stream, offset);
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
   * Skips exactly {@code skip} bytes from an {@link InputStream} or throws if unable to do so.
   *
   * <p>Unlike {@link InputStream#skip(long)}, this method guarantees progress or fails with an
   * {@link IOException}.
   *
   * @param is input stream (not closed by this method)
   * @param skip number of bytes to skip; must be non‑negative
   * @throws IOException if the stream cannot skip the requested number of bytes
   */
  public static void skipFully(InputStream is, long skip) throws IOException {
    long skipped = 0;
    while (skipped < skip) {
      long x = is.skip(skip - skipped);
      if (x <= 0) throw new IOException("Unable to skip " + (skip - skipped) + " bytes");
      skipped += x;
    }
  }

  /**
   * Writes all bytes from {@code input} to a temporary file in {@code target}'s directory and then
   * renames it into place.
   *
   * <p>An atomic move is attempted via {@link #moveTo(File, File)}; when not supported by the
   * filesystem, a non‑atomic replacement is performed. This method does not close the input stream.
   *
   * @param input source of bytes (not closed)
   * @param target destination file to create or replace
   * @return {@code true} on success, {@code false} if the move failed (the temporary file is then
   *     deleted when possible)
   * @throws IOException on I/O failure writing the temporary file
   */
  public static boolean writeTo(InputStream input, File target) throws IOException {
    File file = File.createTempFile("temp", ".tmp", target.getParentFile());
    if (LOG.isDebugEnabled()) {
      LOG.debug("Writing to {} to be renamed to {}", file, target);
    }

    try (FileOutputStream fos = new FileOutputStream(file)) {
      copy(input, fos, -1);
    }

    if (!moveTo(file, target)) {
      try {
        Files.delete(file.toPath());
      } catch (IOException e) {
        LOG.warn("Could not delete temporary file {}", file, e);
      }
      return false;
    }
    return true;
  }

  /**
   * Moves or renames a file, optionally allowing replacement.
   *
   * @param orig file to move
   * @param dest destination path
   * @param overwrite if {@code true}, allow replacing an existing {@code dest}
   * @return {@code true} if moved, {@code false} if {@code dest} exists and {@code overwrite} is
   *     {@code false} or the move otherwise failed
   */
  public static boolean moveTo(File orig, File dest, boolean overwrite) {
    if (!overwrite && dest.exists()) {
      return false;
    }
    return moveTo(orig, dest);
  }

  /**
   * Moves or renames a file, replacing the destination if it exists.
   *
   * <p>An atomic move is attempted ({@link StandardCopyOption#ATOMIC_MOVE}); when not supported, a
   * non‑atomic replacement is performed. This method may fail when moving across filesystems.
   *
   * @param orig file to move
   * @param dest destination path
   * @return {@code true} on success; {@code false} when the move fails
   */
  public static boolean moveTo(File orig, File dest) {
    Path source = orig.toPath();
    Path target = dest.toPath();
    if (tryAtomicMove(source, target, orig, dest)) {
      return true;
    }
    return moveWithReplaceRetries(source, target, orig, dest);
  }

  private static boolean tryAtomicMove(Path source, Path target, File orig, File dest) {
    try {
      Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
      return true;
    } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Atomic move unavailable for {} -> {}: {}", orig, dest, e.toString());
      }
    } catch (IOException e) {
      // On Windows this frequently fails when replacing an existing file; retry with
      // REPLACE_EXISTING before giving up.
      if (LOG.isWarnEnabled()) {
        String atomicFailure = e.toString();
        LOG.warn(
            "Atomic move failed for {} -> {}, retrying non-atomically: {}",
            orig,
            dest,
            atomicFailure);
      }
    }
    return false;
  }

  private static boolean moveWithReplaceRetries(Path source, Path target, File orig, File dest) {
    IOException lastFailure = null;
    for (int attempt = 1; attempt <= REPLACE_MOVE_MAX_ATTEMPTS; attempt++) {
      try {
        Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        return true;
      } catch (IOException e) {
        lastFailure = e;
        if (attempt == 1) {
          LOG.warn(
              "Replace-existing move failed for {} -> {} (attempt {}/{}), retrying: {}",
              orig,
              dest,
              attempt,
              REPLACE_MOVE_MAX_ATTEMPTS,
              e.toString());
        } else if (attempt < REPLACE_MOVE_MAX_ATTEMPTS && LOG.isDebugEnabled()) {
          LOG.debug(
              "Replace-existing move retry failed for {} -> {} (attempt {}/{}): {}",
              orig,
              dest,
              attempt,
              REPLACE_MOVE_MAX_ATTEMPTS,
              e.toString());
        }
        if (attempt == REPLACE_MOVE_MAX_ATTEMPTS) break;
        if (!sleepBeforeReplaceMoveRetry(orig, dest, attempt)) {
          return false;
        }
      }
    }
    LOG.error(
        "Replace-existing move failed for {} -> {} after {} attempts: {}",
        orig,
        dest,
        REPLACE_MOVE_MAX_ATTEMPTS,
        lastFailure,
        lastFailure);
    return false;
  }

  private static boolean sleepBeforeReplaceMoveRetry(File orig, File dest, int attempt) {
    long backoffMillis = retryBackoffMillis(attempt);
    try {
      Thread.sleep(backoffMillis);
      return true;
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      LOG.error(
          "Interrupted while retrying replace-existing move for {} -> {} (attempt {}/{}).",
          orig,
          dest,
          attempt,
          REPLACE_MOVE_MAX_ATTEMPTS,
          interrupted);
      return false;
    }
  }

  private static long retryBackoffMillis(int failedAttempt) {
    long backoff = REPLACE_MOVE_BASE_BACKOFF_MILLIS;
    int shifts = failedAttempt - 1;
    if (shifts > 0) {
      backoff <<= Math.min(shifts, 30);
    }
    return Math.min(backoff, REPLACE_MOVE_MAX_BACKOFF_MILLIS);
  }

  /**
   * Produces a safe filename for the specified target operating system.
   *
   * <p>Control and whitespace characters, characters reserved by the target OS, and any characters
   * listed in {@code extraChars} are replaced with a default substitute (space, underscore, or
   * hyphen). On Windows, trailing spaces and dots are removed. If the basename is a Windows
   * reserved name (e.g., {@code CON}, {@code NUL}), an underscore is prefixed. The result is
   * trimmed; if it is empty, a placeholder string is returned.
   *
   * @param fileName input name to sanitize
   * @param targetOS ruleset to apply; {@link OperatingSystem#UNKNOWN} applies a conservative union
   *     of all supported OS rules
   * @param extraChars additional characters to replace regardless of OS rules
   * @return a sanitized filename
   */
  public static String sanitizeFileName(
      final String fileName, OperatingSystem targetOS, String extraChars) {
    // Filter out any characters that do not exist in the charset.
    final CharBuffer buffer =
        fileNameCharset.decode(fileNameCharset.encode(fileName)); // Charsets are thread‑safe

    final StringBuilder sb = new StringBuilder(fileName.length() + 1);

    char def = chooseDefaultReplacement(extraChars);

    for (char c :
        buffer.array()) { // Note that this will add extra whitespace to the end, which we will trim
      // later.

      boolean replace = shouldReplaceChar(c, targetOS, extraChars);
      sb.append(replace ? def : c);
    }

    // On Windows, a filename must not end with a space or dot; remove any trailing instances.
    trimWindowsTrailingSpaceDot(sb, targetOS);

    // Avoid Windows reserved basenames (e.g., CON, NUL) by prefixing an underscore when needed.
    fixWindowsReservedBasename(sb, targetOS);

    if (sb.isEmpty()) {
      sb.append("Invalid filename"); // Note: not localized
    }

    return sb.toString().trim(); // Trim leading and trailing whitespace.
    // Some of the trailing whitespace may be from the CharBuffer.
  }

  /**
   * Sanitizes a filename using the rules for the detected operating system.
   *
   * @param fileName input name
   * @return a sanitized filename valid on the current platform
   */
  public static String sanitize(String fileName) {
    return sanitizeFileName(fileName, detectedOS, "");
  }

  /**
   * Sanitizes a filename using the rules for the detected operating system and replaces additional
   * caller‑provided characters.
   *
   * @param fileName input name
   * @param extraChars characters that must be replaced regardless of OS rules
   * @return a sanitized filename
   */
  public static String sanitizeFileNameWithExtras(String fileName, String extraChars) {
    return sanitizeFileName(fileName, detectedOS, extraChars);
  }

  /**
   * Sanitizes a filename and enforces an extension suitable for the provided MIME type.
   *
   * @param filename input name
   * @param mimeType MIME type used to select or adjust the filename extension; if {@code null}, no
   *     extension enforcement occurs
   * @return a sanitized filename, possibly with an adjusted extension
   */
  public static String sanitize(String filename, String mimeType) {
    filename = sanitize(filename);
    if (mimeType == null) return filename;
    return DefaultMIMETypes.forceExtension(filename, mimeType);
  }

  /**
   * Copies bytes from {@code source} to {@code destination}.
   *
   * <p>If {@code length == -1}, bytes are copied until the end‑of‑stream; otherwise exactly {@code
   * length} bytes are copied and an {@link EOFException} is thrown if insufficient data is
   * available. This method closes neither stream.
   *
   * @param source input stream to read from (not closed)
   * @param destination output stream to write to (not closed)
   * @param length number of bytes to copy, or {@code -1} to copy until EOF
   * @throws IOException on read or write failure, or when EOF occurs before copying {@code length}
   *     bytes
   */
  public static void copy(InputStream source, OutputStream destination, long length)
      throws IOException {
    long remaining = length == -1 ? Long.MAX_VALUE : length;
    byte[] buffer = new byte[(int) Math.min(remaining, BUFFER_SIZE)];
    int read;
    while (remaining > 0
        && (read = source.read(buffer, 0, (int) Math.min(remaining, BUFFER_SIZE))) != -1) {
      destination.write(buffer, 0, read);
      remaining -= read;
    }
    if (remaining > 0 && length != -1) {
      throw new EOFException("stream reached eof");
    }
  }

  /**
   * Best‑effort secure deletion of a file or recursive deletion of a directory tree.
   *
   * <p>For regular files this overwrites contents with pseudorandom data and then deletes the file.
   * For directories this removes all children and then the directory itself. Deletion is the best
   * effort and may not be effective on some filesystems (e.g., copy‑on‑write, journaling, SSDs).
   *
   * <p>Callers should prefer to check the boolean return value. {@code IOException} is declared for
   * historical reasons; current implementation logs errors and returns {@code false} instead of
   * throwing.
   *
   * @param wd file or directory to delete
   * @return {@code true} on success; {@code false} if any deletion step failed
   * @throws IOException retained for signature compatibility; current implementation logs and
   *     returns {@code false} instead of propagating I/O failures
   */
  @SuppressWarnings("UnusedReturnValue")
  public static boolean secureDeleteAll(File wd) throws IOException {
    if (!wd.isDirectory()) {
      LOG.debug("secureDeleteAll deleting file {}", wd);
      try {
        secureDelete(wd);
      } catch (IOException e) {
        LOG.error("secureDeleteAll failed to delete file {}", wd, e);
        return false;
      }
    } else {
      File[] children = wd.listFiles();
      if (children != null) {
        for (File subfile : children) {
          if (!removeAll(subfile)) return false;
        }
      }
      try {
        Files.delete(wd.toPath());
      } catch (IOException e) {
        LOG.error("secureDeleteAll failed to delete directory {}", wd, e);
      }
    }
    return true;
  }

  /**
   * Recursively deletes a directory and all its contents.
   *
   * <p>Use with caution: this is destructive and irreversible.
   *
   * @param wd directory to delete (or file; files are deleted directly)
   * @return {@code true} on success; {@code false} if any path could not be deleted
   */
  public static boolean removeAll(File wd) {
    if (!wd.isDirectory()) {
      return deleteSingleFile(wd);
    }
    return deleteDirectoryContentsAndSelf(wd);
  }

  /** Deletes a single file, logging and tolerating non-existent paths after an attempt. */
  private static boolean deleteSingleFile(File file) {
    LOG.debug("deleteSingleFile deleting file {}", file);
    try {
      Files.delete(file.toPath());
      return true;
    } catch (IOException e) {
      if (Files.exists(file.toPath())) {
        LOG.error("deleteSingleFile failed to delete file {}", file, e);
        return false;
      }
      return true; // already gone
    }
  }

  /** Recursively deletes all contents of a directory, then the directory itself. */
  private static boolean deleteDirectoryContentsAndSelf(File dir) {
    File[] children = dir.listFiles();
    if (children != null) {
      for (File subfile : children) {
        if (!removeAll(subfile)) return false;
      }
    }
    try {
      Files.delete(dir.toPath());
      return true;
    } catch (IOException e) {
      LOG.error("deleteDirectoryContentsAndSelf failed to delete directory {}", dir, e);
      return false;
    }
  }

  /**
   * Overwrites a regular file with pseudorandom bytes and deletes it.
   *
   * <p>This is the best‑effort mechanism. It may not prevent data recovery on certain storage or
   * filesystems (e.g., wear‑leveling SSDs, COW/journaling filesystems). Consider stronger
   * mitigations when threat models require them. This method performs a single-pass overwriting of
   * file contents and does not attempt metadata scrubbing.
   *
   * @param file non‑directory file to delete; no effect if the file does not exist
   * @throws IOException if the file exists but cannot be deleted
   */
  public static void secureDelete(File file) throws IOException {
    if (!file.exists()) return;
    long size = file.length();
    if (size > 0) {
      try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
        LOG.info("Securely deleting {} which is of length {} bytes...", file, size);
        // Random data first.
        raf.seek(0);
        fill(new RandomAccessFileOutputStream(raf), size);
        raf.getFD().sync();
      }
    }
    try {
      Files.delete(file.toPath());
    } catch (IOException e) {
      if (Files.exists(file.toPath())) throw new IOException("Unable to delete file " + file, e);
    }
  }

  /**
   * Sets owner read/write permissions and removes permissions for groups and others.
   *
   * @param f target file or directory
   * @return {@code true} if all permission changes succeeded
   */
  @SuppressWarnings("UnusedReturnValue")
  public static boolean setOwnerRW(File f) {
    return setOwnerPerm(f, true, true, false);
  }

  /**
   * Sets owner read/write/execute permissions and removes permissions for groups and others.
   *
   * @param f target file or directory
   * @return {@code true} if all permission changes succeeded
   */
  @SuppressWarnings("UnusedReturnValue")
  public static boolean setOwnerRWX(File f) {
    return setOwnerPerm(f, true, true, true);
  }

  /**
   * Sets owner permissions explicitly and removes permissions for groups and others.
   *
   * <p>Semantics depend on the underlying platform. On non‑POSIX platforms some changes may be
   * ignored. The method returns {@code false} if any change operation fails.
   *
   * @param f target file or directory
   * @param r whether the owner may read
   * @param w whether the owner may write
   * @param x whether the owner may execute
   * @return {@code true} if all permission changes succeeded
   */
  public static boolean setOwnerPerm(File f, boolean r, boolean w, boolean x) {
    boolean success = true;
    success &= f.setReadable(false, false);
    success &= f.setReadable(r, true);
    success &= f.setWritable(false, false);
    success &= f.setWritable(w, true);
    success &= f.setExecutable(false, false);
    success &= f.setExecutable(x, true);
    return success;
  }

  /**
   * Compares two paths for equality after canonicalization.
   *
   * <p>This method resolves absolute canonical paths for both arguments (which may normalize case
   * on case‑insensitive platforms) and then compares them with {@link File#equals(Object)}.
   *
   * @param a first file
   * @param b second file
   * @return {@code true} if both refer to the same canonical path
   */
  public static boolean equals(File a, File b) {
    if (Objects.equals(a, b)) return true;
    if (a == null || b == null) return false;
    a = getCanonicalFile(a);
    b = getCanonicalFile(b);
    return a.equals(b);
  }

  /**
   * Creates a temporary file in the given directory.
   *
   * <p>If {@code directory} is {@code null}, the current working directory is used. When the {@code
   * prefix} is shorter than 3 characters, a {@code -TMP} suffix is appended to satisfy the JDK
   * requirement.
   *
   * @param prefix filename prefix (at least 3 characters or extended as noted)
   * @param suffix filename suffix (may be {@code null})
   * @param directory directory in which to create the file; {@code null} means {@code "."}
   * @return the created temporary file
   * @throws IOException if the file cannot be created
   */
  public static File createTempFile(String prefix, String suffix, File directory)
      throws IOException {
    if (directory == null) directory = new File(".");
    if (prefix.length() < 3)
      prefix += "-TMP"; // File.createTempFile requires the prefix to have at least length 3
    return File.createTempFile(prefix, suffix, directory);
  }

  /**
   * Copies a file, replacing the target if it exists, and preserves basic attributes when
   * supported.
   *
   * @param copyFrom source file
   * @param copyTo destination file
   * @return {@code true} on success; {@code false} on failure (errors are logged)
   */
  @SuppressWarnings("unused")
  public static boolean copyFile(File copyFrom, File copyTo) {
    try {
      Path source = copyFrom.toPath();
      Path target = copyTo.toPath();
      Files.copy(
          source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
      return true;
    } catch (IOException | InvalidPathException e) {
      LOG.warn("Unable to copy from {} to {}", copyFrom, copyTo, e);
      return false;
    }
  }

  /**
   * Writes pseudorandom bytes to a stream without using the global secure RNG.
   *
   * <p>Bytes are generated from a per‑call {@link Random} seeded by a synchronized PRNG to avoid
   * draining the global secure generator, providing speed while remaining hard to predict for
   * casual inspection.
   *
   * @param os destination stream (not closed)
   * @param length number of bytes to write
   * @throws IOException if writing fails
   */
  public static void fill(OutputStream os, long length) throws IOException {
    byte[] seed = new byte[16];
    SEED_GENERATOR.nextBytes(seed);
    writeRandomBytes(os, MersenneTwister.createUnsynchronized(seed), length);
  }

  private static void writeRandomBytes(OutputStream os, Random random, long length)
      throws IOException {
    byte[] buffer = new byte[(int) Math.min(length, BUFFER_SIZE)];
    long remaining = length;
    while (remaining > 0) {
      random.nextBytes(buffer);
      int writeLength = (int) Math.min(remaining, BUFFER_SIZE);
      os.write(buffer, 0, writeLength);
      remaining -= writeLength;
    }
  }

  /**
   * Compares two streams for byte equality up to {@code size} bytes.
   *
   * <p>Reads exactly {@code size} bytes from each stream and compares chunk by chunk. Uses {@link
   * MessageDigest#isEqual(byte[], byte[])} to avoid timing differences. Streams are not closed by
   * this method.
   *
   * @param a first stream (not closed)
   * @param b second stream (not closed)
   * @param size number of bytes to compare
   * @return {@code true} if the first {@code size} bytes are identical
   * @throws EOFException if either stream contains fewer than {@code size} bytes
   * @throws IOException on I/O failure
   */
  public static boolean equalStreams(InputStream a, InputStream b, long size) throws IOException {
    byte[] aBuffer = new byte[BUFFER_SIZE];
    byte[] bBuffer = new byte[BUFFER_SIZE];
    DataInputStream aIn = new DataInputStream(a);
    DataInputStream bIn = new DataInputStream(b);
    long checked = 0;
    while (checked < size) {
      int toRead = (int) Math.min(BUFFER_SIZE, size - checked);
      aIn.readFully(aBuffer, 0, toRead);
      bIn.readFully(bBuffer, 0, toRead);
      if (!MessageDigest.isEqual(aBuffer, bBuffer)) return false;
      checked += toRead;
    }
    return true;
  }
}
