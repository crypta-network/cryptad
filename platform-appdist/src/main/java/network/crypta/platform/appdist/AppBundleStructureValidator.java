package network.crypta.platform.appdist;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Validates staged bundle structure and host-independent launchability metadata.
 *
 * <p>This validator keeps signing and verification deterministic across build hosts while still
 * rejecting bundles whose declared executable is not launchable on any supported platform. It does
 * not ask whether the current host can execute the app. Instead, it recognizes bundle metadata that
 * is portable enough to sign on one platform and install on another, such as Windows batch files,
 * Windows PE executables, POSIX shell scripts, and POSIX files whose execute bit is part of the
 * signed digest.
 *
 * <p>The validator also protects the signing input boundary. The manifest must be present and safe,
 * {@code app.exec} must resolve to a regular file under the bundle root, and aliased paths such as
 * symlinks or reparse-point escapes are rejected before digest generation reads file contents.
 */
public final class AppBundleStructureValidator {
  private static final int MAX_SHEBANG_PROBE_BYTES = 4096;
  private static final int DOS_HEADER_SIZE = 64;
  private static final int PE_POINTER_OFFSET = 0x3C;
  private static final int COFF_HEADER_SIZE = 24;
  private static final int IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
  private static final int IMAGE_FILE_DLL = 0x2000;

  private AppBundleStructureValidator() {}

  /**
   * Validates one staged bundle and returns the parsed manifest plus resolved executable path.
   *
   * <p>The returned snapshot is consumed by {@link AppBundleDigestWriter} so executable permission
   * metadata can be authenticated only when it affects launchability. The method performs
   * filesystem checks for the manifest and executable, but it does not walk every bundle entry; the
   * digest writer performs the full tree traversal after this launchability gate succeeds.
   *
   * @param bundleRoot staged bundle root directory to validate as a local bundle
   * @return validated bundle structure snapshot with manifest, executable path, and launch mode
   * @throws IOException if the bundle manifest, executable path, or launchability checks fail
   */
  public static ValidatedBundle validate(Path bundleRoot) throws IOException {
    Path normalizedBundleRoot = AppDistributionSidecars.requireBundleRoot(bundleRoot);
    Path bundleRealRoot = normalizedBundleRoot.toRealPath();
    AppBundleManifest manifest =
        AppBundleManifestParser.parse(
            normalizedBundleRoot.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME));
    Path executable = normalizedBundleRoot.resolve(manifest.execPath()).normalize();
    if (!Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException(
          "app.exec does not resolve to a file in bundle: " + manifest.execPathText());
    }
    AppDistributionSidecars.validateBundleEntry(normalizedBundleRoot, bundleRealRoot, executable);
    validateStaticUiEntry(normalizedBundleRoot, bundleRealRoot, manifest);
    LaunchMode launchMode = classifyLaunchMode(executable);
    if (launchMode == null) {
      throw new AppDistributionException(
          "app.exec is not launchable on any supported platform: " + manifest.execPathText());
    }
    return new ValidatedBundle(manifest, executable, launchMode);
  }

  private static void validateStaticUiEntry(
      Path normalizedBundleRoot, Path bundleRealRoot, AppBundleManifest manifest)
      throws IOException {
    if (manifest.uiMode() != AppUiMode.STATIC) {
      return;
    }
    Path staticEntry = normalizedBundleRoot.resolve(manifest.staticUiEntryPath()).normalize();
    if (!Files.isRegularFile(staticEntry, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException(
          "app.ui.entry does not resolve to a file in bundle: " + manifest.uiEntry());
    }
    AppDistributionSidecars.validateBundleEntry(normalizedBundleRoot, bundleRealRoot, staticEntry);
  }

  private static LaunchMode classifyLaunchMode(Path executable) throws IOException {
    if (isWindowsBatchScript(executable)) {
      return LaunchMode.WINDOWS_BATCH;
    }
    if (hasWindowsComExecutableSuffix(executable)) {
      return LaunchMode.WINDOWS_COM;
    }
    if (hasLaunchablePortableExecutable(executable)) {
      return LaunchMode.WINDOWS_PE;
    }
    if (isInterpreterManagedPosixLauncher(executable)) {
      return LaunchMode.POSIX_INTERPRETED;
    }
    if (hasAnyPosixExecuteBit(executable)) {
      return LaunchMode.POSIX_EXECUTABLE;
    }
    return null;
  }

  private static boolean isWindowsBatchScript(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".cmd") || fileName.endsWith(".bat");
  }

  private static boolean hasWindowsComExecutableSuffix(Path executable) {
    return fileNameLowercase(executable).endsWith(".com");
  }

  private static boolean hasLaunchablePortableExecutable(Path executable) throws IOException {
    try (SeekableByteChannel channel = Files.newByteChannel(executable)) {
      if (channel.size() < DOS_HEADER_SIZE) {
        return false;
      }
      ByteBuffer dosHeader = ByteBuffer.allocate(DOS_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
      if (channel.read(dosHeader) < DOS_HEADER_SIZE) {
        return false;
      }
      dosHeader.flip();
      if (dosHeader.get() != 'M' || dosHeader.get() != 'Z') {
        return false;
      }

      int peHeaderOffset = dosHeader.getInt(PE_POINTER_OFFSET);
      if (peHeaderOffset < DOS_HEADER_SIZE
          || channel.size() < (long) peHeaderOffset + COFF_HEADER_SIZE) {
        return false;
      }

      ByteBuffer coffHeader = ByteBuffer.allocate(COFF_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
      channel.position(peHeaderOffset);
      if (channel.read(coffHeader) < COFF_HEADER_SIZE) {
        return false;
      }
      coffHeader.flip();
      if (coffHeader.get() != 'P'
          || coffHeader.get() != 'E'
          || coffHeader.get() != 0
          || coffHeader.get() != 0) {
        return false;
      }
      coffHeader.position(22);
      int characteristics = Short.toUnsignedInt(coffHeader.getShort());
      return (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
          && (characteristics & IMAGE_FILE_DLL) == 0;
    }
  }

  private static boolean isInterpreterManagedPosixLauncher(Path executable) throws IOException {
    return classifyPosixLauncher(executable) != null;
  }

  private static PosixLauncher classifyPosixLauncher(Path executable) throws IOException {
    String shebang = readShebang(executable);
    if (shebang.isBlank()) {
      return hasPosixShellScriptSuffix(executable)
          ? new PosixLauncher(List.of(posixShellInterpreter()), true)
          : null;
    }
    List<String> interpreter = parseShebangInterpreter(shebang);
    return new PosixLauncher(interpreter, isPosixShellInterpreter(interpreter));
  }

  private static String readShebang(Path executable) throws IOException {
    try (var input = Files.newInputStream(executable)) {
      if (input.read() != '#' || input.read() != '!') {
        return "";
      }
      var shebangBytes = new ByteArrayOutputStream();
      for (int bytesRead = 2; bytesRead < MAX_SHEBANG_PROBE_BYTES; bytesRead++) {
        int nextByte = input.read();
        if (nextByte < 0 || nextByte == '\n' || nextByte == '\r') {
          break;
        }
        shebangBytes.write(nextByte);
      }
      return shebangBytes.toString(StandardCharsets.UTF_8).trim();
    }
  }

  private static List<String> parseShebangInterpreter(String shebang)
      throws AppDistributionException {
    int argumentOffset = firstWhitespaceOffset(shebang);
    if (argumentOffset < 0) {
      validateShebangInterpreter(shebang);
      return List.of(shebang);
    }
    String interpreter = shebang.substring(0, argumentOffset);
    validateShebangInterpreter(interpreter);
    String interpreterArgument = shebang.substring(argumentOffset).trim();
    if (interpreterArgument.isEmpty()) {
      return List.of(interpreter);
    }
    return List.of(interpreter, interpreterArgument);
  }

  private static boolean isPosixShellInterpreter(List<String> interpreter) {
    if (interpreter.isEmpty()) {
      return false;
    }
    String interpreterName = commandBasename(interpreter.getFirst());
    if (isKnownPosixShellName(interpreterName)) {
      return true;
    }
    if (!interpreterName.equals("env") || interpreter.size() < 2) {
      return false;
    }
    return envInvokesPosixShell(interpreter.get(1));
  }

  private static boolean envInvokesPosixShell(String argumentText) {
    String trimmed = argumentText.trim();
    if (trimmed.isEmpty()) {
      return false;
    }
    if (trimmed.startsWith("-S ")) {
      trimmed = trimmed.substring(3).trim();
    }
    return isKnownPosixShellName(commandBasename(firstToken(trimmed)));
  }

  private static boolean isKnownPosixShellName(String commandName) {
    return switch (commandName) {
      case "sh", "ash", "bash", "dash", "ksh", "mksh", "zsh" -> true;
      default -> false;
    };
  }

  private static boolean hasAnyPosixExecuteBit(Path executable) throws IOException {
    if (!Files.getFileStore(executable).supportsFileAttributeView("posix")) {
      return false;
    }
    Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(executable);
    return permissions.contains(PosixFilePermission.OWNER_EXECUTE)
        || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
        || permissions.contains(PosixFilePermission.OTHERS_EXECUTE);
  }

  private static String firstToken(String text) {
    int offset = firstWhitespaceOffset(text);
    return offset < 0 ? text : text.substring(0, offset);
  }

  private static void validateShebangInterpreter(String interpreter)
      throws AppDistributionException {
    if (commandBasename(interpreter).isEmpty()) {
      throw new AppDistributionException("invalid shebang interpreter: " + interpreter);
    }
  }

  private static int firstWhitespaceOffset(String text) {
    for (int i = 0; i < text.length(); i++) {
      if (Character.isWhitespace(text.charAt(i))) {
        return i;
      }
    }
    return -1;
  }

  private static boolean hasPosixShellScriptSuffix(Path executable) {
    return fileNameLowercase(executable).endsWith(".sh");
  }

  private static String posixShellInterpreter() {
    return Path.of("/bin", "sh").toString();
  }

  private static String commandBasename(String command) {
    if (command.isBlank()) {
      return "";
    }
    Path fileName = Path.of(command).getFileName();
    if (fileName == null) {
      return "";
    }
    return fileName.toString().toLowerCase(Locale.ROOT);
  }

  private static String fileNameLowercase(Path path) {
    Path fileName = path.getFileName();
    return (fileName == null ? "" : fileName.toString()).toLowerCase(Locale.ROOT);
  }

  private record PosixLauncher(List<String> interpreter, boolean shellManaged) {
    private PosixLauncher {
      interpreter = List.copyOf(interpreter);
    }
  }

  /** Host-independent launch mode classification for {@code app.exec}. */
  public enum LaunchMode {
    /**
     * Windows batch or command script launcher.
     *
     * <p>These files are launched through the Windows command interpreter by AppHost and do not
     * rely on POSIX execute-bit metadata.
     */
    WINDOWS_BATCH(false),
    /**
     * Windows {@code .com} executable launcher.
     *
     * <p>The suffix is treated as launchable Windows metadata and does not require an authenticated
     * POSIX executable bit.
     */
    WINDOWS_COM(false),
    /**
     * Windows Portable Executable launcher.
     *
     * <p>The file must contain a PE header marked as an executable image and not as a DLL.
     */
    WINDOWS_PE(false),
    /**
     * POSIX launcher handled by an interpreter.
     *
     * <p>This covers supported shebangs and shell-script suffixes where AppHost can invoke the
     * interpreter directly. POSIX execute-bit state is not part of the signed payload for this
     * mode.
     */
    POSIX_INTERPRETED(false),
    /**
     * POSIX launcher whose launchability depends on execute permissions.
     *
     * <p>Digest entries for this mode authenticate the executable-bit state so permission changes
     * after signing are detected during verification.
     */
    POSIX_EXECUTABLE(true);

    private final boolean authenticatesExecutableBit;

    LaunchMode(boolean authenticatesExecutableBit) {
      this.authenticatesExecutableBit = authenticatesExecutableBit;
    }

    boolean authenticatesExecutableBit() {
      return authenticatesExecutableBit;
    }
  }

  /**
   * Validated bundle structure snapshot.
   *
   * <p>The snapshot carries the normalized manifest and executable path that were checked before
   * digest generation. It also records the host-independent launch mode so the digest writer can
   * decide whether executable permission metadata must be included for the declared launcher.
   *
   * @param manifest parsed and normalized bundle manifest
   * @param executable resolved executable path under the bundle root
   * @param launchMode host-independent launchability classification for {@code app.exec}
   */
  public record ValidatedBundle(
      AppBundleManifest manifest, Path executable, LaunchMode launchMode) {
    /**
     * Creates a validated bundle structure snapshot.
     *
     * @param manifest parsed and normalized bundle manifest
     * @param executable resolved executable path under the bundle root
     * @param launchMode host-independent launchability classification for {@code app.exec}
     */
    public ValidatedBundle {
      java.util.Objects.requireNonNull(manifest, "manifest");
      java.util.Objects.requireNonNull(executable, "executable");
      java.util.Objects.requireNonNull(launchMode, "launchMode");
    }

    Boolean authenticatedExecutableBit() {
      return launchMode.authenticatesExecutableBit() ? Boolean.TRUE : null;
    }
  }
}
