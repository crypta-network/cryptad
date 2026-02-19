package network.crypta.fs;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Environment and platform detection for Cryptad.
 *
 * <p>New code is written in Java for the Kotlin-to-Java migration.
 */
public final class AppEnv {
  private final Map<String, String> env;
  private final String osName;
  private final String userName;
  private final Function<Path, String> fileReader;

  /** Broad OS family for the current runtime. */
  public enum OsKind {
    WINDOWS,
    MAC,
    LINUX,
    OTHER
  }

  /**
   * Summary of the current runtime environment.
   *
   * <p>- `os`: broad OS family
   *
   * <p>- `arch`: normalized CPU arch (`amd64` or `arm64`; others map to `amd64`)
   *
   * <p>- `availableManagers`: Linux-only package tools present on PATH.
   */
  public static final class EnvDetection {
    private final OsKind os;
    private final String arch;
    private final List<String> availableManagers;

    public EnvDetection(OsKind os, String arch, List<String> availableManagers) {
      this.os = Objects.requireNonNull(os);
      this.arch = Objects.requireNonNull(arch);
      this.availableManagers = List.copyOf(availableManagers);
    }

    public OsKind getOs() {
      return os;
    }

    public String getArch() {
      return arch;
    }

    public List<String> getAvailableManagers() {
      return availableManagers;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof EnvDetection that)) {
        return false;
      }
      return os == that.os
          && Objects.equals(arch, that.arch)
          && Objects.equals(availableManagers, that.availableManagers);
    }

    @Override
    public int hashCode() {
      return Objects.hash(os, arch, availableManagers);
    }

    @Override
    public String toString() {
      return "EnvDetection{"
          + "os="
          + os
          + ", arch='"
          + arch
          + '\''
          + ", availableManagers="
          + availableManagers
          + '}';
    }
  }

  public AppEnv() {
    this(System.getenv());
  }

  public AppEnv(Map<String, String> env) {
    this(env, systemPropertyOrEmpty("os.name"));
  }

  public AppEnv(Map<String, String> env, String osName) {
    this(env, osName, systemPropertyOrEmpty("user.name"));
  }

  public AppEnv(Map<String, String> env, String osName, String userName) {
    this(env, osName, userName, AppEnv::readIfExists);
  }

  public AppEnv(
      Map<String, String> env, String osName, String userName, Function<Path, String> fileReader) {
    this.env = Objects.requireNonNull(env);
    this.osName = osName != null ? osName : "";
    this.userName = userName != null ? userName : "";
    this.fileReader = Objects.requireNonNull(fileReader);
  }

  public boolean isWindows() {
    return osName.toLowerCase(Locale.ROOT).contains("win");
  }

  public boolean isMac() {
    String lowered = osName.toLowerCase(Locale.ROOT);
    return lowered.contains("mac") || lowered.contains("darwin");
  }

  public boolean isLinux() {
    return !isWindows() && !isMac();
  }

  public boolean isFlatpak() {
    return env.containsKey("FLATPAK_ID");
  }

  public boolean isSnap() {
    return env.containsKey("SNAP");
  }

  /**
   * Detects Docker/container runtime on Linux via cgroup markers.
   *
   * <p>Returns true when explicitly overridden by CRYPTAD_DOCKER=1.
   */
  public boolean isDocker() {
    if ("1".equals(env.get("CRYPTAD_DOCKER"))) {
      return true;
    }
    if (!isLinux()) {
      return false;
    }
    Path cgroupPath = Path.of("/proc/1/cgroup");
    if (!Files.exists(cgroupPath)) {
      return false;
    }
    String cgroup = fileReader.apply(cgroupPath);
    if (cgroup == null) {
      return false;
    }
    String s = cgroup.toLowerCase(Locale.ROOT);
    return s.contains("docker") || s.contains("containerd") || s.contains("kubepods");
  }

  public boolean isSystemdService() {
    if (!isLinux()) {
      return false;
    }
    if ("1".equals(env.get("CRYPTAD_SERVICE"))) {
      return true;
    }
    return env.containsKey("CONFIGURATION_DIRECTORY")
        || env.containsKey("STATE_DIRECTORY")
        || env.containsKey("CACHE_DIRECTORY")
        || env.containsKey("LOGS_DIRECTORY")
        || env.containsKey("RUNTIME_DIRECTORY");
  }

  public boolean isWindowsService() {
    if (!isWindows()) {
      return false;
    }
    if ("1".equals(env.get("CRYPTAD_SERVICE"))) {
      return true;
    }
    String user = uppercaseOrNull(env.get("USERNAME"));
    String session = uppercaseOrNull(env.get("SESSIONNAME"));
    return "SYSTEM".equals(user) || "SERVICES".equals(session);
  }

  public boolean isMacService() {
    if (!isMac()) {
      return false;
    }
    if ("1".equals(env.get("CRYPTAD_SERVICE"))) {
      return true;
    }
    return "root".equals(userName) || env.containsKey("LAUNCHD_JOB");
  }

  public boolean isServiceMode() {
    String mode = System.getProperty("cryptad.service.mode");
    if (mode != null) {
      mode = mode.toLowerCase(Locale.ROOT);
      if ("service".equals(mode)) {
        return true;
      }
      if ("user".equals(mode)) {
        return false;
      }
    }
    return "1".equals(env.get("CRYPTAD_SERVICE"))
        || isSystemdService()
        || isWindowsService()
        || isMacService();
  }

  /** Return the current OS family. */
  public OsKind osKind() {
    if (isWindows()) {
      return OsKind.WINDOWS;
    }
    if (isMac()) {
      return OsKind.MAC;
    }
    if (isLinux()) {
      return OsKind.LINUX;
    }
    return OsKind.OTHER;
  }

  /** Return the normalized CPU architecture (`amd64` or `arm64`). */
  public String arch() {
    String prop = systemPropertyOrEmpty("os.arch").toLowerCase(Locale.ROOT);
    if (prop.contains("aarch64") || prop.contains("arm64")) {
      return "arm64";
    }
    return "amd64";
  }

  /** True when an executable is present on the current PATH. */
  public boolean onPath(String cmd) {
    String path = env.get("PATH");
    if (path == null) {
      return false;
    }
    char sep = File.pathSeparatorChar;
    boolean isWin = isWindows();
    String[] dirs = path.split(java.util.regex.Pattern.quote(String.valueOf(sep)));
    for (String dir : dirs) {
      File base = new File(dir, cmd);
      if (base.exists() && base.canExecute()) {
        return true;
      }
      if (isWin) {
        File withExe = new File(dir, cmd + ".exe");
        if (withExe.exists() && withExe.canExecute()) {
          return true;
        }
      }
    }
    return false;
  }

  /** Raw OS name string from the JVM (e.g., "Windows 11", "Mac OS X", "Linux"). */
  public String osNameRaw() {
    return osName;
  }

  /** Raw OS version string from the JVM or empty when unavailable. */
  public String osVersionRaw() {
    return systemPropertyOrEmpty("os.version");
  }

  /**
   * Linux-only: detect available package managers by looking for their executables on PATH. Returns
   * an empty list on non-Linux platforms.
   */
  public List<String> availableManagers() {
    if (!isLinux()) {
      return List.of();
    }
    List<String> managers = new ArrayList<>();
    if (onPath("flatpak")) {
      managers.add("flatpak");
    }
    if (onPath("snap")) {
      managers.add("snap");
    }
    if (onPath("dpkg")) {
      managers.add("dpkg");
    }
    if (onPath("rpm")) {
      managers.add("rpm");
    }
    return managers;
  }

  /** Compute a summary of the current runtime environment. */
  public EnvDetection detectEnvironment() {
    return new EnvDetection(osKind(), arch(), availableManagers());
  }

  private static String readIfExists(Path path) {
    try {
      if (Files.exists(path)) {
        return Files.readString(path);
      }
      return null;
    } catch (IOException ignored) {
      return null;
    }
  }

  private static String systemPropertyOrEmpty(String key) {
    String value = System.getProperty(key);
    return value != null ? value : "";
  }

  private static String uppercaseOrNull(String value) {
    return value == null ? null : value.toUpperCase(Locale.ROOT);
  }
}
