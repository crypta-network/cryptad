package network.crypta.fs;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Shared filesystem constants and helper routines for directory resolution. */
public final class Dirs {
  public static final String PERM_GROUP_RX = "rwxr-x---";
  public static final String PERM_USER_RWX = "rwx------";
  public static final String MACOS_LIBRARY_PATH = "Library";
  public static final String APP_RUNTIME_SUBPATH = "network/crypta";
  public static final String LINUX_RUN_USER_PREFIX = "/run/user";
  public static final String USER_HOME = "user.home";

  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.fs.Dirs");

  private Dirs() {}

  static void ensureDir(Path path, String perms) {
    if (!Files.exists(path)) {
      try {
        Files.createDirectories(path);
      } catch (IOException e) {
        throw new UncheckedIOException("Failed to create directory: " + path, e);
      }
    }
    try {
      if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
        Set<PosixFilePermission> set = PosixFilePermissions.fromString(perms);
        Files.setPosixFilePermissions(path, set);
      }
    } catch (Exception e) {
      LOG.warn("Failed to set POSIX permissions '{}' on {}: {}", perms, path, e.getMessage(), e);
    }
  }

  static boolean isUnitTestRuntime() {
    String testFlag = System.getProperty("cryptad.test", "");
    if ("true".equalsIgnoreCase(testFlag)) {
      return true;
    }

    String cmd = System.getProperty("sun.java.command", "");
    if (cmd.contains("Gradle Test Executor") || cmd.contains("org.gradle.test")) {
      return true;
    }
    if (!System.getProperty("org.gradle.test.worker", "").isEmpty()) {
      return true;
    }
    if (System.getProperty("surefire.test.class.path") != null) {
      return true;
    }
    return hasClass("org.junit.Test") || hasClass("org.junit.jupiter.api.Test");
  }

  static Resolved buildResolved(Bases b, String appDirName, Path runtime, Path logs) {
    return new Resolved(
        b.config().resolve(appDirName).resolve("config"),
        b.data().resolve(appDirName).resolve("data"),
        b.cache().resolve(appDirName),
        runtime,
        logs);
  }

  static Bases xdgBases(Map<String, String> env, String home) {
    return new Bases(
        Paths.get(env.getOrDefault("XDG_CONFIG_HOME", Paths.get(home, ".config").toString())),
        Paths.get(env.getOrDefault("XDG_DATA_HOME", Paths.get(home, ".local", "share").toString())),
        Paths.get(env.getOrDefault("XDG_CACHE_HOME", Paths.get(home, ".cache").toString())));
  }

  static Path computeStandardXdgRuntime(
      Map<String, String> env,
      Map<String, String> systemProperties,
      AppEnv appEnv,
      Path cacheBase) {
    String xdgRuntimeRaw = env.get("XDG_RUNTIME_DIR");
    Path xdgRuntime = xdgRuntimeRaw != null ? Paths.get(xdgRuntimeRaw) : null;

    if (appEnv.isFlatpak()) {
      String appId = env.getOrDefault("FLATPAK_ID", "network.crypta.Cryptad");
      Path base =
          xdgRuntime != null
              ? xdgRuntime
              : Paths.get(LINUX_RUN_USER_PREFIX, systemProperties.getOrDefault("user.name", "0"));
      return base.resolve("app").resolve(appId).resolve(APP_RUNTIME_SUBPATH);
    }

    if (xdgRuntime != null) {
      return xdgRuntime.resolve(APP_RUNTIME_SUBPATH);
    }

    Path uidBased =
        Paths.get(LINUX_RUN_USER_PREFIX)
            .resolve(System.getProperty("user.name", "0"))
            .resolve(APP_RUNTIME_SUBPATH);
    Path parent = uidBased.getParent();
    if (parent != null && Files.isWritable(parent)) {
      return uidBased;
    }
    return cacheBase.resolve("rt");
  }

  static Path computeSnapRuntime(Map<String, String> env, Path cacheBase) {
    String uid = env.get("UID");
    if (uid == null) {
      String rd = env.getOrDefault("XDG_RUNTIME_DIR", "");
      Pattern p = Pattern.compile("^" + Pattern.quote(LINUX_RUN_USER_PREFIX) + "/(\\d+)/");
      Matcher m = p.matcher(rd);
      uid = m.find() ? m.group(1) : "0";
    }

    String snapInstance = env.get("SNAP_INSTANCE_NAME");
    if (snapInstance == null) {
      snapInstance = env.get("SNAP_NAME");
    }
    if (snapInstance == null) {
      snapInstance = "cryptad";
    }

    Path candidate = Paths.get(LINUX_RUN_USER_PREFIX, uid, "snap." + snapInstance);
    try {
      Path parent = candidate.getParent();
      if (parent != null && Files.isWritable(parent)) {
        return candidate;
      }
      return cacheBase.resolve("rt");
    } catch (Exception _) {
      return cacheBase.resolve("rt");
    }
  }

  private static boolean hasClass(String name) {
    try {
      Class.forName(name, false, Dirs.class.getClassLoader());
      return true;
    } catch (ClassNotFoundException | LinkageError _) {
      return false;
    }
  }

  record Bases(Path config, Path data, Path cache) {}
}
