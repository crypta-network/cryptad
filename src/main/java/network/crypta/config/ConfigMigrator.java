package network.crypta.config;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import network.crypta.fs.Resolved;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs one-time migration of legacy filesystem layout into adaptive Cryptad directories.
 *
 * <p>This utility is invoked during startup to keep existing installations working when path
 * defaults change from relative locations to directory placeholders such as {@code ${dataDir}} and
 * {@code ${configDir}}. It first ensures a configuration file exists in the configured location by
 * copying a legacy file from historical locations or creating a default template when no prior file
 * is found. It then rewrites known legacy path keys in the configuration and attempts to move
 * well-known data folders from the current working directory into their adaptive destinations.
 *
 * <p>Migration is intentionally best-effort: recoverable move and rewrite failures are logged,
 * while setup steps that cannot proceed safely surface as {@link IOException}.
 *
 * <ul>
 *   <li>Preserves existing destination content by skipping moves when target paths already exist.
 *   <li>Prefers atomic moves and falls back to non-atomic moves when required by the filesystem.
 *   <li>Restricts automatic rewrites to specific legacy keys and exact legacy values.
 * </ul>
 */
public final class ConfigMigrator {
  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.config.ConfigMigrator");

  /**
   * Canonical file name of the node configuration file handled by migration.
   *
   * <p>This constant is used when probing legacy locations and when creating or loading the target
   * configuration file in the adaptive configuration directory.
   */
  public static final String CONFIG_FILE = "cryptad.ini";

  private ConfigMigrator() {}

  /**
   * Migrates legacy configuration and data paths into the adaptive directory layout when needed.
   *
   * <p>The method ensures {@value #CONFIG_FILE} exists in {@code dirs.configDir()}, sourcing it
   * from legacy current-working-directory or executable-directory locations when present, otherwise
   * creating a default template. Afterward it rewrites selected legacy configuration keys to
   * placeholder-based values and attempts to move known legacy folders into adaptive destinations.
   * Move and rewrite failures are treated as best-effort and logged, while unrecoverable setup
   * problems during configuration creation or copy propagate as an exception.
   *
   * @param dirs resolved adaptive directories used as migration destinations and path placeholders
   * @param executableDir absolute directory containing the launcher executable for legacy config
   *     lookup
   * @throws IOException if creating, copying, or initially writing the target configuration file
   *     fails
   */
  public static void migrateIfNeeded(Resolved dirs, Path executableDir) throws IOException {
    Path cfgFile = dirs.configDir().resolve(CONFIG_FILE);

    Path cwd = Paths.get("").toAbsolutePath().normalize();
    Path cwdCfg = cwd.resolve(CONFIG_FILE);
    Path exeCfg = executableDir.resolve(CONFIG_FILE);

    if (!Files.exists(cfgFile)) {
      if (Files.exists(cwdCfg)) {
        CryptadConfig.copyIfMissing(cwdCfg, cfgFile);
        LOG.info("Migrated cryptad.ini from CWD to {}", cfgFile);
      } else if (Files.exists(exeCfg)) {
        CryptadConfig.copyIfMissing(exeCfg, cfgFile);
        LOG.info("Migrated cryptad.ini from executable dir to {}", cfgFile);
      } else {
        if (cfgFile.getParent() != null && !Files.exists(cfgFile.getParent())) {
          Files.createDirectories(cfgFile.getParent());
        }
        Files.writeString(cfgFile, CryptadConfig.DEFAULT_TEMPLATE);
        LOG.info("Created default cryptad.ini at {}", cfgFile);
      }
    }

    if (Files.exists(cfgFile)) {
      rewriteLegacyPaths(cfgFile);
    }

    moveIfPresent(cwd.resolve("datastore"), dirs.dataDir().resolve("datastore"));
    moveIfPresent(cwd.resolve("temp"), dirs.cacheDir().resolve("tmp"));
    moveIfPresent(cwd.resolve("persistent-temp"), dirs.cacheDir().resolve("persistent-temp"));
    moveIfPresent(cwd.resolve("downloads"), dirs.dataDir().resolve("downloads"));
    moveIfPresent(cwd.resolve("logs"), dirs.logsDir());
  }

  private static void moveIfPresent(Path src, Path dst) {
    if (!Files.exists(src) || Files.exists(dst)) {
      return;
    }
    try {
      Path parent = dst.getParent();
      if (parent != null && !Files.exists(parent)) {
        Files.createDirectories(parent);
      }
      Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE);
      LOG.info("Moved {} -> {} (atomic)", src, dst);
    } catch (AtomicMoveNotSupportedException _) {
      try {
        Files.move(src, dst);
        LOG.info("Moved {} -> {} (non-atomic fallback)", src, dst);
      } catch (Exception e2) {
        LOG.warn(
            "Failed to move {} -> {} (fallback after atomic not supported): {}",
            src,
            dst,
            e2.getMessage(),
            e2);
      }
    } catch (Exception e) {
      LOG.warn("Failed to move {} -> {} atomically: {}", src, dst, e.getMessage(), e);
    }
  }

  private static void rewriteLegacyPaths(Path configFile) {
    try {
      SimpleFieldSet sfs = SimpleFieldSet.readFrom(Files.newInputStream(configFile), true, true);

      rewrite(sfs, "node.install.cfgDir", ".", "${configDir}");
      rewrite(sfs, "node.install.userDir", ".", "${configDir}");
      rewrite(sfs, "node.install.nodeDir", ".", "${dataDir}/node");
      rewrite(sfs, "node.install.storeDir", "./datastore", "${dataDir}/datastore");
      rewrite(sfs, "node.install.tempDir", "./temp", "${cacheDir}/tmp");
      rewrite(
          sfs,
          "node.install.persistentTempDir",
          "./persistent-temp",
          "${cacheDir}/persistent-temp");
      rewrite(sfs, "node.downloadsDir", "./downloads", "${dataDir}/downloads");
      rewrite(sfs, "logger.dirname", "./logs", "${logsDir}");

      sfs.writeToBigBuffer(Files.newOutputStream(configFile));
      LOG.info("Rewrote legacy paths in {}", configFile);
    } catch (Exception e) {
      LOG.warn("Failed to rewrite legacy paths in {}: {}", configFile, e.getMessage(), e);
    }
  }

  private static void rewrite(SimpleFieldSet sfs, String key, String rel, String placeholder) {
    String value = sfs.get(key);
    if (value == null) {
      return;
    }
    if (value.equals(rel) || value.equals("./" + rel)) {
      sfs.putOverwrite(key, placeholder);
    }
  }
}
