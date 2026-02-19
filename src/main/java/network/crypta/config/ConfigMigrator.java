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

/** Best-effort migration from legacy relative paths to adaptive directories. */
public final class ConfigMigrator {
  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.config.ConfigMigrator");

  public static final String CONFIG_FILE = "cryptad.ini";
  private static final String PLUGINS_DIR = "plugins";

  private ConfigMigrator() {}

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
        Files.writeString(cfgFile, CryptadConfig.defaultTemplate());
        LOG.info("Created default cryptad.ini at {}", cfgFile);
      }
    }

    if (Files.exists(cfgFile)) {
      rewriteLegacyPaths(cfgFile);
    }

    moveIfPresent(cwd.resolve("datastore"), dirs.dataDir().resolve("datastore"));
    moveIfPresent(cwd.resolve(PLUGINS_DIR), dirs.dataDir().resolve(PLUGINS_DIR));
    moveIfPresent(cwd.resolve("plugin-data"), dirs.dataDir().resolve(PLUGINS_DIR));
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

  private static void rewriteLegacyPaths(Path configFile) throws IOException {
    try {
      SimpleFieldSet sfs = SimpleFieldSet.readFrom(Files.newInputStream(configFile), true, true);

      rewrite(sfs, "node.install.cfgDir", ".", "${configDir}");
      rewrite(sfs, "node.install.userDir", ".", "${configDir}");
      rewrite(sfs, "node.install.nodeDir", ".", "${dataDir}/node");
      rewrite(sfs, "node.install.storeDir", "./datastore", "${dataDir}/datastore");
      rewrite(sfs, "node.install.pluginDir", "./plugins", "${dataDir}/plugins");
      rewrite(sfs, "node.install.pluginStoresDir", "plugin-data", "${dataDir}/plugins");
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
