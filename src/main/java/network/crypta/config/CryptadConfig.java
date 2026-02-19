package network.crypta.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.regex.Pattern;
import network.crypta.fs.Resolved;
import network.crypta.support.SimpleFieldSet;

public final class CryptadConfig {
  private static final Pattern TRAVERSAL_PATTERN = Pattern.compile("(^|/)\\.\\.(/|$)");

  private CryptadConfig() {}

  public static SimpleFieldSet loadExpandingPlaceholders(Path configFile, Resolved dirs)
      throws IOException {
    return loadExpandingPlaceholders(configFile, dirs, System.getProperties());
  }

  public static SimpleFieldSet loadExpandingPlaceholders(
      Path configFile, Resolved dirs, Properties systemProps) throws IOException {
    Path parent = configFile.getParent();
    if (parent != null && !Files.exists(parent)) {
      Files.createDirectories(parent);
    }
    if (!Files.exists(configFile)) {
      Files.writeString(configFile, defaultTemplate(), StandardCharsets.UTF_8);
    }
    SimpleFieldSet sfs = SimpleFieldSet.readFrom(Files.newInputStream(configFile), true, true);
    SimpleFieldSet expanded = expandAll(sfs, dirs, systemProps);
    createAll(expanded);
    return expanded;
  }

  public static SimpleFieldSet expandAll(SimpleFieldSet input, Resolved dirs) {
    return expandAll(input, dirs, System.getProperties());
  }

  public static SimpleFieldSet expandAll(
      SimpleFieldSet input, Resolved dirs, Properties systemProps) {
    String home = systemProps.getProperty("user.home");
    String tmp = systemProps.getProperty("java.io.tmpdir");
    Map<String, String> base =
        Map.of(
            "configDir", dirs.getConfigDir().toString(),
            "dataDir", dirs.getDataDir().toString(),
            "stateDir", dirs.getDataDir().toString(),
            "cacheDir", dirs.getCacheDir().toString(),
            "runDir", dirs.getRunDir().toString(),
            "logsDir", dirs.getLogsDir().toString(),
            "home", home,
            "tmp", tmp);

    SimpleFieldSet out = new SimpleFieldSet(input);
    Iterator<String> it = out.keyIterator();
    while (it.hasNext()) {
      String key = it.next();
      String value = out.get(key);
      if (value == null) {
        continue;
      }
      String newVal = expandValue(value, base);
      if (!Objects.equals(newVal, value)) {
        out.putOverwrite(key, newVal);
      }
    }
    ensureFinalDefaults(out, base);
    return out;
  }

  private static void ensureFinalDefaults(SimpleFieldSet sfs, Map<String, String> base) {
    String userDir = Path.of(base.get("dataDir"), "user").toString();
    setIfMissing(sfs, "node.install.cfgDir", base.get("configDir"));
    setIfMissing(sfs, "node.install.storeDir", base.get("dataDir"));
    setIfMissing(sfs, "node.install.userDir", userDir);
    setIfMissing(
        sfs,
        "node.install.pluginStoresDir",
        Path.of(base.get("dataDir"), "plugin-data").toString());
    setIfMissing(sfs, "node.install.pluginDir", Path.of(base.get("dataDir"), "plugins").toString());
    setIfMissing(sfs, "node.install.tempDir", Path.of(base.get("cacheDir"), "tmp").toString());
    setIfMissing(
        sfs,
        "node.install.persistentTempDir",
        Path.of(base.get("cacheDir"), "persistent-temp").toString());
    setIfMissing(sfs, "node.install.nodeDir", Path.of(base.get("dataDir"), "node").toString());
    setIfMissing(sfs, "node.install.runDir", base.get("runDir"));
    setIfMissing(sfs, "node.downloadsDir", Path.of(base.get("dataDir"), "downloads").toString());
    setIfMissing(sfs, "logger.dirname", base.get("logsDir"));
    setIfMissing(sfs, "node.masterKeyFile", Path.of(userDir, "master.keys").toString());
  }

  private static void setIfMissing(SimpleFieldSet sfs, String key, String value) {
    if (sfs.get(key) == null) {
      sfs.putSingle(key, value);
    }
  }

  /**
   * Expands a single configuration value by:
   *
   * <p>- Replacing placeholders like ${configDir}, ${dataDir}, etc.
   *
   * <p>- Expanding leading-token shorthand like dataDir/foo or dataDir\foo.
   *
   * <p>- Anchoring to known base directories and normalizing the path.
   *
   * <p>- Enforcing traversal protection for anchored bases.
   */
  public static String expandValue(String value, Map<String, String> base) {
    try {
      PlaceholderResult afterPlaceholders = replacePlaceholders(value, base);
      String afterLeadingToken = expandLeadingToken(afterPlaceholders.value, base);
      AnchorResult anchored = anchorAndNormalize(afterLeadingToken, base, value);
      validateUnanchoredTraversal(
          anchored.value, anchored.anchored, afterPlaceholders.replacedAny, value);
      return anchored.value;
    } catch (IOException ioe) {
      throw sneakyThrow(ioe);
    }
  }

  private static String normSep(String s) {
    return s.replace('\\', '/');
  }

  private static PlaceholderResult replacePlaceholders(String input, Map<String, String> base) {
    String out = input;
    boolean replacedAny = false;
    for (Map.Entry<String, String> e : base.entrySet()) {
      String placeholder = "${" + e.getKey() + "}";
      if (out.contains(placeholder)) {
        replacedAny = true;
      }
      out = out.replace(placeholder, e.getValue());
    }
    return new PlaceholderResult(out, replacedAny);
  }

  private static String expandLeadingToken(String input, Map<String, String> base) {
    String out = input;
    for (Map.Entry<String, String> e : base.entrySet()) {
      String key = e.getKey();
      String val = e.getValue();
      if (out.equals(key)) {
        out = val;
      } else if (out.startsWith(key + "/") || out.startsWith(key + "\\")) {
        String rem = out.substring(key.length() + 1);
        String remNorm = normSep(rem);
        out = Path.of(val, remNorm).toString();
      }
    }
    return out;
  }

  private static AnchorResult anchorAndNormalize(
      String input, Map<String, String> base, String original) throws IOException {
    String out = input;
    boolean anchored = false;
    String outNorm = normSep(out);

    for (String v : base.values()) {
      Path basePath = Path.of(v).normalize();
      String vNorm = normSep(v);
      while (vNorm.endsWith("/")) {
        vNorm = vNorm.substring(0, vNorm.length() - 1);
      }

      if (outNorm.equals(vNorm) || outNorm.equals(vNorm + "/")) {
        out = basePath.toString();
        anchored = true;
        continue;
      }

      String prefix = vNorm + "/";
      if (outNorm.startsWith(prefix)) {
        String remainder = outNorm.substring(prefix.length());
        Path resolved = basePath.resolve(remainder).normalize();
        if (!resolved.startsWith(basePath)) {
          throw new IOException(
              "Illegal path traversal in config value: '"
                  + original
                  + "' (resolved: '"
                  + resolved
                  + "')");
        }
        out = resolved.toString();
        anchored = true;
      }
    }
    return new AnchorResult(out, anchored);
  }

  private static void validateUnanchoredTraversal(
      String out, boolean anchored, boolean replacedAny, String original) throws IOException {
    if (replacedAny && !anchored) {
      String safe = normSep(out);
      if (TRAVERSAL_PATTERN.matcher(safe).find()) {
        throw new IOException(
            "Illegal path traversal in config value: '"
                + original
                + "' (unanchored with '..' segments)");
      }
    }
  }

  private static void createAll(SimpleFieldSet sfs) {
    List<String> keys =
        List.of(
            "node.install.cfgDir",
            "node.install.storeDir",
            "node.install.userDir",
            "node.install.pluginStoresDir",
            "node.install.pluginDir",
            "node.install.tempDir",
            "node.install.persistentTempDir",
            "node.install.nodeDir",
            "node.install.runDir",
            "node.downloadsDir",
            "logger.dirname");

    List<Path> dirs = new ArrayList<>();
    for (String key : keys) {
      String value = sfs.get(key);
      if (value != null) {
        dirs.add(Path.of(value));
      }
    }
    for (Path dir : dirs) {
      try {
        if (!Files.exists(dir)) {
          Files.createDirectories(dir);
        }
      } catch (Exception ignored) {
        // Best effort.
      }
    }
  }

  public static String defaultTemplate() {
    return """
    # Cryptad config (auto-generated)
    logger.priority=NORMAL
    node.updater.enabled=true
    node.updater.autoupdate=false
    End
    """
        + "\n";
  }

  public static void copyIfMissing(Path src, Path dst) throws IOException {
    if (!Files.exists(dst) && Files.exists(src)) {
      Path parent = dst.getParent();
      if (parent != null && !Files.exists(parent)) {
        Files.createDirectories(parent);
      }
      Files.copy(src, dst, StandardCopyOption.COPY_ATTRIBUTES);
    }
  }

  private static RuntimeException sneakyThrow(Throwable t) {
    CryptadConfig.<RuntimeException>throwAny(t);
    throw new IllegalStateException("Unreachable");
  }

  @SuppressWarnings("unchecked")
  private static <T extends Throwable> void throwAny(Throwable t) throws T {
    throw (T) t;
  }

  private record PlaceholderResult(String value, boolean replacedAny) {}

  private record AnchorResult(String value, boolean anchored) {}
}
