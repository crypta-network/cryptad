package network.crypta.pluginmanager;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.config.SubConfig;
import network.crypta.crypt.AEADCryptBucket;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.node.NodeInitException;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.PaddedBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages on-disk persistence for plugin data stores associated with a running node.
 *
 * <p>This helper creates and locates the per-plugin store files under the configured program
 * directory, handles the encrypted and unencrypted variants, and encapsulates the fallback sequence
 * used when loading existing data. Typical usage is to construct one instance during node startup,
 * call {@link #loadPluginStore(String)} when a plugin initializes, and call {@link
 * #writePluginStore(String, PluginStore)} when the plugin persists updates. It does not retain
 * state beyond the node reference and the resolved directory.
 *
 * <p>Storage files are rotated with a simple main/backup scheme and are read using authenticated
 * encryption when configured. The class itself does not synchronize access, so callers should
 * coordinate concurrent reads or writes for the same store identifier to avoid races or partial
 * updates. Failures to parse or authenticate a store are reported via logging and result in a
 * {@code null} return so callers can fall back to defaults.
 *
 * <ul>
 *   <li>Derives store file locations for main and backup data.
 *   <li>Applies optional encryption and padding wrappers.
 *   <li>Loads stores with a deterministic fallback order.
 * </ul>
 */
public class PluginStores {

  private static final Logger LOG = LoggerFactory.getLogger(PluginStores.class);
  private static final String LOAD_STORE_ERROR_PREFIX = "Unable to load plugin data for ";
  private static final String LOAD_STORE_ERROR_SUFFIX =
      "This could be caused by data corruption or bugs in Crypta.";

  final Node node;
  private final ProgramDirectory pluginStoresDir;

  /**
   * Creates a plugin store manager and ensures the backing directory is available.
   *
   * <p>The directory location is resolved through the node configuration and is created if it does
   * not already exist. This constructor is typically invoked once during node initialization and is
   * expected to be long-lived for the process lifetime. If the program directory cannot be
   * configured or validated, initialization fails with a {@link NodeInitException}. When the
   * directory cannot be created at runtime, a warning is logged and subsequent operations may still
   * fail.
   *
   * @param node live node instance used to resolve directories and encryption keys; must be
   *     non-null
   * @param installConfig configuration scope used to look up the plugin storage path; must be
   *     non-null
   * @throws NodeInitException if the plugin storage directory cannot be resolved or initialized
   */
  public PluginStores(Node node, SubConfig installConfig) throws NodeInitException {
    this.node = node;
    pluginStoresDir =
        node.setupProgramDir(
            installConfig,
            "pluginStoresDir",
            "plugin-data",
            "NodeClientCore.pluginStoresDir",
            "NodeClientCore.pluginStoresDir",
            null);
    File dir = pluginStoresDir.dir();
    if (!(dir.mkdirs() || (dir.exists() && dir.isDirectory() && dir.canRead() && dir.canWrite()))) {
      LOG.error("Unable to create folder for plugin data: {}", pluginStoresDir.dir());
    }
  }

  private void writePluginStoreInner(
      String storeIdentifier, PluginStore pluginStore, boolean isEncrypted) throws IOException {
    try (Bucket bucket = makePluginStoreBucket(storeIdentifier, isEncrypted);
        OutputStream os = bucket.getOutputStream()) {
      if (pluginStore != null) {
        pluginStore.exportStoreAsSFS().writeTo(os);
      }
    }
  }

  private File getPluginStoreFile(String storeIdentifier, boolean encrypted, boolean backup) {
    String filename = storeIdentifier;
    filename += ".data";
    if (backup) filename += ".bak";
    if (encrypted) filename += ".crypt";
    return pluginStoresDir.file(filename);
  }

  private Bucket makePluginStoreBucket(String storeIdentifier, boolean isEncrypted) {
    File f = getPluginStoreFile(storeIdentifier, isEncrypted, false);
    Bucket bucket = new FileBucket(f, false, true, false, false);
    if (isEncrypted) {
      byte[] key = node.storage().getPluginStoreKey(storeIdentifier);
      if (key != null && key.length > 0) {
        // We pad then encrypt, which is wasteful, but we have no way to persist the size.
        // Unfortunately AEADCryptBucket needs to know the real termination point.
        bucket = new AEADCryptBucket(bucket, key);
        bucket = new PaddedBucket(bucket);
      }
    }
    return bucket;
  }

  private Bucket findPluginStoreBucket(
      String storeIdentifier, boolean isEncrypted, boolean backup) {
    File f = getPluginStoreFile(storeIdentifier, isEncrypted, backup);
    if (!f.exists()) return null;
    Bucket bucket = new FileBucket(f, false, false, false, false);
    if (isEncrypted) {
      byte[] key = node.storage().getPluginStoreKey(storeIdentifier);
      if (key != null && key.length > 0) {
        // We pad then encrypt, which is wasteful, but we have no way to persist the size.
        // Unfortunately AEADCryptBucket needs to know the real termination point.
        bucket = new AEADCryptBucket(bucket, key);
        bucket = new PaddedBucket(bucket, bucket.size());
      }
    }
    return bucket;
  }

  /**
   * Loads a plugin store by trying the encrypted/plain and main/backup combinations.
   *
   * <p>This method follows a fixed fallback order: it first tries the preferred encryption mode
   * using the main file, then the backup file, and finally repeats the sequence with the opposite
   * encryption mode. If a file is missing, unreadable, or fails authenticated decoding, the method
   * logs the error and continues to the next candidate. A {@code null} return indicates that no
   * usable store data could be loaded and the caller should recreate defaults.
   *
   * <pre>{@code
   * PluginStore store = pluginStores.loadPluginStore("my-plugin");
   * if (store == null) {
   *   store = new PluginStore(new SimpleFieldSet(true));
   * }
   * }</pre>
   *
   * @param storeIdentifier stable per-plugin identifier used to derive the file name; not null or
   *     blank
   * @return the loaded plugin store, or {@code null} when no valid store file can be read
   */
  public PluginStore loadPluginStore(String storeIdentifier) {
    boolean isEncrypted = node.wantEncryptedDatabase();
    PluginStore store = loadPluginStore(storeIdentifier, isEncrypted, false);
    if (store != null) return store;
    store = loadPluginStore(storeIdentifier, isEncrypted, true);
    if (store != null) return store;
    isEncrypted = !isEncrypted;
    store = loadPluginStore(storeIdentifier, isEncrypted, false);
    if (store != null) return store;
    store = loadPluginStore(storeIdentifier, isEncrypted, true);
    return store;
  }

  private PluginStore loadPluginStore(String storeIdentifier, boolean isEncrypted, boolean backup) {
    Bucket bucket = findPluginStoreBucket(storeIdentifier, isEncrypted, backup);
    if (bucket == null) return null;
    try (Bucket bucketResource = bucket;
        InputStream is = bucketResource.getInputStream()) {
      // Do NOT use IOUtils.closeQuietly().
      // We use authenticated encryption, which will throw at close() time if the file is corrupt,
      // or has been modified while the node was offline etc.
      SimpleFieldSet fs = SimpleFieldSet.readFrom(is, false, false, true, true);
      return new PluginStore(fs);
    } catch (IOException | IllegalBase64Exception | FSParseException e) {
      // Hence, if close() throws, we DO need to catch it here.
      LOG.warn("{}{} : {}", LOAD_STORE_ERROR_PREFIX, storeIdentifier, e.toString());
      LOG.warn(LOAD_STORE_ERROR_SUFFIX);
      return null;
    }
  }

  /**
   * Writes a plugin store, rotating any existing file to a backup beforehand.
   *
   * <p>The current main file is renamed to a backup when possible, then a new file is written in
   * the node's preferred encryption mode. Any stale files for the opposite encryption mode are
   * removed to avoid ambiguity during subsequent loads. This operation is not atomic across
   * filesystem boundaries, so callers should avoid concurrent writes for the same identifier.
   *
   * <pre>{@code
   * PluginStore store = buildUpdatedStore();
   * pluginStores.writePluginStore("my-plugin", store);
   * }</pre>
   *
   * @param storeIdentifier stable per-plugin identifier used to derive the file name; not null or
   *     blank
   * @param store store data to persist; when null, an empty store file is written
   * @throws IOException if creating or writing the store file fails
   */
  public void writePluginStore(String storeIdentifier, PluginStore store) throws IOException {
    boolean isEncrypted = node.wantEncryptedDatabase();
    File backup = getPluginStoreFile(storeIdentifier, isEncrypted, true);
    File main = getPluginStoreFile(storeIdentifier, isEncrypted, false);
    if (backup.exists() && main.exists()) {
      FileUtil.secureDelete(backup);
    }
    if (main.exists() && !main.renameTo(backup)) {
      LOG.warn(
          "Unable to rename {} to {} when writing pluginstore for {}",
          main,
          backup,
          storeIdentifier);
    }
    writePluginStoreInner(storeIdentifier, store, isEncrypted);
    File f = getPluginStoreFile(storeIdentifier, !isEncrypted, true);
    if (f.exists()) {
      FileUtil.secureDelete(f);
    }
    f = getPluginStoreFile(storeIdentifier, !isEncrypted, false);
    if (f.exists()) {
      FileUtil.secureDelete(f);
    }
  }
}
