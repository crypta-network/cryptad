package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.stream.Stream;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PluginStoresTest {

  @Mock private Node node;
  @Mock private SubConfig subConfig;

  @Test
  void loadPluginStore_whenEncryptedPreferredButOnlyUnencryptedExists_returnsStore(
      @TempDir Path tempDir) throws Exception {
    String storeIdentifier = "demo";
    PluginStore expected = createStore("unencrypted");
    ProgramDirectory programDirectory = stubProgramDirectory(tempDir);
    when(node.wantEncryptedDatabase()).thenReturn(true);

    PluginStores pluginStores = new PluginStores(node, subConfig);
    File unencryptedFile = programDirectory.file(storeIdentifier + ".data");
    writeStoreFile(unencryptedFile, expected);

    PluginStore loaded = pluginStores.loadPluginStore(storeIdentifier);

    assertStoreValues(loaded, "unencrypted", "unencrypted".length());
  }

  @Test
  void loadPluginStore_whenEncryptedBackupExists_returnsBackupStore(@TempDir Path tempDir)
      throws Exception {
    String storeIdentifier = "encryptedBackup";
    byte[] key = new byte[16];
    ProgramDirectory programDirectory = stubProgramDirectory(tempDir);
    when(node.wantEncryptedDatabase()).thenReturn(true);
    when(node.getPluginStoreKey(storeIdentifier)).thenReturn(key);

    PluginStores pluginStores = new PluginStores(node, subConfig);
    PluginStore expected = createStore("backup");
    pluginStores.writePluginStore(storeIdentifier, expected);

    File main = programDirectory.file(storeIdentifier + ".data.crypt");
    File backup = programDirectory.file(storeIdentifier + ".data.bak.crypt");
    assertFalse(backup.exists());
    if (!main.renameTo(backup)) {
      throw new IOException("Failed to rename main store to backup for test setup");
    }

    PluginStore loaded = pluginStores.loadPluginStore(storeIdentifier);

    assertStoreValues(loaded, "backup", "backup".length());
  }

  @ParameterizedTest
  @MethodSource("missingKeyVariants")
  void loadPluginStore_whenEncryptedButKeyMissing_readsPlainCryptFile(
      byte[] key, @TempDir Path tempDir) throws Exception {
    String storeIdentifier = "plainCrypt";
    ProgramDirectory programDirectory = stubProgramDirectory(tempDir);
    when(node.wantEncryptedDatabase()).thenReturn(true);
    when(node.getPluginStoreKey(storeIdentifier)).thenReturn(key);

    PluginStores pluginStores = new PluginStores(node, subConfig);
    PluginStore expected = createStore("plaintext");
    File cryptFile = programDirectory.file(storeIdentifier + ".data.crypt");
    writeStoreFile(cryptFile, expected);

    PluginStore loaded = pluginStores.loadPluginStore(storeIdentifier);

    assertStoreValues(loaded, "plaintext", "plaintext".length());
  }

  @Test
  void loadPluginStore_whenCorruptFile_returnsNull(@TempDir Path tempDir) throws Exception {
    String storeIdentifier = "corrupt";
    ProgramDirectory programDirectory = stubProgramDirectory(tempDir);
    when(node.wantEncryptedDatabase()).thenReturn(false);

    PluginStores pluginStores = new PluginStores(node, subConfig);
    SimpleFieldSet corrupt = new SimpleFieldSet(true, true);
    corrupt.putSingle("string.%%", "bad");
    try (OutputStream os = new FileOutputStream(programDirectory.file(storeIdentifier + ".data"))) {
      corrupt.writeTo(os);
    }

    PluginStore loaded = pluginStores.loadPluginStore(storeIdentifier);

    assertNull(loaded);
  }

  @Test
  void writePluginStore_whenMainExists_renamesToBackup_andCleansOppositeEncryption(
      @TempDir Path tempDir) throws Exception {
    String storeIdentifier = "rotate";
    ProgramDirectory programDirectory = stubProgramDirectory(tempDir);
    when(node.wantEncryptedDatabase()).thenReturn(false);

    PluginStores pluginStores = new PluginStores(node, subConfig);
    PluginStore original = createStore("original");
    PluginStore newStore = createStore("updated");
    PluginStore obsoleteBackup = createStore("obsolete");

    File main = programDirectory.file(storeIdentifier + ".data");
    File backup = programDirectory.file(storeIdentifier + ".data.bak");
    File cryptMain = programDirectory.file(storeIdentifier + ".data.crypt");
    File cryptBackup = programDirectory.file(storeIdentifier + ".data.bak.crypt");
    writeStoreFile(main, original);
    writeStoreFile(backup, obsoleteBackup);
    writeStoreFile(cryptMain, createStore("crypt"));
    writeStoreFile(cryptBackup, createStore("cryptBackup"));

    pluginStores.writePluginStore(storeIdentifier, newStore);

    PluginStore updatedMain = readStoreFromFile(main);
    PluginStore updatedBackup = readStoreFromFile(backup);

    assertStoreValues(updatedMain, "updated", "updated".length());
    assertStoreValues(updatedBackup, "original", "original".length());
    assertFalse(cryptMain.exists());
    assertFalse(cryptBackup.exists());
  }

  private ProgramDirectory stubProgramDirectory(Path tempDir) throws Exception {
    ProgramDirectory programDirectory = new ProgramDirectory();
    Path pluginDir = tempDir.resolve("plugin-data");
    programDirectory.move(pluginDir.toString());
    when(node.setupProgramDir(
            any(SubConfig.class), anyString(), anyString(), anyString(), anyString(), isNull()))
        .thenReturn(programDirectory);
    return programDirectory;
  }

  private static PluginStore createStore(String marker) {
    PluginStore store = new PluginStore();
    store.strings.put("marker", marker);
    store.integers.put("count", marker.length());
    return store;
  }

  private static void assertStoreValues(PluginStore store, String marker, int count) {
    assertNotNull(store);
    assertEquals(marker, store.strings.get("marker"));
    assertEquals(Integer.valueOf(count), store.integers.get("count"));
  }

  private static void writeStoreFile(File file, PluginStore store) throws IOException {
    try (OutputStream os = new FileOutputStream(file)) {
      store.exportStoreAsSFS().writeTo(os);
    }
  }

  private static PluginStore readStoreFromFile(File file) throws Exception {
    try (InputStream is = new FileInputStream(file)) {
      SimpleFieldSet fs = SimpleFieldSet.readFrom(is, false, false, true, true);
      return new PluginStore(fs);
    }
  }

  private static Stream<byte[]> missingKeyVariants() {
    return Stream.of(null, new byte[0]);
  }
}
