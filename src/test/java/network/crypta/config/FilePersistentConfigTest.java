package network.crypta.config;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FilePersistentConfigTest {

  private static final String HEADER_UNIT = "Unit Test Header";
  private static final String SHORT_DESC = "short";
  private static final String LONG_DESC = "long";

  @Test
  @DisplayName("construct_whenMainFileHasContent_registerAppliesInitialValues")
  void construct_whenMainFileHasContent_registerAppliesInitialValues(@TempDir File tmp)
      throws Exception {
    // Arrange
    File cfg = new File(tmp, "config.ini");
    writeSfs(cfg, "# header one\n", "test.prefix.key=value-from-file\n", "End\n");

    // Act
    FilePersistentConfig cfgObj =
        FilePersistentConfig.constructFilePersistentConfig(cfg, HEADER_UNIT);

    // Register subconfig and option; should read the initial value from the file
    SubConfig sc = cfgObj.createSubConfig("test.prefix");
    sc.register(
        "key",
        "default-value",
        new Option.Meta(10, false, false, SHORT_DESC, LONG_DESC),
        new network.crypta.support.api.StringCallback() {
          private String v = "default-value";

          @Override
          public String get() {
            return v;
          }

          @Override
          public void set(String value) {
            v = value;
          }
        });

    // Assert (before finishedInit: initial value must be applied)
    assertEquals("value-from-file", sc.getString("key"));

    // Finish init (should not throw) — also ensures internal SFS is cleared
    cfgObj.finishedInit();
    assertNull(cfgObj.getSimpleFieldSet());
  }

  @Test
  @DisplayName("store_beforeFinishedInit_defersWrite_untilFinishedInit")
  void store_beforeFinishedInit_defersWrite_untilFinishedInit(@TempDir File tmp) throws Exception {
    // Arrange
    File cfg = new File(tmp, "deferred.ini");
    FilePersistentConfig cfgObj =
        FilePersistentConfig.constructFilePersistentConfig(cfg, HEADER_UNIT);

    SubConfig sc = cfgObj.createSubConfig("group");
    sc.register(
        "name",
        "default",
        new Option.Meta(1, false, false, SHORT_DESC, LONG_DESC),
        new network.crypta.support.api.StringCallback() {
          private String v = "default";

          @Override
          public String get() {
            return v;
          }

          @Override
          public void set(String value) {
            v = value;
          }
        });
    sc.set("name", "custom");

    // Act: call store() before finishedInit — should defer, no files created
    cfgObj.store();

    File tmpFile = new File(cfg.getPath() + ".tmp");
    assertFalse(cfg.exists(), "config file must not be created before finishedInit");
    assertFalse(tmpFile.exists(), "temp file must not exist before finishedInit");

    // Act: now finish init — should trigger a writing
    cfgObj.finishedInit();

    // Assert: config written with header and our value
    assertTrue(cfg.exists(), "config file should be created after finishedInit triggers write");

    SimpleFieldSet readBack = SimpleFieldSet.readFrom(cfg, true, true);
    assertNotNull(readBack.getHeader(), "header array should be present");
    assertEquals(1, readBack.getHeader().length);
    assertEquals(HEADER_UNIT, readBack.getHeader()[0]);
    assertEquals("custom", readBack.get("group.name"));
  }

  @Test
  @DisplayName("store_afterFinishedInit_writesImmediately")
  void store_afterFinishedInit_writesImmediately(@TempDir File tmp) throws Exception {
    // Arrange
    File cfg = new File(tmp, "immediate.ini");
    FilePersistentConfig cfgObj =
        FilePersistentConfig.constructFilePersistentConfig(cfg, "Another Header");

    SubConfig sc = cfgObj.createSubConfig("sec");
    sc.register(
        "opt",
        "def",
        new Option.Meta(1, false, false, SHORT_DESC, LONG_DESC),
        new network.crypta.support.api.StringCallback() {
          private String v = "def";

          @Override
          public String get() {
            return v;
          }

          @Override
          public void set(String value) {
            v = value;
          }
        });
    sc.set("opt", "val");

    // Finish init first so store() writes immediately
    cfgObj.finishedInit();
    cfgObj.store();

    // Assert
    assertTrue(cfg.exists());
    SimpleFieldSet readBack = SimpleFieldSet.readFrom(cfg, true, true);
    assertEquals("val", readBack.get("sec.opt"));
    assertEquals("Another Header", readBack.getHeader()[0]);
  }

  @Test
  @DisplayName("construct_whenTempFileEmpty_throwsIOException")
  void construct_whenTempFileEmpty_throwsIOException(@TempDir File tmp) throws Exception {
    // Arrange: create only the temp file (empty)
    File cfg = new File(tmp, "broken.ini");
    File tmpFile = new File(cfg.getPath() + ".tmp");
    assertTrue(tmpFile.createNewFile());

    // Act + Assert
    assertThrows(
        IOException.class, () -> FilePersistentConfig.constructFilePersistentConfig(cfg, "hdr"));
  }

  @Test
  @DisplayName("construct_prefersTempFile_whenMainMissing")
  void construct_prefersTempFile_whenMainMissing(@TempDir File tmp) throws Exception {
    // Arrange: only temp has valid content
    File cfg = new File(tmp, "fromtmp.ini");
    File tmpFile = new File(cfg.getPath() + ".tmp");
    writeSfs(tmpFile, "# H\n", "p.k=v\n", "End\n");

    // Act
    FilePersistentConfig cfgObj = FilePersistentConfig.constructFilePersistentConfig(cfg, "hdr");
    SubConfig sc = cfgObj.createSubConfig("p");
    sc.register(
        "k",
        "d",
        new Option.Meta(0, false, false, "s", "l"),
        new network.crypta.support.api.StringCallback() {
          private String v = "d";

          @Override
          public String get() {
            return v;
          }

          @Override
          public void set(String value) {
            v = value;
          }
        });

    // Assert: initial value taken from the temp file
    assertEquals("v", sc.getString("k"));
  }

  @Test
  @DisplayName("innerStore_whenNotFinished_throwsIllegalStateException")
  void innerStore_whenNotFinished_throwsIllegalStateException(@TempDir File tmp) {
    // Arrange: use a test subclass to expose innerStore()
    File cfg = new File(tmp, "guard.ini");
    File tmpFile = new File(cfg.getPath() + ".tmp");
    TestableConfig subject = new TestableConfig(null, cfg, tmpFile, "hdr");

    // Act + Assert
    assertThrows(IllegalStateException.class, subject::callInnerStore);
  }

  // --- helpers ---

  private static void writeSfs(File target, String... lines) throws IOException {
    try (FileOutputStream fos = new FileOutputStream(target)) {
      for (String l : lines) {
        fos.write(l.getBytes(StandardCharsets.UTF_8));
      }
    }
  }

  /** Test subclass exposing {@code innerStore()} for precondition testing. */
  static final class TestableConfig extends FilePersistentConfig {
    TestableConfig(SimpleFieldSet fs, File fnam, File tmp, String header) {
      super(fs, fnam, tmp, header);
    }

    void callInnerStore() throws IOException {
      innerStore();
    }
  }
}
