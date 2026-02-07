package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings("java:S100")
class DiskDirPutFileTest {

  private static final String IDENTIFIER = "req-42";
  private static final boolean GLOBAL = true;

  @TempDir Path tempDir;

  @Test
  void create_whenFilenameMissing_expectMessageInvalidException() {
    SimpleFieldSet subset = new SimpleFieldSet(true);

    MessageInvalidException ex =
        assertThrows(
            MessageInvalidException.class,
            () -> DiskDirPutFile.create("index.html", null, subset, IDENTIFIER, GLOBAL));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, ex.protocolCode);
    assertEquals(IDENTIFIER, ex.ident);
    assertTrue(ex.global);
    assertTrue(ex.getMessage().contains("Missing field: Filename"));
  }

  @Test
  void create_whenOverrideProvided_expectMimeTypeMatchesOverride() throws Exception {
    File source = createTempFile("override.txt");
    SimpleFieldSet subset = subsetWithFilename(source);
    String overrideMime = "application/json";

    DiskDirPutFile file =
        DiskDirPutFile.create("folder/data.txt", overrideMime, subset, IDENTIFIER, GLOBAL);

    assertEquals(overrideMime, file.getMIMEType());
    assertEquals(source.getAbsolutePath(), file.getFile().getAbsolutePath());
  }

  @Test
  void create_whenOverrideMissing_expectMimeDerivedFromName() throws Exception {
    String name = "docs/index.html";
    File source = createTempFile("nameDerived.bin");
    SimpleFieldSet subset = subsetWithFilename(source);

    DiskDirPutFile file = DiskDirPutFile.create(name, null, subset, IDENTIFIER, GLOBAL);

    assertEquals(DefaultMIMETypes.guessMIMEType(name, true), file.getMIMEType());
  }

  @Test
  void guessMIME_whenNameHasNoExtension_expectGuessFromFileName() throws IOException {
    File pngFile = createTempFile("photo.png");

    String mime = DiskDirPutFile.guessMIME("folder/readme", pngFile);

    assertEquals(DefaultMIMETypes.guessMIMEType(pngFile.getName(), false), mime);
  }

  @Test
  void getData_whenInvoked_returnsFileBucketBoundToResolvedFile() throws IOException {
    File file = createTempFile("bucket.dat");
    DiskDirPutFile diskDirPutFile =
        new DiskDirPutFile("file.bin", "application/octet-stream", file);

    RandomAccessBucket data = diskDirPutFile.getData();

    assertInstanceOf(FileBucket.class, data);
    FileBucket bucket = (FileBucket) data;
    assertEquals(file.getAbsolutePath(), bucket.getFile().getAbsolutePath());
  }

  private File createTempFile(String name) throws IOException {
    Path path = tempDir.resolve(name);
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.deleteIfExists(path);
    return Files.createFile(path).toFile();
  }

  private static SimpleFieldSet subsetWithFilename(File file) {
    SimpleFieldSet subset = new SimpleFieldSet(true);
    subset.putSingle("Filename", file.getAbsolutePath());
    return subset;
  }
}
