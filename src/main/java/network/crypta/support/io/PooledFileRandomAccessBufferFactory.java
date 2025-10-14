package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;

/** Creates temporary RAFs using a FilenameGenerator. */
public class PooledFileRandomAccessBufferFactory implements LockableRandomAccessBufferFactory {

  private final FilenameGenerator fg;

  public PooledFileRandomAccessBufferFactory(FilenameGenerator filenameGenerator) {
    fg = filenameGenerator;
  }

  // No encryption toggling in this factory; encryption is handled by higher-level factories.

  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    long id = fg.makeRandomFilename();
    File file = fg.getFilename(id);
    try {
      return new PooledFileRandomAccessBuffer(file, false, size, id, true);
    } catch (IOException | RuntimeException e) {
      try {
        Files.deleteIfExists(file.toPath());
      } catch (IOException ignored) {
        // Best-effort cleanup; original behavior ignored failures as well.
      }
      throw e;
    }
  }

  @Override
  public LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    long id = fg.makeRandomFilename();
    File file = fg.getFilename(id);
    try {
      return new PooledFileRandomAccessBuffer(
          file, initialContents, offset, size, id, true, readOnly);
    } catch (IOException | RuntimeException e) {
      // Constructor may throw IOException; writing initial contents may also throw unchecked
      // exceptions (e.g., IndexOutOfBoundsException, NullPointerException). Clean up the temp file
      // then rethrow to preserve original behavior.
      try {
        Files.deleteIfExists(file.toPath());
      } catch (IOException ignored) {
        // Best-effort cleanup; original behavior ignored failures as well.
      }
      throw e;
    }
  }
}
