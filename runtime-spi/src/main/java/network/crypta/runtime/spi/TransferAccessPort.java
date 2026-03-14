package network.crypta.runtime.spi;

import java.io.File;

/** Exposes file-transfer policy checks and directories using only JDK file types. */
public interface TransferAccessPort {
  boolean allowUploadFrom(File file);

  boolean allowDownloadTo(File file);

  File downloadsDir();

  File persistentTempDir();

  File[] allowedUploadDirs();

  File[] allowedDownloadDirs();
}
