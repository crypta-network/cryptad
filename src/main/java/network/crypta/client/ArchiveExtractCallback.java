package network.crypta.client;

import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;

/** Called when we have extracted an archive, and a specified file either is or isn't in it. */
public interface ArchiveExtractCallback extends Serializable {

  /**
   * Got the data. Note that the bucket will be persistent if the caller asked for an off-thread
   * extraction.
   */
  void gotBucket(Bucket data, ClientContext context);

  /** Not in the archive */
  void notInArchive(ClientContext context);

  /** Failed: restart */
  void onFailed(ArchiveRestartException e, ClientContext context);

  /** Failed for some other reason */
  void onFailed(ArchiveFailureException e, ClientContext context);
}
