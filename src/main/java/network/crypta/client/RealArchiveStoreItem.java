package network.crypta.client;

import network.crypta.keys.FreenetURI;
import network.crypta.support.LogThresholdCallback;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.MultiReaderBucket;

class RealArchiveStoreItem extends ArchiveStoreItem {

  private final MultiReaderBucket mb;
  private final Bucket bucket;
  private final long spaceUsed;

  private static volatile boolean logMINOR;

  static {
    Logger.registerLogThresholdCallback(
        new LogThresholdCallback() {
          @Override
          public void shouldUpdate() {
            logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
          }
        });
  }

  /**
   * Create an ArchiveStoreElement from a TempStoreElement.
   *
   * @param key2 The key of the archive the file came from.
   * @param realName The name of the file in that archive.
   * @param temp The TempStoreElement currently storing the data.
   * @param manager The parent ArchiveManager within which this item is stored.
   */
  RealArchiveStoreItem(ArchiveStoreContext ctx, FreenetURI key2, String realName, Bucket bucket) {
    super(new ArchiveKey(key2, realName), ctx);
    if (bucket == null) throw new NullPointerException();
    mb = new MultiReaderBucket(bucket);
    this.bucket = mb.getReaderBucket();
    if (this.bucket == null) throw new NullPointerException();
    this.bucket.setReadOnly();
    spaceUsed = this.bucket.size();
  }

  /** Return the data, as a Bucket, in plaintext. */
  Bucket dataAsBucket() {
    return bucket;
  }

  /** Return the length of the data. */
  long dataSize() {
    return bucket.size();
  }

  /** Return the estimated space used by the data. */
  @Override
  long spaceUsed() {
    return spaceUsed;
  }

  @Override
  void innerClose() {
    if (logMINOR) Logger.minor(this, "innerClose(): " + this + " : " + bucket);
    if (bucket == null) {
      // This still happens. It is clearly impossible as we check in the constructor and throw if it
      // is null.
      // Nonetheless there is little we can do here ...
      Logger.error(this, "IMPOSSIBLE: BUCKET IS NULL!", new Exception("error"));
      return;
    }
    bucket.free();
  }

  @Override
  Bucket getDataOrThrow() throws ArchiveFailureException {
    return dataAsBucket();
  }

  @Override
  Bucket getReaderBucket() throws ArchiveFailureException {
    return mb.getReaderBucket();
  }
}
