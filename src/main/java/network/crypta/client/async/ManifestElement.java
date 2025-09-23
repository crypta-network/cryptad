package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ResumeFailedException;

/** Kept for migration only */
@Deprecated
public class ManifestElement implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /** Filename */
  private String name;

  /** Full name in the container it is inserted as part of. */
  private String fullName;

  /** Data to be inserted. Can be null, if the insert has completed. */
  private Bucket data;

  /** MIME type override. null => use default for filename */
  private String mimeOverride;

  /** Original size of the bucket. Can be set explicitly even if data == null. */
  private long dataSize;

  /** Redirect target */
  private FreenetURI targetURI;

  public network.crypta.support.api.ManifestElement migrate(BucketFactory bf, ClientContext context)
      throws ResumeFailedException, IOException {
    if (data == null) {
      if (targetURI == null)
        throw new ResumeFailedException("Must have either a URI or a redirect");
      return new network.crypta.support.api.ManifestElement(
          name, fullName, mimeOverride, targetURI);
    } else {
      if (data.size() != dataSize)
        throw new ResumeFailedException(
            "Bucket in site insert changed size from " + dataSize + " to " + data.size());
      data.onResume(context);
      RandomAccessBucket convertedData = BucketTools.toRandomAccessBucket(data, bf);
      return new network.crypta.support.api.ManifestElement(
          name, fullName, convertedData, mimeOverride, dataSize);
    }
  }
}
