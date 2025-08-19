package network.crypta.client;

import java.io.Serial;
import java.io.Serializable;
import java.util.HashSet;
import network.crypta.keys.FreenetURI;

/**
 * @author amphibian (Matthew Toseland)
 *     <p>Object passed down a full fetch, including all the recursion. Used, at present, for
 *     detecting archive fetch loops, hence the name.
 *     <p>WARNING: Changing non-transient members on classes that are Serializable can result in
 *     restarting downloads or losing uploads.
 */
public class ArchiveContext implements Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private HashSet<FreenetURI> soFar;
  final int maxArchiveLevels;
  final long maxArchiveSize;

  public ArchiveContext(long maxArchiveSize, int max) {
    this.maxArchiveLevels = max;
    this.maxArchiveSize = maxArchiveSize;
  }

  protected ArchiveContext() {
    // For serialization.
    maxArchiveLevels = 0;
    maxArchiveSize = 0;
  }

  /**
   * Check for a loop.
   *
   * <p>The URI provided is expected to be a reasonably unique identifier for the archive.
   */
  public synchronized void doLoopDetection(FreenetURI key) throws ArchiveFailureException {
    if (soFar == null) {
      soFar = new HashSet<FreenetURI>();
    }
    if (soFar.size() > maxArchiveLevels)
      throw new ArchiveFailureException(ArchiveFailureException.TOO_MANY_LEVELS);
    FreenetURI uri = key;
    if (!soFar.add(uri)) {
      throw new ArchiveFailureException(ArchiveFailureException.ARCHIVE_LOOP_DETECTED);
    }
  }

  public synchronized void clear() {
    soFar = null;
  }
}
