package network.crypta.support;

import java.util.Map;
import network.crypta.client.Metadata;
import network.crypta.support.api.ManifestElement;

/**
 * Estimates the size of an archive-style container built from a manifest tree.
 *
 * <p>This utility computes deterministic size estimates for both a "limited" view (respecting
 * maximum item/container thresholds) and an "unlimited" view (as if all items could be embedded) of
 * a directory tree used to assemble a container. The calculations are tuned for TAR-like containers
 * and preserve historical heuristics used by the builders.
 *
 * <p>Thread-safety: All methods are stateless and thread-safe.
 *
 * @author saces
 */
public final class ContainerSizeEstimator {

  // Default archive type constant removed: only TAR sizing is currently implemented.

  // TAR format constants. Behavior intentionally matches the historical implementation.
  private static final int TAR_BLOCK_SIZE = 512;
  // Per-file sidecar metadata overhead used by container builders: base plus filename length.
  // Represents the on-archive ".metadata-*" entry for each file.
  private static final int METADATA_OVERHEAD_BASE = 128;

  /**
   * Aggregated size estimates for a manifest subtree.
   *
   * <p>Values are in bytes and split into two axes:
   *
   * <ul>
   *   <li>files — sizes for items at the current level (non-recursive)
   *   <li>subTrees — sizes for nested directories (recursive), including each directory entry
   * </ul>
   *
   * <p>Each axis has a "NoLimit" counterpart. The unlimited view assumes all files are embedded
   * directly (no redirects). Historically, the unlimited estimate includes an extra count of the
   * sidecar metadata per file that fits, preserving builder heuristics.
   */
  public static final class ContainerSize {

    private long sizeFiles;
    private long sizeFilesNoLimit;
    private long sizeSubTrees;
    private long sizeSubTreesNoLimit;

    private ContainerSize() {
      sizeFiles = 0;
      sizeFilesNoLimit = 0;
      sizeSubTrees = 0;
      sizeSubTreesNoLimit = 0;
    }

    /**
     * Total limited size in bytes for files at this level plus all subtrees.
     *
     * @return cumulative limited size in bytes
     */
    public long getSizeTotal() {
      return sizeFiles + sizeSubTrees;
    }

    /**
     * Total unlimited size in bytes for files at this level plus all subtrees.
     *
     * <p>The unlimited view assumes every file can be embedded and applies the historical sidecar
     * metadata accounting described in the class documentation.
     *
     * @return cumulative unlimited size in bytes
     */
    public long getSizeTotalNoLimit() {
      return sizeFilesNoLimit + sizeSubTreesNoLimit;
    }

    /**
     * Limited size in bytes for just the files at the current level.
     *
     * @return size in bytes
     */
    public long getSizeFiles() {
      return sizeFiles;
    }

    /**
     * Unlimited size in bytes for just the files at the current level.
     *
     * @return size in bytes
     */
    public long getSizeFilesNoLimit() {
      return sizeFilesNoLimit;
    }

    /**
     * Limited size in bytes for all nested subtrees, including each directory entry.
     *
     * @return size in bytes
     */
    public long getSizeSubTrees() {
      return sizeSubTrees;
    }

    /**
     * Unlimited size in bytes for all nested subtrees, including each directory entry.
     *
     * @return size in bytes
     */
    public long getSizeSubTreesNoLimit() {
      return sizeSubTreesNoLimit;
    }
  }

  private ContainerSizeEstimator() {}

  /**
   * Estimates sizes for a manifest subtree.
   *
   * <p>The {@code metadata} map models directory contents. Values are either:
   *
   * <ul>
   *   <li>{@link ManifestElement} — a file or redirect; or
   *   <li>{@code Map<String, Object>} — a nested directory (recursed into up to {@code maxDeep}).
   * </ul>
   *
   * <p>Files with size greater than {@code maxItemSize} are treated as redirects in the limited
   * view. The unlimited view assumes all files fit. Subtrees include their own directory header.
   * For non-{@code HashMap} directories, the method normalizes via {@link
   * Metadata#forceMap(Object)}.
   *
   * <p>Iteration stops early on an axis when the rolling limited size would exceed {@code
   * maxContainerSize}.
   *
   * @param metadata directory map; keys are names, values are {@link ManifestElement} or directory
   *     {@code Map}
   * @param maxItemSize maximum number of bytes for a file to be embedded before it is considered a
   *     redirect in the limited view
   * @param maxContainerSize budget in bytes for the current container; used to short-circuit
   *     iteration when exceeded
   * @param maxDeep maximum recursion depth for subdirectories; {@code 0} disables recursion
   * @return aggregated size estimates for the subtree rooted at {@code metadata}
   * @throws NullPointerException if {@code metadata} is {@code null}
   */
  public static ContainerSize getSubTreeSize(
      Map<String, Object> metadata, long maxItemSize, long maxContainerSize, int maxDeep) {
    ContainerSize result = new ContainerSize();
    getSubTreeSize(metadata, result, maxItemSize, maxContainerSize, maxDeep);
    return result;
  }

  private static void getSubTreeSize(
      Map<String, Object> metadata,
      ContainerSize result,
      long maxItemSize,
      long maxContainerSize,
      int maxDeep) {
    // Files at the current level.
    for (Map.Entry<String, Object> entry : metadata.entrySet()) {
      Object value = entry.getValue();
      if (value instanceof ManifestElement me
          && processFile(me, result, maxItemSize, maxContainerSize)) {
        break;
      }
    }

    // Subdirectories (recurse when allowed by maxDeep).
    if (maxDeep > 0) {
      for (Map.Entry<String, Object> entry : metadata.entrySet()) {
        if (processSubDirectory(entry.getValue(), result, maxItemSize, maxContainerSize, maxDeep)) {
          break;
        }
      }
    }
  }

  private static boolean processFile(
      ManifestElement me, ContainerSize result, long maxItemSize, long maxContainerSize) {
    long itemSize = me.getSize();
    if (itemSize > -1) {
      // Unlimited view: full file + one sidecar metadata entry.
      result.sizeFilesNoLimit += getContainerItemSize(itemSize);
      result.sizeFilesNoLimit += METADATA_OVERHEAD_BASE + me.getName().length();

      if (itemSize > maxItemSize) {
        // Limited view: treat as redirect (one directory entry only).
        result.sizeFiles += TAR_BLOCK_SIZE;
      } else {
        // Limited view: include the full file. Historical behavior counts the sidecar metadata
        // twice in the unlimited estimate for files that fit.
        result.sizeFiles += getContainerItemSize(itemSize);
        result.sizeFilesNoLimit += METADATA_OVERHEAD_BASE + me.getName().length();
      }
      return result.sizeFiles > maxContainerSize;
    }
    // Redirect entry (no file payload stored in the container).
    result.sizeFiles += TAR_BLOCK_SIZE;
    result.sizeFilesNoLimit += TAR_BLOCK_SIZE;
    return result.sizeFiles > maxContainerSize;
  }

  private static boolean processSubDirectory(
      Object value, ContainerSize result, long maxItemSize, long maxContainerSize, int maxDeep) {
    if (!(value instanceof Map)) {
      return false;
    }
    result.sizeSubTrees += TAR_BLOCK_SIZE;
    Map<String, Object> hm = Metadata.forceMap(value);
    ContainerSize tempResult = new ContainerSize();
    getSubTreeSize(
        hm, tempResult, maxItemSize, (maxContainerSize - result.sizeSubTrees), maxDeep - 1);
    result.sizeSubTrees += tempResult.getSizeTotal();
    result.sizeSubTreesNoLimit += tempResult.getSizeTotalNoLimit();
    return result.sizeSubTrees > maxContainerSize;
  }

  /**
   * Estimates container space for a single file using the currently supported archive format.
   *
   * <p>Result: {@code 512 + roundUp(size, 512)} — a TAR header block plus data padded to the next
   * 512-byte boundary. Negative {@code size} values produce {@code 512}.
   *
   * @param size file length in bytes; negative implies header only (no data)
   * @return estimated space in bytes for this item in the container
   */
  public static long getContainerItemSize(long size) {
    return tarItemSize(size);
  }

  /**
   * TAR item size in bytes: one header block plus data rounded up to the 512-byte block size.
   *
   * @param size file length in bytes; negative yields the header size ({@code 512})
   * @return {@code 512 + roundUp(size, 512)}
   */
  public static long tarItemSize(long size) {
    return TAR_BLOCK_SIZE + (((size + (TAR_BLOCK_SIZE - 1)) / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE);
  }
}
