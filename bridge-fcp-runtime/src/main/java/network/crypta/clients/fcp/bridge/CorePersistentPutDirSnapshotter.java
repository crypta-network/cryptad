package network.crypta.clients.fcp.bridge;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import network.crypta.client.Metadata;
import network.crypta.clients.fcp.ClientPutBase;
import network.crypta.clients.fcp.PersistentPutDirEntrySnapshot;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.DelayedFreeBucket;
import network.crypta.support.io.DelayedFreeRandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PaddedEphemerallyEncryptedBucket;
import network.crypta.support.io.PersistentTempFileBucket;
import network.crypta.support.io.TempBucketFactory;

/**
 * Converts runtime-owned manifest trees into adapter-owned {@link PersistentPutDirEntrySnapshot}
 * values.
 *
 * <p>The bridge layer still owns the details of manifest flattening, bucket unwrapping, and
 * upload-source classification for persistent directory inserts. Those details depend on runtime
 * types such as delayed-free wrappers, temporary bucket implementations, and the legacy metadata
 * helper used for nested manifest maps. This helper concentrates that knowledge in one bridge-only
 * place. The adapter receives only detached entry snapshots and can therefore serialize {@code
 * PersistentPutDir} replies without importing the runtime classes that describe live bucket state.
 *
 * <p>The same conversion path is used for two situations: normal live executions and replay-only
 * fallback when a durable request has restored its stored manifest tree but not its live execution
 * wrapper. Keeping both paths on the same helper preserves the historical wire behavior for disk,
 * direct, redirect, delayed-free, and already-freed entries. Unknown bucket types still fail
 * deterministically, so callers do not silently misreport the upload source.
 *
 * <ul>
 *   <li>Flattens nested manifest maps into the {@code Files.N} ordering expected by FCP.
 *   <li>Classifies disk, direct, redirect, and already-freed entries from the runtime bucket state.
 *   <li>Preserves the same replay behavior for live and compatibility fallback paths.
 * </ul>
 */
final class CorePersistentPutDirSnapshotter {

  /** Utility class; callers use the static snapshot helpers only. */
  private CorePersistentPutDirSnapshotter() {}

  /**
   * Snapshots a manifest tree into detached persistent-put-dir entry descriptors.
   *
   * <p>The returned list is ordered by the iteration order of the nested manifest maps, matching
   * the legacy-flattening behavior expected by the FCP serializer. A {@code null} manifest yields
   * an empty list so replay callers can keep generating replies even when no stored tree is
   * available.
   *
   * @param manifestElements nested manifest tree restored from the request or live execution spec
   * @return detached entry snapshots ready for {@code PersistentPutDir} serialization
   */
  static List<PersistentPutDirEntrySnapshot> snapshot(Map<String, Object> manifestElements) {
    List<PersistentPutDirEntrySnapshot> entries = new ArrayList<>();
    if (manifestElements == null) {
      return entries;
    }
    snapshot(manifestElements, entries, "");
    return entries;
  }

  /**
   * Recursively walks one manifest directory node and appends flattened entry snapshots.
   *
   * @param manifestElements current manifest directory node
   * @param entries destination list receiving flattened entry snapshots
   * @param prefix path prefix accumulated from parent directories
   */
  private static void snapshot(
      Map<String, Object> manifestElements,
      List<PersistentPutDirEntrySnapshot> entries,
      String prefix) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      String fullName = prefix.isEmpty() ? name : prefix + '/' + name;
      Object value = entry.getValue();
      if (value instanceof Map) {
        snapshot(Metadata.forceMap(value), entries, fullName);
      } else if (value instanceof ManifestElement manifestElement) {
        entries.add(toPersistentPutDirEntrySnapshot(fullName, manifestElement));
      } else {
        throw new IllegalStateException(String.valueOf(value));
      }
    }
  }

  /**
   * Converts one manifest leaf into the detached snapshot form used by the adapter layer.
   *
   * <p>Redirect entries are emitted without inspecting the bucket state. File-backed entries are
   * classified from their runtime bucket implementation after delayed-free wrappers are removed.
   * When the bucket has already been freed, the helper preserves the entry name, size, and MIME
   * override but leaves the upload source unset so the serializer can omit it.
   *
   * @param fullName flattened path for the manifest entry relative to the directory root
   * @param element live manifest element carrying runtime bucket and metadata state
   * @return detached snapshot that captures only the fields needed by {@code PersistentPutDir}
   */
  private static PersistentPutDirEntrySnapshot toPersistentPutDirEntrySnapshot(
      String fullName, ManifestElement element) {
    FreenetURI targetUri = element.getTargetURI();
    if (targetUri != null) {
      return new PersistentPutDirEntrySnapshot(
          fullName,
          ClientPutBase.UploadFrom.REDIRECT,
          element.getSize(),
          null,
          element.getMimeTypeOverride(),
          targetUri);
    }
    Bucket data = unwrapPersistentPutDirBucket(element.getData());
    if (data == null) {
      return new PersistentPutDirEntrySnapshot(
          fullName, null, element.getSize(), null, element.getMimeTypeOverride(), null);
    }
    if (data instanceof FileBucket bucket) {
      return new PersistentPutDirEntrySnapshot(
          fullName,
          ClientPutBase.UploadFrom.DISK,
          element.getSize(),
          bucket.getFile().getPath(),
          element.getMimeTypeOverride(),
          null);
    }
    if (isPersistentPutDirDirectBucket(data)) {
      return new PersistentPutDirEntrySnapshot(
          fullName,
          ClientPutBase.UploadFrom.DIRECT,
          element.getSize(),
          null,
          element.getMimeTypeOverride(),
          null);
    }
    throw new IllegalStateException("Don't know what to do with bucket: " + data);
  }

  /**
   * Reports whether a runtime bucket should be exposed as {@code UploadFrom=direct}.
   *
   * @param data runtime bucket implementation for one manifest entry
   * @return {@code true} when the bucket represents a direct-style upload source
   */
  private static boolean isPersistentPutDirDirectBucket(Bucket data) {
    return data instanceof PaddedEphemerallyEncryptedBucket
        || data instanceof NullBucket
        || data instanceof PersistentTempFileBucket
        || data instanceof TempBucketFactory.TempBucket
        || data instanceof EncryptedRandomAccessBucket;
  }

  /**
   * Removes delayed-free wrappers so disk/direct classification sees the underlying bucket type.
   *
   * @param data runtime bucket possibly wrapped in delayed-free adapters
   * @return underlying bucket used for upload-source classification, or the original bucket when no
   *     wrapper is present
   */
  private static Bucket unwrapPersistentPutDirBucket(Bucket data) {
    if (data instanceof DelayedFreeBucket bucket) {
      return bucket.getUnderlying();
    }
    if (data instanceof DelayedFreeRandomAccessBucket bucket) {
      return bucket.getUnderlying();
    }
    return data;
  }
}
