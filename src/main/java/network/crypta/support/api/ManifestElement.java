package network.crypta.support.api;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.OptionalDataException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.io.ResumeFailedException;

/**
 * A single entry in a directory manifest.
 *
 * <p>An element describes either:
 *
 * <ul>
 *   <li>a file payload backed by a {@link RandomAccessBucket}, or
 *   <li>a redirect to a {@link FreenetURI}.
 * </ul>
 *
 * <p>Instances are mostly immutable once constructed. The {@code data} reference may become {@code
 * null} after the payload is consumed and freed by higher layers.
 *
 * <p>Serialization: this class participates in Java serialization for checkpointing. The bucket
 * field is {@code transient} at runtime but is included in {@link #serialPersistentFields} so
 * {@link ObjectInputStream#defaultReadObject()} can restore it from legacy streams. The writer
 * stores the bucket inside the default field block when it implements {@link java.io.Serializable};
 * if it does not, a {@link java.io.NotSerializableException} is thrown and the checkpoint is not
 * written. The reader also tolerates a trailing object carrying the bucket for compatibility with
 * intermediary streams.
 */
public class ManifestElement implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  // Include 'data' in the persistent field list so defaultReadObject() can restore it from streams
  // that carry it in the default field block. The writer below stores the actual bucket there when
  // it implements java.io.Serializable; this keeps older readers working. No trailing object is
  // required for the common case; readObject(ObjectInputStream) tolerates a trailing object for
  // compatibility with streams that may include it.
  @Serial
  @SuppressWarnings("UnusedVariable")
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField("name", String.class),
    new ObjectStreamField("fullName", String.class),
    new ObjectStreamField("data", RandomAccessBucket.class),
    new ObjectStreamField("mimeOverride", String.class),
    new ObjectStreamField("dataSize", long.class),
    new ObjectStreamField("targetURI", FreenetURI.class)
  };

  /** Name of the element within the manifest (file name or relative path). */
  final String name;

  /**
   * Full path used within the container. When different from {@link #name}, it reflects a display
   * or canonicalized form used by the caller.
   */
  public final String fullName;

  /**
   * Data to be inserted for file entries.
   *
   * <p>May be {@code null} for redirects and after a file entry has completed and released its
   * storage.
   *
   * <p>Serialization semantics: {@link RandomAccessBucket} implementations are not required to be
   * {@link java.io.Serializable}. We therefore keep this field {@code transient} and serialize it
   * explicitly via {@code writeObject}/{@code readObject}. If {@code data} is present but not
   * {@link java.io.Serializable}, Java serialization fails with {@link
   * java.io.NotSerializableException}. Failing the checkpoint is intentional and avoids persisting
   * a corrupted manifest entry that would lose its data on resume.
   */
  transient RandomAccessBucket data;

  /** Optional MIME type override. When {@code null}, a type is guessed from {@link #name}. */
  public final String mimeOverride;

  /**
   * Original payload size in bytes.
   *
   * <p>For redirects the value is {@code -1}. For files, this may be set even when {@link #data} is
   * {@code null} (e.g., after freeing the bucket).
   */
  final long dataSize;

  /** Redirect target for redirect entries; {@code null} for file entries. */
  public final FreenetURI targetURI;

  /**
   * Creates a file entry.
   *
   * @param name2 file name as it appears in the manifest
   * @param fullName2 full path within the container
   * @param data2 payload bucket; expected to be non-{@code null}
   * @param mimeOverride2 optional MIME type override; when {@code null}, a type is guessed
   * @param size original payload length in bytes; expected to be non-negative
   */
  public ManifestElement(
      String name2, String fullName2, RandomAccessBucket data2, String mimeOverride2, long size) {
    this.name = name2;
    this.fullName = fullName2;
    this.data = data2;
    assert (data != null);
    this.mimeOverride = mimeOverride2;
    this.dataSize = size;
    this.targetURI = null;
  }

  /**
   * Creates a file entry using the same value for the manifest name and full path.
   *
   * @param name2 file name as it appears in the manifest
   * @param data2 payload bucket; expected to be non-{@code null}
   * @param mimeOverride2 optional MIME type override; when {@code null}, a type is guessed
   * @param size2 original payload length in bytes; expected to be non-negative
   */
  public ManifestElement(String name2, RandomAccessBucket data2, String mimeOverride2, long size2) {
    this.name = name2;
    this.fullName = name2;
    this.data = data2;
    this.mimeOverride = mimeOverride2;
    this.dataSize = size2;
    this.targetURI = null;
  }

  /**
   * Copy constructor that returns a new element with a different {@code name}.
   *
   * <p>All other attributes are copied from {@code me}.
   *
   * @param me source element to copy
   * @param newName replacement name within the manifest
   */
  public ManifestElement(ManifestElement me, String newName) {
    this.name = newName;
    this.fullName = me.fullName;
    this.data = me.data;
    this.mimeOverride = me.mimeOverride;
    this.dataSize = me.dataSize;
    this.targetURI = me.targetURI;
  }

  /**
   * Copy constructor that returns a new element with different {@code name} and {@code fullName}.
   *
   * <p>All other attributes are copied from {@code me}.
   *
   * @param me source element to copy
   * @param newName replacement name within the manifest
   * @param newFullName replacement full path within the container
   */
  public ManifestElement(ManifestElement me, String newName, String newFullName) {
    this.name = newName;
    this.fullName = newFullName;
    assert (fullName != null);
    this.data = me.data;
    this.mimeOverride = me.mimeOverride;
    this.dataSize = me.dataSize;
    this.targetURI = me.targetURI;
  }

  /**
   * Creates a redirect entry using the same value for the manifest name and full path.
   *
   * @param name2 entry name within the manifest
   * @param targetURI2 redirect target; must be non-{@code null}
   * @param mimeOverride2 optional MIME type override for the redirect
   */
  public ManifestElement(String name2, FreenetURI targetURI2, String mimeOverride2) {
    this.name = name2;
    this.fullName = name2;
    this.data = null;
    this.mimeOverride = mimeOverride2;
    this.dataSize = -1;
    this.targetURI = targetURI2;
    assert (targetURI != null);
  }

  /**
   * Creates a redirect entry with distinct name and full path values.
   *
   * @param name2 entry name within the manifest
   * @param fullName2 full path within the container
   * @param mimeOverride2 optional MIME type override for the redirect
   * @param targetURI2 redirect target; must be non-{@code null}
   */
  public ManifestElement(
      String name2, String fullName2, String mimeOverride2, FreenetURI targetURI2) {
    this.name = name2;
    this.fullName = fullName2;
    this.mimeOverride = mimeOverride2;
    this.targetURI = targetURI2;
    this.data = null;
    this.dataSize = -1;
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o instanceof ManifestElement element) {
      return element.name.equals(name);
    }
    return false;
  }

  /**
   * Releases the payload bucket if present.
   *
   * <p>Calls {@link RandomAccessBucket#free()}. Safe to invoke multiple times; subsequent calls
   * have no effect when the bucket is already {@code null} or freed by the implementation.
   */
  public void freeData() {
    if (data != null) {
      data.free();
    }
  }

  /**
   * Returns the entry name as it appears in the manifest.
   *
   * @return file name or relative path; never {@code null}
   */
  public String getName() {
    return name;
  }

  /**
   * Returns the MIME type override.
   *
   * @return explicit type when provided; otherwise {@code null}
   */
  public String getMimeTypeOverride() {
    return mimeOverride;
  }

  /**
   * Returns a MIME type suitable for client metadata.
   *
   * <p>When {@link #mimeOverride} is non-{@code null}, it is returned as-is. Otherwise, a type is
   * guessed from {@link #name} using {@link DefaultMIMETypes#guessMIMEType(String, boolean)}.
   *
   * @return resolved MIME type, or {@code null} when it cannot be determined
   */
  public String getMimeType() {
    String mimeType = mimeOverride;
    if ((mimeOverride == null) && (name != null))
      mimeType = DefaultMIMETypes.guessMIMEType(name, true);
    return mimeType;
  }

  /**
   * Returns the payload bucket for file entries.
   *
   * @return the bucket, or {@code null} for redirects or after freeing
   */
  public RandomAccessBucket getData() {
    return data;
  }

  /**
   * Returns the original payload length.
   *
   * @return size in bytes, or {@code -1} for redirects
   */
  public long getSize() {
    return dataSize;
  }

  /**
   * Returns the redirect target for redirect entries.
   *
   * @return destination URI, or {@code null} for file entries
   */
  public FreenetURI getTargetURI() {
    return targetURI;
  }

  /**
   * Reattaches runtime state after a restart.
   *
   * <p>Delegates to {@link RandomAccessBucket#onResume(ClientContext)} when a bucket is present.
   *
   * @param context runtime context used by nested bucket implementations
   * @throws ResumeFailedException if the bucket cannot resume
   */
  public void onResume(ClientContext context) throws ResumeFailedException {
    if (data != null) data.onResume(context);
  }

  /* ===== Java serialization support (explicit bucket handling) ===== */

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    // Preserve forward compatibility: when the bucket is Serializable, keep writing it inside the
    // default field block so older releases (which only read default fields) restore it correctly.
    // Only when the bucket is non-Serializable do we refuse to persist the checkpoint, matching the
    // historical behavior of similar bucket wrappers.
    ObjectOutputStream.PutField fields = out.putFields();
    fields.put("name", name);
    fields.put("fullName", fullName);
    fields.put("mimeOverride", mimeOverride);
    fields.put("dataSize", dataSize);
    fields.put("targetURI", targetURI);
    if (data == null) {
      fields.put("data", null);
      out.writeFields();
      return;
    }
    if (data instanceof Serializable serializable) {
      fields.put("data", serializable);
      out.writeFields();
      return;
    }
    // Non-serializable buckets cannot be safely persisted via Java serialization.
    out.writeFields();
    throw new java.io.NotSerializableException(data.getClass().getName());
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Read the default field block first. Historically, checkpoints stored the bucket inside the
    // default field block. However, intermediary builds also wrote the bucket as a trailing object
    // after the default fields. To remain compatible with those streams, attempt to read a trailing
    // object and treat it as the bucket when present. When no trailing object exists (the common
    // case), ObjectInputStream signals the end of class-defined data with
    // OptionalDataException#eof=true, so we must not advance the stream further.
    // Behavior is guarded by test:
    //   ManifestElementTest.deserialization_whenTwoElementsInStream_doesNotConsumeNextObject
    in.defaultReadObject();
    try {
      Object maybeBucket = in.readObject();
      data = (maybeBucket == null) ? null : (RandomAccessBucket) maybeBucket;
    } catch (OptionalDataException e) {
      // No trailing object for this class; keep the bucket restored from default fields.
      if (!e.eof) throw e;
    }
  }
}
