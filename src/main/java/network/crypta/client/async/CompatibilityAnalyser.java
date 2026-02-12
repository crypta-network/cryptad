package network.crypta.client.async;

import java.io.*;
import java.util.Arrays;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Analyses and aggregates insert compatibility requirements across multiple inputs.
 *
 * <p>This helper accumulates constraints that influence how data is prepared for insertion, such as
 * the minimum and maximum {@link InsertContext.CompatibilityMode}, whether compression should be
 * avoided, and an optional 32-byte cryptographic key. Typical usage is to create an instance, merge
 * constraints from several sources (metadata, caller hints, or discovered characteristics), and
 * then query the resulting bounds and flags to configure the actual insert operation.
 *
 * <p>The analyser maintains simple, monotonic invariants: the minimum compatibility only increases
 * when merged, the maximum compatibility only decreases (or is initialized when unknown), and the
 * compression flag switches from “do not compress” to “may compress” if any merged input allows
 * compression. When conflicting cryptographic keys are observed, the key becomes {@code null} to
 * signal that a consistent value is unavailable.
 *
 * <p>This type is mutable and not thread-safe. Callers that access it from multiple threads should
 * either confine instances to a single thread or synchronize external access. Instances may be
 * serialized; the on-disk format is versioned via {@link #VERSION}.
 *
 * <ul>
 *   <li>Responsibility: accumulate and report compatibility bounds and flags.
 *   <li>Notable behavior: subsequent merges are ignored once marked definitive.
 * </ul>
 *
 * @see InsertContext.CompatibilityMode
 */
public final class CompatibilityAnalyser implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(CompatibilityAnalyser.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * The lowest permitted {@link InsertContext.CompatibilityMode} across all merged inputs. The
   * value monotonically increases as constraints are merged, and starts as {@code COMPAT_UNKNOWN}.
   */
  CompatibilityMode min;

  /**
   * The highest permitted {@link InsertContext.CompatibilityMode} across all merged inputs. The
   * value monotonically decreases as constraints are merged, and starts as {@code COMPAT_UNKNOWN}.
   */
  CompatibilityMode max;

  /**
   * Optional 32-byte cryptographic key associated with the analysis. When multiple merges provide
   * different keys the analyser clears this field to {@code null} to indicate conflict.
   */
  byte[] cryptoKey;

  /**
   * If {@code true}, compression should be avoided. The flag changes to {@code false} if any merge
   * allows compression; it never flips back to {@code true} within the same instance.
   */
  boolean dontCompress;

  /**
   * When {@code true}, the result is considered final and subsequent merges are ignored. This is a
   * coarse-grained guard to freeze the current outcome once a definite decision was reached.
   */
  boolean definitive;

  /**
   * Creates a new analyser with no prior knowledge.
   *
   * <p>The initial state sets both compatibility bounds to {@link
   * InsertContext.CompatibilityMode#COMPAT_UNKNOWN}, requests no compression by default (safer
   * choice for compatibility), and leaves the cryptographic key unset. Call {@link #merge(
   * InsertContext.CompatibilityMode, InsertContext.CompatibilityMode, byte[], boolean, boolean)} to
   * incorporate constraints discovered from inputs.
   */
  public CompatibilityAnalyser() {
    this.min = CompatibilityMode.COMPAT_UNKNOWN;
    this.max = CompatibilityMode.COMPAT_UNKNOWN;
    this.dontCompress = true;
  }

  /**
   * Merges a set of constraints into the current analysis.
   *
   * <p>The minimum mode is raised as needed, the maximum mode is lowered (or initialized if
   * unknown), the compression flag becomes {@code false} if any merge permits compression, and the
   * cryptographic key is kept only if all merged values match. If {@code definitive} is set, the
   * analyser marks itself definitive and subsequent calls to this method are ignored.
   *
   * <p>This method is idempotent with the same arguments and monotonic in its effect on the stored
   * bounds. Passing {@link InsertContext.CompatibilityMode#COMPAT_CURRENT} is not permitted.
   *
   * @param min the lowest acceptable compatibility mode for the source of this merge; must not be
   *     {@code COMPAT_CURRENT}; {@code null} is not allowed.
   * @param max the highest acceptable compatibility mode for the source of this merge; must not be
   *     {@code COMPAT_CURRENT}; {@code null} is not allowed.
   * @param cryptoKey a 32-byte cryptographic key associated with the input; may be {@code null} to
   *     indicate no key. If a different non-null key is observed later the stored key is cleared.
   * @param dontCompress if {@code true}, requests avoiding compression for this input; if {@code
   *     false}, compression is allowed and the analyser’s flag flips to {@code false}.
   * @param definitive when {@code true}, marks the analysis final so that further merges are
   *     ignored after applying this merge.
   * @throws IllegalArgumentException if {@code min} or {@code max} is {@code COMPAT_CURRENT}.
   */
  public void merge(
      CompatibilityMode min,
      CompatibilityMode max,
      byte[] cryptoKey,
      boolean dontCompress,
      boolean definitive) {
    if (this.definitive) {
      LOG.warn("merge() after definitive");
      return;
    }
    if (min == CompatibilityMode.COMPAT_CURRENT) {
      throw new IllegalArgumentException("min must not be COMPAT_CURRENT");
    }
    if (max == CompatibilityMode.COMPAT_CURRENT) {
      throw new IllegalArgumentException("max must not be COMPAT_CURRENT");
    }
    if (definitive) this.definitive = true;
    if (!dontCompress) this.dontCompress = false;
    if (min.code > this.min.code) this.min = min;
    if (max.code < this.max.code || this.max == CompatibilityMode.COMPAT_UNKNOWN) this.max = max;
    if (this.cryptoKey == null) {
      this.cryptoKey = cryptoKey;
    } else if (cryptoKey != null && !Arrays.equals(this.cryptoKey, cryptoKey)) {
      LOG.error("Two different crypto keys!");
      this.cryptoKey = null;
    }
  }

  /**
   * Returns the accumulated minimum compatibility mode.
   *
   * <p>The value only moves upward as constraints are merged. It begins as {@code COMPAT_UNKNOWN}
   * and becomes more specific over time. Callers should treat the result as read-only and use it to
   * constrain insert metadata or encoding choices.
   *
   * @return the current lower bound of compatibility across all merges; may be {@code
   *     COMPAT_UNKNOWN} when insufficient information is available.
   */
  public CompatibilityMode min() {
    return min;
  }

  /**
   * Returns the accumulated maximum compatibility mode.
   *
   * <p>The value only moves downward as constraints are merged. It begins as {@code COMPAT_UNKNOWN}
   * and becomes more specific over time. Use together with {@link #min()} to understand the final
   * compatibility interval.
   *
   * @return the current upper bound of compatibility across all merges; may be {@code
   *     COMPAT_UNKNOWN} when insufficient information is available.
   */
  public CompatibilityMode max() {
    return max;
  }

  /**
   * Returns the 32-byte cryptographic key if a consistent key was observed.
   *
   * <p>The key is retained only while all merged inputs supply the same non-null value. If a
   * conflict is detected, the stored key is cleared and this method returns {@code null} to signal
   * that the caller must not rely on a single agreed key.
   *
   * @return the agreed 32-byte key, or {@code null} when unset or conflicting values were merged.
   */
  public byte[] getCryptoKey() {
    return cryptoKey;
  }

  /**
   * Indicates whether compression should be avoided for the analysed inputs.
   *
   * <p>The default is {@code true}. Once a merge advertises that compression is acceptable, the
   * flag becomes {@code false}; it does not revert to {@code true} for the lifetime of this
   * instance.
   *
   * @return {@code true} to avoid compression; {@code false} if any merge permitted compression.
   */
  public boolean dontCompress() {
    return dontCompress;
  }

  /**
   * Reports whether the analysis was marked final.
   *
   * <p>When definitive, subsequent calls to {@link #merge(CompatibilityMode, CompatibilityMode,
   * byte[], boolean, boolean)} are ignored to preserve the current outcome.
   *
   * @return {@code true} if the analyser is final and will ignore future merges; otherwise {@code
   *     false}.
   */
  public boolean definitive() {
    return definitive;
  }

  /**
   * Returns the current compatibility bounds as a pair.
   *
   * <p>The array contains exactly two elements: the first is {@link #min()}, the second is {@link
   * #max()}. The returned array is a new instance and can be safely modified by the caller.
   *
   * @return a two-element array containing the minimum and maximum compatibility modes.
   */
  public InsertContext.CompatibilityMode[] getModes() {
    return new InsertContext.CompatibilityMode[] {min(), max()};
  }

  /**
   * Serialization format version for {@link #writeTo(DataOutputStream)} and the corresponding
   * deserialization constructor. Bump when the persistent layout changes.
   */
  static final int VERSION = 2;

  /**
   * Writes the current analysis to a {@link DataOutputStream}.
   *
   * <p>The layout is: an {@code int} version, two {@code short} codes for {@link #min()} and {@link
   * #max()}, a {@code boolean} followed by 32 bytes when a key is present, then two {@code boolean}
   * values for {@link #dontCompress()} and {@link #definitive()}. This method does not flush or
   * close the stream.
   *
   * @param dos the target stream used to persist the analysis; must be open and writable.
   * @throws IOException if writing to {@code dos} fails for any reason.
   */
  public void writeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(VERSION);
    dos.writeShort(min.code);
    dos.writeShort(max.code);
    if (cryptoKey == null) {
      dos.writeBoolean(false);
    } else {
      dos.writeBoolean(true);
      assert (cryptoKey.length == 32);
      dos.write(cryptoKey);
    }
    dos.writeBoolean(dontCompress);
    dos.writeBoolean(definitive);
  }

  /**
   * Reconstructs an analyser from a {@link DataInputStream} previously written by {@link
   * #writeTo(DataOutputStream)}.
   *
   * <p>The constructor validates the format version and mode codes. When a cryptographic key is
   * present, exactly 32 bytes are read. The stream is not closed by this constructor.
   *
   * @param dis the source stream positioned at the start of a serialized analyser; not {@code
   *     null}.
   * @throws IOException if reading from {@code dis} fails or the stream terminates prematurely.
   * @throws StorageFormatException if the version is unknown or a mode code is not recognized.
   */
  public CompatibilityAnalyser(DataInputStream dis) throws IOException, StorageFormatException {
    int ver = dis.readInt();
    if (ver != VERSION)
      throw new StorageFormatException("Unknown version for CompatibilityAnalyser");
    try {
      min = CompatibilityMode.byCode(dis.readShort());
      max = CompatibilityMode.byCode(dis.readShort());
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Bad min value");
    }
    if (dis.readBoolean()) {
      cryptoKey = new byte[32];
      dis.readFully(cryptoKey);
    }
    dontCompress = dis.readBoolean();
    definitive = dis.readBoolean();
  }
}
