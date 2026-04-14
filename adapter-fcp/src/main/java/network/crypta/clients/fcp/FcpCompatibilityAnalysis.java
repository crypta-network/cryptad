package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Detached compatibility analyzer used by the adapter for status and persistence.
 *
 * <p>The binary encoding intentionally matches the legacy {@code CompatibilityAnalyser} format so
 * persistent GET requests remain compatible across this seam refactor. The object accumulates the
 * compatibility hints that arrive while a request is running and preserves the same min/max bounds,
 * splitfile crypto-key handling, and definitive-state behavior that the older runtime-owned type
 * exposed to the FCP layer.
 *
 * <p>The analysis starts in an unknown state and becomes more specific as events merge into it.
 * Later merges can raise the minimum required compatibility mode. They can also tighten the maximum
 * mode when a more restrictive bound arrives. Compression turns off as soon as any source says it
 * is unsafe. The result freezes once a definitive answer becomes available. Those rules matter for
 * both FCP status reporting and persistence replay, so the adapter keeps them documented here
 * rather than relying on runtime internals.
 */
public final class FcpCompatibilityAnalysis implements Serializable {
  /** Logger used when callers merge inconsistent or late compatibility information. */
  private static final Logger LOG = LoggerFactory.getLogger(FcpCompatibilityAnalysis.class);

  /** Stable serialization version for the detached compatibility analysis object itself. */
  @Serial private static final long serialVersionUID = 1L;

  /** Legacy wire-format version shared with the historical runtime compatibility analyzer. */
  static final int VERSION = 2;

  /** Current lower compatibility bound derived from merged request events. */
  private FcpCompatibilityMode min;

  /** Current upper compatibility bound derived from merged request events. */
  private FcpCompatibilityMode max;

  /** Splitfile crypto key retained while merged observations remain consistent. */
  private byte[] cryptoKey;

  /** Whether any merged observation has ruled out compression. */
  private boolean dontCompress;

  /** Whether the current analysis should reject later merge attempts as informational only. */
  private boolean definitive;

  /** Creates an empty compatibility analysis. */
  public FcpCompatibilityAnalysis() {
    min = FcpCompatibilityMode.COMPAT_UNKNOWN;
    max = FcpCompatibilityMode.COMPAT_UNKNOWN;
    dontCompress = true;
  }

  /**
   * Restores an analysis from the persisted compatibility encoding.
   *
   * @param dis input stream positioned at the start of a serialized analysis
   * @throws IOException if reading fails
   * @throws StorageFormatException if the encoding is invalid
   */
  public FcpCompatibilityAnalysis(DataInputStream dis) throws IOException, StorageFormatException {
    int version = dis.readInt();
    if (version != VERSION) {
      throw new StorageFormatException("Unknown version for CompatibilityAnalyser");
    }
    try {
      min = FcpCompatibilityMode.byCode(dis.readShort());
      max = FcpCompatibilityMode.byCode(dis.readShort());
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

  /**
   * Merges new compatibility hints into the current analysis.
   *
   * @param min minimum compatibility hint
   * @param max maximum compatibility hint
   * @param cryptoKey optional splitfile crypto key
   * @param dontCompress whether compression should be avoided
   * @param definitive whether the result should be frozen after this merge
   */
  public void merge(
      FcpCompatibilityMode min,
      FcpCompatibilityMode max,
      byte[] cryptoKey,
      boolean dontCompress,
      boolean definitive) {
    if (this.definitive) {
      LOG.warn("merge() after definitive");
      return;
    }
    if (min == FcpCompatibilityMode.COMPAT_CURRENT) {
      throw new IllegalArgumentException("min must not be COMPAT_CURRENT");
    }
    if (max == FcpCompatibilityMode.COMPAT_CURRENT) {
      throw new IllegalArgumentException("max must not be COMPAT_CURRENT");
    }
    if (definitive) {
      this.definitive = true;
    }
    if (!dontCompress) {
      this.dontCompress = false;
    }
    if (min.code() > this.min.code()) {
      this.min = min;
    }
    if (this.max == FcpCompatibilityMode.COMPAT_UNKNOWN || max.code() < this.max.code()) {
      this.max = max;
    }
    if (this.cryptoKey == null) {
      this.cryptoKey = cryptoKey;
    } else if (cryptoKey != null && !Arrays.equals(this.cryptoKey, cryptoKey)) {
      LOG.error("Two different crypto keys!");
      this.cryptoKey = null;
    }
  }

  /**
   * Returns the current minimum compatibility mode.
   *
   * @return current lower compatibility bound
   */
  public FcpCompatibilityMode min() {
    return min;
  }

  /**
   * Returns the current maximum compatibility mode.
   *
   * @return current upper compatibility bound
   */
  public FcpCompatibilityMode max() {
    return max;
  }

  /**
   * Returns the splitfile crypto key if one is still consistent across merges.
   *
   * <p>The returned array is the stored key reference rather than a defensive copy. Callers should
   * treat it as read-only because mutating it would also mutate the analysis state.
   *
   * @return splitfile crypto key or {@code null} when no stable key is available
   */
  public byte[] getCryptoKey() {
    return cryptoKey;
  }

  /**
   * Indicates whether compression should be avoided.
   *
   * @return {@code true} if compression should be avoided
   */
  public boolean dontCompress() {
    return dontCompress;
  }

  /**
   * Indicates whether the analysis is final.
   *
   * @return {@code true} if the analysis is definitive
   */
  public boolean definitive() {
    return definitive;
  }

  /**
   * Returns the current min/max modes as an array.
   *
   * @return two-element array containing min and max modes
   */
  public FcpCompatibilityMode[] getModes() {
    return new FcpCompatibilityMode[] {min(), max()};
  }

  /**
   * Writes the analysis using the legacy compatibility-analyzer encoding.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  public void writeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(VERSION);
    dos.writeShort(min.code());
    dos.writeShort(max.code());
    if (cryptoKey == null) {
      dos.writeBoolean(false);
    } else {
      dos.writeBoolean(true);
      assert cryptoKey.length == 32;
      dos.write(cryptoKey);
    }
    dos.writeBoolean(dontCompress);
    dos.writeBoolean(definitive);
  }
}
