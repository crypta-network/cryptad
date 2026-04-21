package network.crypta.clients.fcp;

import java.io.Serial;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;

/**
 * Default detached insert-context handle used by the adapter and bridge.
 *
 * <p>The class stores the persistent insert-policy snapshot that the adapter needs while keeping
 * the live runtime {@code InsertContext} out of adapter-owned request state. It is the ordinary
 * concrete implementation returned by bridge code when the adapter asks for a persistent insert
 * context and the ordinary object serialized inside adapter-owned request state when PUT requests
 * survive reconnections or node restarts.
 *
 * <p>The handle is intentionally mutable because the request assembly still needs to apply
 * per-request overrides such as retry limits, compression flags, and compatibility mode after the
 * baseline defaults are copied from the runtime. At the same time, it keeps the low-level splitfile
 * and RNF limits immutable so the adapter cannot accidentally drift away from the bridge-owned
 * baseline that was captured when the handle was created.
 *
 * <p>Instances are not thread-safe by themselves. The owning request coordinates access and uses
 * the embedded {@link ClientEventProducer} to register and remove listeners that mirror the event
 * surface of the historical runtime insert context.
 */
public final class DefaultFcpInsertContextHandle implements FcpInsertContextHandle {
  @Serial private static final long serialVersionUID = 1L;

  /** Event producer that backs listener registration on this detached handle. */
  private final ClientEventProducer eventProducer;

  /** Count of consecutive RNFs that the runtime should treat as effective success. */
  private int consecutiveRnfsCountAsSuccess;

  /** Maximum number of splitfile data blocks per segment captured from the runtime baseline. */
  private final int splitfileSegmentDataBlocks;

  /** Maximum number of splitfile check blocks per segment captured from the runtime baseline. */
  private final int splitfileSegmentCheckBlocks;

  /** Mutable flag controlling whether the insert should request CHK-only behavior. */
  private boolean getChkOnly;

  /** Mutable flag controlling whether compression should be skipped entirely. */
  private boolean dontCompress;

  /** Mutable retry limit applied to insert attempts for this request. */
  private int maxInsertRetries;

  /** Mutable flag describing whether the insert may populate the client cache. */
  private boolean canWriteClientCache;

  /** Mutable compressor descriptor string passed through to the runtime insert context. */
  private String compressorDescriptor;

  /** Mutable flag describing whether cacheable inserts may fork additional work. */
  private boolean forkOnCacheable;

  /** Mutable redundancy override for single-block inserts. */
  private int extraInsertsSingleBlock;

  /** Mutable redundancy override for splitfile header blocks. */
  private int extraInsertsSplitfileHeaderBlock;

  /** Mutable detached compatibility mode used when bridging back to the runtime context. */
  private FcpCompatibilityMode compatibilityMode;

  /** Mutable flag restricting the insert to local handling only. */
  private boolean localRequestOnly;

  /** Mutable flag enabling early-encode behavior in the runtime insert context. */
  private boolean earlyEncode;

  /** Mutable flag controlling whether USK datehints should be ignored. */
  private boolean ignoreUskDatehints;

  /**
   * Creates a detached insert-context handle with a fresh event producer.
   *
   * <p>Use this constructor when no existing listener registry needs to be preserved. The handle
   * receives a new {@link SimpleEventProducer}, copies the mutable insert options, and retains the
   * supplied immutable limit values for later bridge round-tripping.
   *
   * @param limits detached limit values copied from the runtime insert context
   * @param options detached insert options that seed the mutable request policy
   */
  public DefaultFcpInsertContextHandle(FcpInsertContextLimits limits, FcpInsertOptions options) {
    this(new SimpleEventProducer(), limits, options);
  }

  /**
   * Creates a detached insert-context handle with an explicit event producer.
   *
   * <p>This constructor is mainly used by bridge code converting a live or legacy runtime insert
   * context into the detached adapter-owned representation. Passing the original event producer
   * lets resumed requests continue to observe the expected listener behavior while still severing
   * the compile-time dependency on the runtime type.
   *
   * @param eventProducer event producer that should back listener registration on this handle
   * @param limits detached limit values copied from the runtime insert context
   * @param options detached insert options that seed the mutable request policy
   */
  public DefaultFcpInsertContextHandle(
      ClientEventProducer eventProducer, FcpInsertContextLimits limits, FcpInsertOptions options) {
    this.eventProducer = eventProducer;
    this.getChkOnly = options.getCHKOnly();
    this.dontCompress = options.dontCompress();
    this.maxInsertRetries = options.maxRetries();
    this.consecutiveRnfsCountAsSuccess = limits.consecutiveRnfsCountAsSuccess();
    this.splitfileSegmentDataBlocks = limits.splitfileSegmentDataBlocks();
    this.splitfileSegmentCheckBlocks = limits.splitfileSegmentCheckBlocks();
    this.canWriteClientCache = options.canWriteClientCache();
    this.compressorDescriptor = options.compressorDescriptor();
    this.forkOnCacheable = options.forkOnCacheable();
    this.extraInsertsSingleBlock = options.extraInsertsSingleBlock();
    this.extraInsertsSplitfileHeaderBlock = options.extraInsertsSplitfileHeaderBlock();
    this.compatibilityMode = options.compatibilityMode().intern();
    this.localRequestOnly = options.localRequestOnly();
    this.earlyEncode = options.earlyEncode();
    this.ignoreUskDatehints = options.ignoreUSKDatehints();
  }

  @Override
  public void setGetCHKOnly(boolean getCHKOnly) {
    this.getChkOnly = getCHKOnly;
  }

  @Override
  public boolean getCHKOnly() {
    return getChkOnly;
  }

  @Override
  public void setDontCompress(boolean dontCompress) {
    this.dontCompress = dontCompress;
  }

  @Override
  public void addEventListener(ClientEventListener listener) {
    eventProducer.addEventListener(listener);
  }

  @Override
  public boolean removeEventListener(ClientEventListener listener) {
    return eventProducer.removeEventListener(listener);
  }

  @Override
  public ClientEventProducer eventProducer() {
    return eventProducer;
  }

  @Override
  public void setMaxInsertRetries(int maxInsertRetries) {
    this.maxInsertRetries = maxInsertRetries;
  }

  @Override
  public int getMaxInsertRetries() {
    return maxInsertRetries;
  }

  @Override
  public void setConsecutiveRnfsCountAsSuccess(int consecutiveRnfsCountAsSuccess) {
    this.consecutiveRnfsCountAsSuccess = consecutiveRnfsCountAsSuccess;
  }

  @Override
  public int getConsecutiveRnfsCountAsSuccess() {
    return consecutiveRnfsCountAsSuccess;
  }

  @Override
  public int getSplitfileSegmentDataBlocks() {
    return splitfileSegmentDataBlocks;
  }

  @Override
  public int getSplitfileSegmentCheckBlocks() {
    return splitfileSegmentCheckBlocks;
  }

  @Override
  public void setCanWriteClientCache(boolean canWriteClientCache) {
    this.canWriteClientCache = canWriteClientCache;
  }

  @Override
  public boolean canWriteClientCache() {
    return canWriteClientCache;
  }

  @Override
  public void setCompressorDescriptor(String compressorDescriptor) {
    this.compressorDescriptor = compressorDescriptor;
  }

  @Override
  public String getCompressorDescriptor() {
    return compressorDescriptor;
  }

  @Override
  public void setForkOnCacheable(boolean forkOnCacheable) {
    this.forkOnCacheable = forkOnCacheable;
  }

  @Override
  public boolean forkOnCacheable() {
    return forkOnCacheable;
  }

  @Override
  public void setExtraInsertsSingleBlock(int extraInsertsSingleBlock) {
    this.extraInsertsSingleBlock = extraInsertsSingleBlock;
  }

  @Override
  public int getExtraInsertsSingleBlock() {
    return extraInsertsSingleBlock;
  }

  @Override
  public void setExtraInsertsSplitfileHeaderBlock(int extraInsertsSplitfileHeaderBlock) {
    this.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeaderBlock;
  }

  @Override
  public int getExtraInsertsSplitfileHeaderBlock() {
    return extraInsertsSplitfileHeaderBlock;
  }

  @Override
  public void setCompatibilityMode(FcpCompatibilityMode compatibilityMode) {
    this.compatibilityMode = compatibilityMode.intern();
  }

  @Override
  public FcpCompatibilityMode getCompatibilityMode() {
    return compatibilityMode;
  }

  @Override
  public void setLocalRequestOnly(boolean localRequestOnly) {
    this.localRequestOnly = localRequestOnly;
  }

  @Override
  public boolean localRequestOnly() {
    return localRequestOnly;
  }

  @Override
  public void setEarlyEncode(boolean earlyEncode) {
    this.earlyEncode = earlyEncode;
  }

  @Override
  public boolean earlyEncode() {
    return earlyEncode;
  }

  @Override
  public void setIgnoreUSKDatehints(boolean ignoreUSKDatehints) {
    this.ignoreUskDatehints = ignoreUSKDatehints;
  }

  @Override
  public boolean ignoreUSKDatehints() {
    return ignoreUskDatehints;
  }

  @Override
  public boolean isDontCompress() {
    return dontCompress;
  }
}
