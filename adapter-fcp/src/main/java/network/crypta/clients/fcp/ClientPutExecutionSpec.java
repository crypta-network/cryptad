package network.crypta.clients.fcp;

import network.crypta.client.ClientMetadata;
import network.crypta.client.async.ClientPutCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Detached single-file insert description consumed by the bridge runtime.
 *
 * <p>This specification carries the adapter-owned inputs that the bridge needs to construct a live
 * single-file insert execution for a {@link ClientPut}. It groups the request callback, identity,
 * insert policy, payload bucket, metadata, and a small nested option set so the bridge can build a
 * concrete runtime-owned putter without forcing {@code :adapter-fcp} to import the daemon insert
 * engine classes directly.
 *
 * <p>The object is intentionally simple and read-only. It is assembled from the already validated
 * FCP request state, then handed across the module boundary where the bridge translates it into the
 * concrete runtime operation for the current insert attempt.
 */
public final class ClientPutExecutionSpec {
  /** Callback surface that receives progress, completion, and failure notifications. */
  private final ClientPutCallback callback;

  /** Detached request identity and persistence metadata for the insert. */
  private final ClientRequestParams requestParams;

  /** The insert policy snapshot governing retries, compression, and compatibility. */
  private final FcpInsertContextHandle insertContext;

  /** Payload bucket to insert or redirect metadata bucket for metadata-only inserts. */
  private final RandomAccessBucket data;

  /** Client-visible metadata associated with the payload being inserted. */
  private final ClientMetadata clientMetadata;

  /** Flag indicating whether {@link #data} currently contains metadata rather than raw payload. */
  private final boolean isMetadata;

  /** Nested option group containing the putter-only execution settings. */
  private final ExecutionOptions executionOptions;

  /**
   * Creates a detached single-file execution specification for the bridge runtime.
   *
   * <p>The constructor stores the already prepared request state that a bridge implementation needs
   * when constructing a live runtime-owned putter. It does not validate or normalize the inputs
   * further; higher-level FCP request assembly is expected to provide a coherent payload bucket,
   * insert context, and option set before handing the spec to the runtime bridge.
   *
   * @param callback callback that should receive insert lifecycle notifications
   * @param requestParams detached request identity and persistence metadata for the insert
   * @param insertContext insert policy snapshot that should govern this execution
   * @param data payload or metadata bucket to hand to the runtime-owned putter
   * @param clientMetadata client-visible metadata associated with the insert
   * @param isMetadata whether the bucket currently represents metadata rather than raw content
   * @param executionOptions nested option group containing single-file putter settings
   */
  public ClientPutExecutionSpec(
      ClientPutCallback callback,
      ClientRequestParams requestParams,
      FcpInsertContextHandle insertContext,
      RandomAccessBucket data,
      ClientMetadata clientMetadata,
      boolean isMetadata,
      ExecutionOptions executionOptions) {
    this.callback = callback;
    this.requestParams = requestParams;
    this.insertContext = insertContext;
    this.data = data;
    this.clientMetadata = clientMetadata;
    this.isMetadata = isMetadata;
    this.executionOptions = executionOptions;
  }

  /**
   * Returns the callback that should receive insert lifecycle notifications.
   *
   * <p>The bridge passes this callback directly into the runtime-owned putter so that progress,
   * completion, and failure events continue to flow back into the owning FCP request.
   *
   * @return callback to use for this single-file insert execution
   */
  public ClientPutCallback callback() {
    return callback;
  }

  /**
   * Returns the detached request metadata for this insert execution.
   *
   * <p>The bridge uses this metadata for stable values such as the target URI, request identifier,
   * persistence mode, and the original priority snapshot that was present when the execution was
   * assembled.
   *
   * @return request-scoped metadata associated with this execution attempt
   */
  public ClientRequestParams requestParams() {
    return requestParams;
  }

  /**
   * Returns the insert policy snapshot for this execution.
   *
   * <p>This context captures the retry, compression, and compatibility policy that should be used
   * by the runtime-owned insert engine when the bridge constructs the concrete putter.
   *
   * @return the insert policy snapshot to apply to the runtime-owned execution
   */
  public FcpInsertContextHandle insertContext() {
    return insertContext;
  }

  /**
   * Returns the bucket that supplies bytes for this insert.
   *
   * <p>The bucket may contain raw payload bytes or generated redirect metadata, depending on the
   * surrounding request assembly. The bridge treats it as the authoritative data source for the
   * current single-file insert attempt.
   *
   * @return payload or metadata bucket for the runtime-owned putter
   */
  public RandomAccessBucket data() {
    return data;
  }

  /**
   * Returns the client-visible metadata associated with this insert.
   *
   * <p>This metadata is supplied alongside the payload bucket so the runtime-owned putter can
   * preserve MIME and related client-facing details during insert assembly.
   *
   * @return client metadata associated with the insert payload
   */
  public ClientMetadata clientMetadata() {
    return clientMetadata;
  }

  /**
   * Returns whether the payload bucket currently contains metadata.
   *
   * <p>Redirect and some manifest-related insert paths encode metadata into the bucket and should
   * be flagged accordingly, so the runtime-owned putter handles the bucket correctly.
   *
   * @return {@code true} when {@link #data()} contains metadata rather than raw payload content
   */
  public boolean isMetadata() {
    return isMetadata;
  }

  /**
   * Returns the optional target filename to supply to the runtime-owned putter.
   *
   * <p>This value is drawn from the nested execution options and typically matters when the target
   * URI needs a document name synthesized from the uploaded filename.
   *
   * @return target filename hint for the runtime-owned single-file putter, or {@code null}
   */
  public String targetFilename() {
    return executionOptions.targetFilename();
  }

  /**
   * Returns whether this insert should be treated as a binary blob.
   *
   * <p>Binary blob inserts suppress normal metadata handling and final URI generation semantics.
   * The bridge forwards this flag directly into the runtime-owned putter options.
   *
   * @return {@code true} when the insert should use binary-blob semantics
   */
  public boolean binaryBlob() {
    return executionOptions.binaryBlob();
  }

  /**
   * Returns the explicit splitfile crypto key override, if present.
   *
   * <p>This value is passed through unchanged, so restart and initial execution use the same
   * explicit keying behavior whenever a client requested one.
   *
   * @return splitfile crypto key override, or {@code null} when default keying should apply
   */
  public byte[] overrideSplitfileCryptoKey() {
    return executionOptions.overrideSplitfileCryptoKey();
  }

  /**
   * Returns the metadata threshold configured for this execution.
   *
   * <p>The runtime-owned putter uses this threshold when deciding how to treat insert metadata. The
   * adapter keeps it in the detached spec so the bridge can reconstruct identical runtime behavior
   * on restart.
   *
   * @return metadata threshold value to apply to the insert execution
   */
  public long metadataThreshold() {
    return executionOptions.metadataThreshold();
  }

  /**
   * Returns the target URI for this insert execution.
   *
   * <p>This is a convenience accessor over the detached request metadata because the bridge needs
   * the target URI frequently when constructing a runtime-owned putter.
   *
   * @return target insert URI associated with this execution attempt
   */
  public FreenetURI targetURI() {
    return requestParams.uri();
  }

  /**
   * Single-file putter options detached from the runtime-owned putter types.
   *
   * <p>This nested object keeps the putter-specific knobs together without widening {@link
   * ClientRequestParams}. It is limited to the execution details that matter only when the bridge
   * instantiates a live single-file putter.
   */
  @SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
  public static final class ExecutionOptions {
    /** Optional filename hint used when synthesizing a target document name. */
    private final String targetFilename;

    /** Whether the insert should use binary-blob behavior instead of normal metadata handling. */
    private final boolean binaryBlob;

    /** Optional explicit splitfile crypto key override supplied by the client. */
    private final byte[] overrideSplitfileCryptoKey;

    /** Threshold value forwarded to the runtime-owned putter metadata handling logic. */
    private final long metadataThreshold;

    /**
     * Creates a detached set of single-file putter options.
     *
     * <p>The values are stored exactly as provided and later consumed by the bridge when it
     * constructs the runtime-owned putter for a single-file insert attempt.
     *
     * @param targetFilename optional filename hint for target URI document-name handling
     * @param binaryBlob whether the insert should use binary-blob behavior
     * @param overrideSplitfileCryptoKey optional explicit splitfile crypto key override
     * @param metadataThreshold threshold to forward to runtime metadata handling
     */
    public ExecutionOptions(
        String targetFilename,
        boolean binaryBlob,
        byte[] overrideSplitfileCryptoKey,
        long metadataThreshold) {
      this.targetFilename = targetFilename;
      this.binaryBlob = binaryBlob;
      this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
      this.metadataThreshold = metadataThreshold;
    }

    /**
     * Returns the optional target filename hint for the putter.
     *
     * @return target filename hint, or {@code null} when no hint should be applied
     */
    public String targetFilename() {
      return targetFilename;
    }

    /**
     * Returns whether the insert should use binary-blob behavior.
     *
     * @return {@code true} when the runtime-owned putter should treat the insert as a binary blob
     */
    public boolean binaryBlob() {
      return binaryBlob;
    }

    /**
     * Returns the explicit splitfile crypto key override, if any.
     *
     * @return splitfile crypto key override, or {@code null} when default keying should apply
     */
    public byte[] overrideSplitfileCryptoKey() {
      return overrideSplitfileCryptoKey;
    }

    /**
     * Returns the metadata threshold to apply to the runtime-owned putter.
     *
     * @return metadata threshold value associated with this execution option set
     */
    public long metadataThreshold() {
      return metadataThreshold;
    }
  }
}
