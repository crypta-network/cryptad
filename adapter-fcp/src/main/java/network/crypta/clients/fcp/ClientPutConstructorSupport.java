package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Assembles detached construction state for {@link ClientPut} before the request instance exists.
 *
 * <p>The public {@link ClientPut} constructors accept FCP-facing request models, but the heavy
 * assembly work they trigger is narrower and fully deterministic: identifier validation, disk/DDA
 * checks, MIME resolution, redirect metadata preparation, and creation of the live single-file
 * execution. This helper isolates that constructor-only responsibility so {@code ClientPut} itself
 * can stay focused on request state, serialization, and public accessors.
 *
 * <p>The support class is intentionally stateless. Callers use one of the static factory methods to
 * convert validated FCP inputs into an immutable {@link Init} bundle, then hand that bundle to the
 * package-private {@link ClientPut} constructor. No request lifecycle state is retained here after
 * the bundle is created, which keeps construction replayable and easier to reason about during
 * persistence restores.
 *
 * <p>In practice this helper is the boundary between protocol parsing and request ownership. By the
 * time one of its factory methods returns, the insert identifier has been checked, disk-access
 * rules have been enforced, upload metadata has been normalized, and the detached execution inputs
 * have been assembled in the exact shape that {@link ClientPutBase} and {@link ClientPut} expect.
 * That separation reduces constructor sprawl without changing the observable behavior of FCP PUT
 * requests.
 */
final class ClientPutConstructorSupport {
  /**
   * Logger used only for construction-time diagnostics while the upload state is being prepared.
   */
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutConstructorSupport.class);

  /** Debugging template for persistent uploads to log bucket identity and source. */
  private static final String PERSISTENT_UPLOAD_LOG_TEMPLATE =
      "Prepared persistent upload data: data = {}, uploadFrom = {}";

  /** Debugging template for message-based uploads to log bucket identity and source. */
  private static final String MESSAGE_UPLOAD_LOG_TEMPLATE =
      "Prepared message upload data: data = {}, uploadFrom = {}";

  /** Prevents instantiation; this type exposes only static constructor-support utilities. */
  private ClientPutConstructorSupport() {}

  /**
   * Immutable construction bundle for the package-private {@link ClientPut} constructor.
   *
   * <p>The bundle carries both the base-request initialization data and the prepared single-file
   * insert state that must be installed on the concrete request once it exists. It also retains the
   * detached execution inputs needed to create the live {@link ClientPutExecution} after the
   * request has initialized its inherited context state.
   *
   * <p>The record deliberately separates "base" request state from the upload-specific pieces that
   * only {@link ClientPut} owns. That split lets {@link ClientPutBase} rebuild its insert context
   * and persistence identity first, then lets {@link ClientPut} install the prepared bucket,
   * metadata, URI, and execution details in one place.
   *
   * @param baseInit detached base-request inputs consumed by {@link ClientPutBase}
   * @param uploadFrom original upload source classification that drives later reporting and cleanup
   * @param origFilename source filename for disk-backed uploads, or {@code null} when not
   *     applicable
   * @param targetUri normalized insert or redirect URI selected for the request
   * @param data prepared request-owned bucket containing upload or metadata bytes
   * @param clientMetadata normalized MIME metadata associated with the prepared upload
   * @param targetFilename requested target filename used for metadata and persistent tags
   * @param binaryBlob whether the request should run in Binary Blob mode
   * @param metadataBucket whether {@code data} contains metadata rather than raw upload content
   * @param executionOptions detached execution knobs passed to the runtime putter factory
   * @param runtimeSupport runtime seam used to instantiate the live execution after the request
   *     object exists
   */
  record Init(
      BaseInit baseInit,
      ClientPutBase.UploadFrom uploadFrom,
      File origFilename,
      FreenetURI targetUri,
      RandomAccessBucket data,
      ClientMetadata clientMetadata,
      String targetFilename,
      boolean binaryBlob,
      boolean metadataBucket,
      ClientPutExecutionSpec.ExecutionOptions executionOptions,
      FcpInsertRuntimeSupport runtimeSupport) {

    /**
     * Creates the live runtime-backed single-file execution for a fully initialized request.
     *
     * <p>Callers invoke this only after {@link ClientPutBase} has restored the detached insert
     * context and the concrete {@link ClientPut} instance has copied all record fields onto itself.
     * The method then assembles the bridge-owned {@link ClientPutExecutionSpec} and delegates to
     * {@link ClientPutPutterFactory}, preserving the same runtime construction order as the former
     * in-constructor logic.
     *
     * @param request concrete request that will own the returned execution and receive its
     *     callbacks
     * @return live execution handle ready to be stored on {@code request}
     * @throws IOException if the runtime putter cannot be created from the prepared state
     */
    ClientPutExecution createExecution(ClientPut request) throws IOException {
      return ClientPutPutterFactory.create(
          runtimeSupport,
          new ClientPutExecutionSpec(
              request,
              baseInit.requestParams(),
              request.ctx,
              data,
              clientMetadata,
              metadataBucket,
              executionOptions));
    }
  }

  /**
   * Immutable base-constructor input bundle consumed by {@link ClientPutBase}.
   *
   * <p>The record groups the detached request parameters, charset, insert options, runtime support,
   * and either a connection handler or persistent client owner. That lets {@link ClientPutBase}
   * reconstruct its shared state without forcing {@link ClientPut} to keep all constructor-only
   * dependencies in its own type surface.
   *
   * @param requestParams detached request identity and persistence parameters
   * @param charset optional charset hint supplied for metadata generation
   * @param options detached insert options that should be copied onto the insert context handle
   * @param handler connection owner for connection-scoped requests, or {@code null} when the
   *     request is already persistent
   * @param persistentClient persistent owner for reboot/forever requests, or {@code null} for
   *     connection-scoped requests
   * @param runtimeSupport runtime seam used to get factories and default insert context state
   * @param publicUri precomputed request URI corresponding to the insert URI used by this request
   */
  record BaseInit(
      ClientRequestParams requestParams,
      String charset,
      FcpInsertOptions options,
      FCPConnectionHandler handler,
      PersistentRequestClient persistentClient,
      FcpInsertRuntimeSupport runtimeSupport,
      FreenetURI publicUri) {}

  /**
   * Builds a detached constructor bundle for a persistent single-file insert request.
   *
   * <p>This path is used when a request already has a persistent owner and an upload description
   * assembled outside the normal socket-message flow. The method validates identifier reuse,
   * normalizes MIME and Binary Blob handling, performs any required persistent disk checks, and
   * prepares the request-owned upload bucket or redirect metadata. The returned {@link Init} can be
   * handed directly to the package-private {@link ClientPut} constructor.
   *
   * @param request persistent insert request definition including owner, identifier, and request
   *     flags
   * @param options detached insert options that will later be copied onto the request's insert
   *     context handle
   * @param upload normalized upload description containing the source bucket, filename, and
   *     redirect information
   * @param server FCP server used to resolve the insert runtime support seam
   * @return immutable constructor bundle containing a prepared request and execution state
   * @throws IdentifierCollisionException if the persistent owner already has a request with the
   *     same identifier
   * @throws NotAllowedException if the upload configuration violates the persistent disk-access
   *     policy
   * @throws MetadataUnresolvedException if redirect or metadata preparation cannot complete
   * @throws IOException if bucket preparation or request setup fails
   */
  static Init fromPersistentRequest(
      FcpInsertRequest request, FcpInsertOptions options, ClientPutUpload upload, FCPServer server)
      throws IdentifierCollisionException,
          NotAllowedException,
          MetadataUnresolvedException,
          IOException {
    FcpInsertRuntimeSupport runtimeSupport = server.insertRuntimeSupport();
    ClientRequestParams requestParams =
        new ClientRequestParams(
            ClientPutBase.checkEmptySSK(request.uri(), upload.targetFilename(), runtimeSupport),
            ensurePersistentIdentifierAvailable(request.client(), request.identifier()),
            request.verbosity(),
            request.priorityClass(),
            request.persistence(),
            options.realTimeFlag(),
            request.clientToken(),
            request.global());
    BaseInit baseInit =
        new BaseInit(
            requestParams,
            request.charset(),
            options,
            null,
            request.client(),
            runtimeSupport,
            ClientPutBase.derivePublicURI(requestParams.uri()));

    ClientPutBase.UploadFrom uploadFromType = upload.uploadFromType();
    File uploadOrigFilename = upload.origFilename();
    String contentType = upload.contentType();
    String uploadTargetFilename = upload.targetFilename();
    RandomAccessBucket tempData = upload.data();
    boolean binaryBlob = upload.binaryBlob();

    if (uploadFromType == ClientPutBase.UploadFrom.DISK) {
      ClientPutDiskUploadValidator.validatePersistentDiskUpload(
          runtimeSupport.transferAccess(), uploadOrigFilename);
    }

    if (binaryBlob) {
      contentType = null;
    }
    ClientMetadata clientMetadata = new ClientMetadata(contentType);
    if (LOG.isDebugEnabled()) {
      LOG.debug(PERSISTENT_UPLOAD_LOG_TEMPLATE, tempData, uploadFromType);
    }
    PreparedData preparedData =
        ClientPutPreparedDataFactory.prepareForPersistentUpload(
            uploadFromType,
            clientMetadata,
            tempData,
            upload.redirectTarget(),
            runtimeSupport,
            requestParams.persistence() == ClientRequest.Persistence.FOREVER);
    return new Init(
        baseInit,
        uploadFromType,
        uploadOrigFilename,
        preparedData.targetUri(),
        preparedData.bucket(),
        clientMetadata,
        uploadTargetFilename,
        binaryBlob,
        preparedData.isMetadata(),
        new ClientPutExecutionSpec.ExecutionOptions(
            requestParams.uri().getDocName() == null ? uploadTargetFilename : null,
            binaryBlob,
            options.overrideSplitfileCryptoKey(),
            -1L),
        runtimeSupport);
  }

  /**
   * Builds a detached constructor bundle for a message-driven single-file insert request.
   *
   * <p>This path starts from the parsed {@link ClientPutMessage} sent over an active FCP
   * connection. It reconstructs the detached insert options, validates connection-scoped identifier
   * reuse, applies disk-access checks, resolves MIME handling, prepares the request bucket, and
   * verifies any salted-hash constraint supplied by the client. The result is the same immutable
   * {@link Init} shape used by the persistent-request path, which keeps later request construction
   * uniform.
   *
   * @param handler connection handler that owns the request while the message is being processed
   * @param message parsed FCP PUT message containing user-supplied options and upload data
   * @param server FCP server used to resolve the insert runtime support seam
   * @return immutable constructor bundle containing a prepared request and execution state
   * @throws IdentifierCollisionException if the connection already owns a request with the same
   *     identifier
   * @throws MessageInvalidException if the message violates disk-access or request validation rules
   * @throws IOException if bucket preparation or salted-hash verification fails
   */
  static Init fromMessage(FCPConnectionHandler handler, ClientPutMessage message, FCPServer server)
      throws IdentifierCollisionException, MessageInvalidException, IOException {
    FcpInsertRuntimeSupport runtimeSupport = server.insertRuntimeSupport();
    FcpInsertOptions options =
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(
                message.getCHKOnly,
                message.dontCompress,
                message.localRequestOnly,
                message.maxRetries,
                message.consecutiveRnfsCountAsSuccess,
                message.earlyEncode,
                message.realTimeFlag,
                message.ignoreUSKDatehints),
            new FcpInsertTuningOptions(
                message.canWriteClientCache,
                message.forkOnCacheable,
                message.compressorDescriptor,
                message.extraInsertsSingleBlock,
                message.extraInsertsSplitfileHeaderBlock,
                message.compatibilityMode),
            message.overrideSplitfileCryptoKey);
    ClientRequestParams requestParams =
        new ClientRequestParams(
            ClientPutBase.checkEmptySSK(message.uri, message.targetFilename, runtimeSupport),
            ensureConnectionIdentifierAvailable(handler, message),
            message.verbosity,
            message.priorityClass,
            message.persistence,
            options.realTimeFlag(),
            message.clientToken,
            message.global);
    BaseInit baseInit =
        new BaseInit(
            requestParams,
            null,
            options,
            handler,
            null,
            runtimeSupport,
            ClientPutBase.derivePublicURI(requestParams.uri()));

    boolean binaryBlob = message.binaryBlob;
    DiskUploadContext diskContext =
        ClientPutDiskUploadValidator.validateDiskUpload(
            runtimeSupport.transferAccess(), handler, message, message.identifier, message.global);

    String targetFilename = message.targetFilename;
    ClientPutBase.UploadFrom uploadFrom = message.uploadFromType;
    File origFilename = message.origFilename;
    String mimeType =
        ClientPutMimeResolver.resolve(
            message, origFilename, targetFilename, binaryBlob, message.identifier, message.global);

    ClientMetadata clientMetadata = new ClientMetadata(mimeType);
    PreparedData preparedData =
        ClientPutPreparedDataFactory.prepareForMessage(
            message,
            clientMetadata,
            runtimeSupport,
            requestParams.persistence() == ClientRequest.Persistence.FOREVER,
            uploadFrom,
            requestParams.identifier(),
            requestParams.global());
    RandomAccessBucket data = preparedData.bucket();
    ClientPutDiskUploadValidator.verifySaltedHash(
        diskContext, data, requestParams.identifier(), requestParams.global());

    if (LOG.isDebugEnabled()) {
      LOG.debug(MESSAGE_UPLOAD_LOG_TEMPLATE, data, uploadFrom);
    }
    return new Init(
        baseInit,
        uploadFrom,
        origFilename,
        preparedData.targetUri(),
        data,
        clientMetadata,
        targetFilename,
        binaryBlob,
        preparedData.isMetadata(),
        new ClientPutExecutionSpec.ExecutionOptions(
            requestParams.uri().getDocName() == null ? targetFilename : null,
            binaryBlob,
            message.overrideSplitfileCryptoKey,
            message.metadataThreshold),
        runtimeSupport);
  }

  /**
   * Ensures that a connection-scoped PUT identifier is unique on the owning socket.
   *
   * <p>Only {@link ClientRequest.Persistence#CONNECTION} requests need this check because
   * persistent owners track reboot and forever requests instead of the live handler map.
   *
   * @param handler connection handler that owns the in-flight request map
   * @param message parsed PUT message carrying the requested identifier and persistence mode
   * @return the identifier when it is valid for the current handler state
   * @throws IdentifierCollisionException if the handler already owns a request with the same
   *     identifier
   */
  private static String ensureConnectionIdentifierAvailable(
      FCPConnectionHandler handler, ClientPutMessage message) throws IdentifierCollisionException {
    if (message.persistence != ClientRequest.Persistence.CONNECTION) {
      return message.identifier;
    }
    if (handler.requestsByIdentifier.containsKey(message.identifier)) {
      throw new IdentifierCollisionException();
    }
    return message.identifier;
  }

  /**
   * Ensures that a persistent request identifier is unique for the owning client.
   *
   * @param client persistent request owner, or {@code null} when no persistent owner is involved
   * @param identifier identifier requested for the new persistent insert
   * @return the identifier when no existing persistent request already owns it
   * @throws IdentifierCollisionException if {@code client} already has a request with the same
   *     identifier
   */
  private static String ensurePersistentIdentifierAvailable(
      PersistentRequestClient client, String identifier) throws IdentifierCollisionException {
    if (client != null && client.getRequest(identifier) != null) {
      throw new IdentifierCollisionException();
    }
    return identifier;
  }
}
