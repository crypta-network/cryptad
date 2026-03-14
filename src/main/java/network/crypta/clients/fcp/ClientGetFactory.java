package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds fully configured {@link ClientGet} instances from FCP inputs.
 *
 * <p>The factory performs the deterministic wiring for GET requests: it validates identifiers,
 * assembles an appropriate {@link FetchContext}, plans return handling, and packages everything
 * into a {@link ClientGet.ClientGetSetup}. Callers use the resulting request object for
 * registration and execution; the factory does not start or enqueue the request itself. Because it
 * is stateless and uses only local variables, the class is thread-safe and can be called
 * concurrently.
 *
 * <p>The factory is intentionally conservative about side effects: it only logs ignored parameters
 * (such as a legacy charset hint) and throws explicit exceptions for identifier collisions or
 * invalid return targets. This makes it suitable for both connection-scoped requests and global
 * queue requests where persistence and DDA checks are required.
 *
 * <ul>
 *   <li><strong>Validation</strong>: checks identifier uniqueness in the appropriate scope.
 *   <li><strong>Context setup</strong>: clones and adjusts a persistent {@link FetchContext}.
 *   <li><strong>Return planning</strong>: resolves disk/bucket targets and metadata buckets.
 * </ul>
 *
 * @see ClientGet
 * @see ClientGetMessage
 * @see ClientGetReturnPlanner
 */
final class ClientGetFactory {
  /** Logger for configuration-related diagnostics during request construction. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetFactory.class);

  /** Prevents instantiation; this class exposes only static factory helpers. */
  private ClientGetFactory() {}

  /**
   * Creates a persistent, global-queue {@link ClientGet} from a validated configuration.
   *
   * <p>The method derives a persistent {@link FetchContext} from the node core, applies the
   * configuration's limits and flags, and plans the return path according to {@link
   * ClientGet.ReturnType}. It then constructs a {@link ClientGet} instance without starting it. The
   * returned request is ready to be registered with a persistent client and subsequently started.
   *
   * <p>This factory is strict about identifier collisions and output policy. It will throw if the
   * identifier is already in use or if disk output is disallowed by the configured DDA policy.
   *
   * @param globalClient persistent client used for global-queue ownership and id checks.
   * @param uri target {@link FreenetURI} describing the key to fetch; must be non-null.
   * @param requestConfig immutable configuration with limits, flags, and return preferences.
   * @param core node core providing fetch contexts, planners, and bucket factories.
   * @return configured {@link ClientGet} instance ready for registration and start.
   * @throws IdentifierCollisionException if the identifier is already registered globally.
   * @throws NotAllowedException if disk output violates policy or DDA restrictions.
   * @throws IOException if bucket or file initialization fails during setup.
   */
  static ClientGet fromGlobal(
      PersistentRequestClient globalClient,
      FreenetURI uri,
      ClientGet.GlobalRequestConfig requestConfig,
      NodeClientCore core)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    ensureGlobalIdentifierAvailable(globalClient, requestConfig.identifier());
    FetchContext fctx = buildFetchContextForGlobal(core, requestConfig);
    if (requestConfig.charset() != null && LOG.isDebugEnabled()) {
      LOG.debug(
          "Charset parameter is ignored for ClientGet global queue requests: {}",
          requestConfig.charset());
    }
    TransferAccessPort transferAccess = core.getRuntimePorts().transferAccess();
    ClientGetReturnPlanner.ReturnSetup returnSetup =
        ClientGetGetterFactory.planReturnForGlobal(
            requestConfig.identifier(),
            fctx,
            requestConfig.returnType(),
            requestConfig.returnFilename(),
            requestConfig.filterData(),
            transferAccess);
    ClientRequestParams params =
        new ClientRequestParams(
            uri,
            requestConfig.identifier(),
            requestConfig.verbosity(),
            requestConfig.prioClass(),
            (requestConfig.persistRebootOnly()
                ? ClientRequest.Persistence.REBOOT
                : ClientRequest.Persistence.FOREVER),
            requestConfig.realTimeFlag(),
            null,
            true);
    ClientGet.ClientGetSetup requestSetup =
        new ClientGet.ClientGetSetup(
            fctx, returnSetup, requestConfig.returnType(), requestConfig.binaryBlob(), null, core);
    return new ClientGet(params, globalClient, requestSetup);
  }

  /**
   * Creates a connection-scoped or global {@link ClientGet} from a parsed FCP message.
   *
   * <p>The method constructs request parameters from the message, validates identifier scope, and
   * applies message-specific fetch context overrides. It also resolves any requested return targets
   * and optional initial metadata buckets. The request is returned in a configured but not started
   * state, so the caller can register it and schedule execution explicitly.
   *
   * <p>Any bucket creation failures are wrapped into a {@link MessageInvalidException} with an
   * internal-error code to match FCP error reporting expectations.
   *
   * @param handler connection handler supplying scope checks and DDA enforcement hooks.
   * @param message parsed FCP GET message containing identifiers, flags, and limits.
   * @param core node core providing contexts, planners, and bucket factories.
   * @return configured {@link ClientGet} instance ready for registration and start.
   * @throws IdentifierCollisionException if the identifier is already used in scope.
   * @throws MessageInvalidException if validation fails or bucket setup throws I/O errors.
   */
  static ClientGet fromMessage(
      FCPConnectionHandler handler, ClientGetMessage message, NodeClientCore core)
      throws IdentifierCollisionException, MessageInvalidException {
    ClientRequestParams params =
        new ClientRequestParams(
            message.uri,
            message.identifier,
            message.verbosity,
            message.priorityClass,
            message.persistence,
            message.realTimeFlag,
            message.clientToken,
            message.global);
    if (message.persistence == ClientRequest.Persistence.CONNECTION) {
      ensureConnectionIdentifierAvailable(handler, message.identifier);
    }
    FetchContext fctx = buildFetchContextForMessage(core, message);
    TransferAccessPort transferAccess = core.getRuntimePorts().transferAccess();
    ClientGetReturnPlanner.ReturnSetup returnSetup =
        ClientGetGetterFactory.planReturnForMessage(
            message.identifier, message.global, fctx, message, transferAccess, handler);
    Bucket initialMetadata = message.getInitialMetadata();
    try {
      ClientGet.ClientGetSetup requestSetup =
          new ClientGet.ClientGetSetup(
              fctx, returnSetup, message.returnType, message.binaryBlob, initialMetadata, core);
      return new ClientGet(params, handler, requestSetup);
    } catch (IOException e) {
      throw bucketCreationFailure(e, message.identifier, message.global);
    }
  }

  /**
   * Ensures the global identifier is not already registered on the persistent client.
   *
   * <p>This method performs a lightweight lookup against the persistent client map and throws when
   * the identifier is already reserved. When the client is {@code null}, the check is skipped to
   * allow callers to validate other aspects without requiring a backing queue.
   *
   * @param client persistent client whose identifier map is checked for collisions.
   * @param identifier candidate identifier that must be unique in the global queue.
   * @throws IdentifierCollisionException if the identifier is already present.
   */
  private static void ensureGlobalIdentifierAvailable(
      PersistentRequestClient client, String identifier) throws IdentifierCollisionException {
    if (client != null && client.getRequest(identifier) != null) {
      throw new IdentifierCollisionException();
    }
  }

  /**
   * Ensures the connection-scoped identifier is not already in use by the handler.
   *
   * <p>This check protects per-connection namespaces, so multiple requests do not share an
   * identifier. If the handler is {@code null}, the check is skipped to allow callers to validate
   * other parameters first.
   *
   * @param handler connection handler tracking identifiers for the active session.
   * @param identifier candidate identifier that must be unique for the connection.
   * @throws IdentifierCollisionException if the identifier already exists in scope.
   */
  private static void ensureConnectionIdentifierAvailable(
      FCPConnectionHandler handler, String identifier) throws IdentifierCollisionException {
    if (handler != null && handler.requestsByIdentifier.containsKey(identifier)) {
      throw new IdentifierCollisionException();
    }
  }

  /**
   * Builds a {@link FetchContext} for global-queue requests using default persistent settings.
   *
   * <p>The context is cloned from the node core's persistent template and then adjusted with the
   * configuration's limits, datastore flags, and filtering preferences. The returned context is
   * mutable and owned by the caller; further modifications affect only the request being built.
   *
   * @param core node core providing the default persistent fetch context.
   * @param requestConfig configuration containing datastore flags and retry limits.
   * @return configured fetch context instance tailored for this request.
   */
  private static FetchContext buildFetchContextForGlobal(
      NodeClientCore core, ClientGet.GlobalRequestConfig requestConfig) {
    FetchContext fctx = core.getClientContext().getDefaultPersistentFetchContext();
    fctx.setLocalRequestOnly(requestConfig.dsOnly());
    fctx.setIgnoreStore(requestConfig.ignoreDS());
    fctx.setMaxNonSplitfileRetries(requestConfig.maxNonSplitfileRetries());
    fctx.setMaxSplitfileBlockRetries(requestConfig.maxSplitfileRetries());
    fctx.setFilterData(requestConfig.filterData());
    fctx.setMaxOutputLength(requestConfig.maxOutputLength());
    fctx.setMaxTempLength(requestConfig.maxOutputLength());
    fctx.setCanWriteClientCache(requestConfig.writeToClientCache());
    return fctx;
  }

  /**
   * Builds a {@link FetchContext} for message-driven requests with per-message overrides.
   *
   * <p>The context starts from the persistent defaults and is then updated with message-specific
   * retry limits, size limits, allowed MIME types, and USK date hint behavior. The returned context
   * is owned by the caller and can be further adjusted before the request starts.
   *
   * @param core node core providing the default persistent fetch context.
   * @param message the parsed message supplying overrides and allowed MIME type hints.
   * @return configured fetch context instance tailored for the message.
   */
  private static FetchContext buildFetchContextForMessage(
      NodeClientCore core, ClientGetMessage message) {
    FetchContext fctx = core.getClientContext().getDefaultPersistentFetchContext();
    fctx.setLocalRequestOnly(message.dsOnly);
    fctx.setIgnoreStore(message.ignoreDS);
    fctx.setMaxNonSplitfileRetries(message.maxRetries);
    fctx.setMaxSplitfileBlockRetries(message.maxRetries);
    fctx.setMaxOutputLength(message.maxSize);
    fctx.setMaxTempLength(message.maxTempSize);
    fctx.setCanWriteClientCache(message.shouldWriteToClientCache());
    fctx.setFilterData(message.filterData);
    fctx.setIgnoreUSKDatehints(message.ignoreUSKDatehints);
    ClientGetGetterFactory.applyAllowedMimeTypes(fctx, message.allowedMIMETypes);
    return fctx;
  }

  /**
   * Wraps bucket creation failures in a protocol error suitable for FCP clients.
   *
   * <p>The returned {@link MessageInvalidException} preserves the original cause and uses the
   * standard internal-error code so the caller can relay a consistent error message upstream.
   *
   * @param e underlying I/O failure that prevented temporary bucket creation.
   * @param identifier request identifier associated with the failing request.
   * @param global true when the request targets the global queue.
   * @return FCP error wrapper that retains the original cause and identifier.
   */
  private static MessageInvalidException bucketCreationFailure(
      IOException e, String identifier, boolean global) {
    MessageInvalidException mie =
        new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR,
            "Cannot create bucket for temporary storage (out of disk space?): " + e,
            identifier,
            global);
    mie.initCause(e);
    return mie;
  }
}
