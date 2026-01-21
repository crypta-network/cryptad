package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.WeakHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchResult;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.DownloadCache;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.clients.fcp.ClientGet.ReturnType;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.support.Base64;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.NoFreeBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates persistent-request operations for the FCP server and exposes cache lookups.
 *
 * <p>This helper encapsulates the logic for managing reboot and forever queues, global request
 * removal/modification, and the download cache read path. It is constructed once per {@link
 * FCPServer} and holds references to the persistent request root and the global queue clients. The
 * class is intentionally package-private, so the server façade can delegate to it while keeping
 * persistence-specific details localized.
 *
 * <p>The instance uses the {@link ClientContext} job runner for operations that must be serialized
 * against persistent state. Methods that call into {@link PersistentRequestClient} may block until
 * a queued job completes, so callers should avoid invoking them from latency-sensitive threads.
 * Synchronization is limited to the reboot-client map and does not cover the underlying request
 * queues, which manage their own concurrency.
 *
 * <ul>
 *   <li>Registers persistent clients and routes global queue operations.
 *   <li>Schedules persistence-affecting work on the job runner.
 *   <li>Implements {@link DownloadCache} lookups for completed requests.
 * </ul>
 *
 * @see FCPServer
 * @see PersistentRequestClient
 * @see PersistentRequestRoot
 */
final class FcpServerPersistentOps implements DownloadCache {
  /** Logger for persistence operations and cache lookup diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(FcpServerPersistentOps.class);

  /** Prefix used to construct global request identifiers for FProxy-backed fetches. */
  private static final String FPROXY_PREFIX = "FProxy:";

  /** The owning server used for queue coordination and callback wiring. */
  private final FCPServer server;

  /** Client core providing contexts, RNG, and bucket factories. */
  private final NodeClientCore core;

  /** Root registry for forever-persistent clients. */
  private final PersistentRequestRoot persistentRoot;

  /** Reboot-persistent clients keyed by name, weakly referenced. */
  private final WeakHashMap<String, PersistentRequestClient> rebootClientsByName;

  /** Global reboot queue client; created eagerly during construction. */
  private final PersistentRequestClient globalRebootClient;

  /** Global forever queue client sourced from the persistent root. */
  private final PersistentRequestClient globalForeverClient;

  /**
   * Creates a persistence helper bound to the provided server, core, and persistent root.
   *
   * <p>The constructor initializes the reboot-client map, wires the forever-global client from the
   * provided root, and allocates the reboot-global client used for temporary persistence. No
   * network operations occur here; the helper is ready for use immediately after construction.
   *
   * @param server owning server used when scheduling global queue operations.
   * @param core client core supplying contexts, RNG, and storage factories.
   * @param persistentRoot registry for forever-persistent clients and queues.
   */
  FcpServerPersistentOps(
      FCPServer server, NodeClientCore core, PersistentRequestRoot persistentRoot) {
    this.server = server;
    this.core = core;
    this.persistentRoot = persistentRoot;
    this.rebootClientsByName = new WeakHashMap<>();
    this.globalForeverClient = persistentRoot.globalForeverClient;
    this.globalRebootClient =
        new PersistentRequestClient("Global Queue", null, true, null, Persistence.REBOOT, null);
  }

  /**
   * Reloads cached request status for the forever global queue.
   *
   * <p>This helper is typically invoked during startup to rebuild the status cache from the
   * persisted request state. It is a no-op for reboot-only queues but will refresh in-memory status
   * for forever persistence.
   */
  void load() {
    globalForeverClient.updateRequestStatusCache();
  }

  /**
   * Registers or replaces a reboot-persistent client by name.
   *
   * <p>If a client with the same name already exists and is connected, the old connection is closed
   * and replaced with the new handler. The returned client instance is stable across reconnections.
   *
   * @param name stable identifier for the reboot-persistent client; must not be {@code null}.
   * @param handler active connection handler, or {@code null} when reconnecting headless.
   * @return existing or newly created client bound to the provided handler.
   */
  PersistentRequestClient registerRebootClient(String name, FCPConnectionHandler handler) {
    PersistentRequestClient oldClient;
    synchronized (this) {
      oldClient = rebootClientsByName.get(name);
      if (oldClient == null) {
        PersistentRequestClient client =
            new PersistentRequestClient(name, handler, false, null, Persistence.REBOOT, null);
        rebootClientsByName.put(name, client);
        return client;
      } else {
        FCPConnectionHandler oldConn = oldClient.getConnection();
        if (oldConn != null) {
          oldConn.setKilledDupe();
          oldConn.send(new CloseConnectionDuplicateClientNameMessage());
          oldConn.close();
        }
        oldClient.setConnection(handler);
        return oldClient;
      }
    }
  }

  /**
   * Registers a forever-persistent client with the global registry.
   *
   * <p>This delegates to {@link PersistentRequestRoot} to create or reuse the named client. The
   * caller-supplied handler is attached when non-null.
   *
   * @param name stable client name used for persistence lookups; must not be {@code null}.
   * @param handler current connection handler, or {@code null} when detached.
   * @return persistent client instance representing the forever queue for the name.
   */
  PersistentRequestClient registerForeverClient(String name, FCPConnectionHandler handler) {
    return persistentRoot.registerForeverClient(name, handler);
  }

  /**
   * Looks up a forever-persistent client and optionally refreshes its connection binding.
   *
   * <p>Returns {@code null} when no client with the given name exists. The supplied handler is
   * stored when non-null to reattach an active connection.
   *
   * @param name stable client identifier used during registration.
   * @param handler connection handler to attach, or {@code null} to leave unchanged.
   * @return existing client, or {@code null} when no match exists.
   */
  PersistentRequestClient getForeverClient(String name, FCPConnectionHandler handler) {
    return persistentRoot.getForeverClient(name, handler);
  }

  /**
   * Unregisters a client from persistence tracking when it is no longer active.
   *
   * <p>Reboot clients are removed from the local map, while forever clients delegate to the shared
   * {@link PersistentRequestRoot} cleanup logic.
   *
   * @param client client to unregister; must not be {@code null}.
   */
  void unregisterClient(PersistentRequestClient client) {
    if (client.persistence == Persistence.REBOOT) {
      synchronized (this) {
        String name = client.name;
        rebootClientsByName.remove(name);
      }
    } else {
      persistentRoot.maybeUnregisterClient(client);
    }
  }

  /**
   * Returns a snapshot of persistent request status entries across all global queues.
   *
   * <p>The method aggregates status from both reboot and forever queues. If persistence is disabled
   * at the core, a {@link PersistenceDisabledException} is raised to signal that the cache cannot
   * be read safely.
   *
   * @return array of request status entries; never {@code null}.
   * @throws PersistenceDisabledException when persistence is unavailable or disabled.
   */
  RequestStatus[] getGlobalRequests() throws PersistenceDisabledException {
    if (core.killedDatabase()) throw new PersistenceDisabledException();
    List<RequestStatus> v = new ArrayList<>();
    globalRebootClient.addPersistentRequestStatus(v);
    if (globalForeverClient != null) globalForeverClient.addPersistentRequestStatus(v);
    return v.toArray(new RequestStatus[0]);
  }

  /**
   * Removes a single global request and blocks until completion.
   *
   * <p>The method first attempts removal from the reboot queue. If not found, it schedules a
   * removal on the persistent job runner for the forever queue and waits for completion.
   *
   * @param identifier request identifier to remove; must not be {@code null}.
   * @return {@code true} when the request was removed or removal was attempted; {@code false} when
   *     the job failed.
   * @throws PersistenceDisabledException when persistence is unavailable or disabled.
   */
  boolean removeGlobalRequestBlocking(final String identifier) throws PersistenceDisabledException {
    if (!globalRebootClient.removeByIdentifier(identifier, true, server, core.getClientContext())) {
      final CountDownLatch done = new CountDownLatch(1);
      final AtomicBoolean success = new AtomicBoolean();
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP removeGlobalRequestBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  boolean succeeded = false;
                  try {
                    succeeded =
                        globalForeverClient.removeByIdentifier(
                            identifier, true, server, core.getClientContext());
                  } catch (Exception e) {
                    LOG.error("Caught removing identifier {}: {}", identifier, e, e);
                  } finally {
                    success.set(succeeded);
                    done.countDown();
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);
      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return success.get();
      }
      return success.get();
    } else return true;
  }

  /**
   * Removes all global requests and waits for the forever queue removal to complete.
   *
   * <p>The reboot queue is cleared immediately on the calling thread. The forever queue is cleared
   * via a queued persistent job to maintain database consistency.
   *
   * @return {@code true} if both queues were cleared successfully; {@code false} otherwise.
   * @throws PersistenceDisabledException when persistence is unavailable or disabled.
   */
  boolean removeAllGlobalRequestsBlocking() throws PersistenceDisabledException {
    globalRebootClient.removeAll();
    final CountDownLatch done = new CountDownLatch(1);
    final AtomicBoolean success = new AtomicBoolean();
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "FCP removeAllGlobalRequestsBlocking";
              }

              @Override
              public boolean run(ClientContext context) {
                boolean succeeded = false;
                try {
                  globalForeverClient.removeAll();
                  succeeded = true;
                } catch (Exception e) {
                  LOG.error("Caught while processing panic: {}", e, e);
                } finally {
                  success.set(succeeded);
                  done.countDown();
                }
                return true;
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);
    try {
      done.await();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return success.get();
    }
    return success.get();
  }

  /**
   * Updates the token and priority of a global request, blocking until applied.
   *
   * <p>Reboot queue updates occur immediately, while forever queue updates run on the persistent
   * job runner and are synchronized using a wait/notify wrapper.
   *
   * @param identifier request identifier to locate in the queues.
   * @param newToken replacement token string stored with the request; may be {@code null}.
   * @param newPriority new priority class value for scheduling decisions.
   * @return {@code true} when an update path executed; {@code false} when not found or failed.
   * @throws PersistenceDisabledException when persistence is unavailable or disabled.
   */
  boolean modifyGlobalRequestBlocking(
      final String identifier, final String newToken, final short newPriority)
      throws PersistenceDisabledException {
    ClientRequest req = this.globalRebootClient.getRequest(identifier);
    if (req != null) {
      req.modifyRequest(newToken, newPriority, server);
      return true;
    } else {
      class OutputWrapper {
        boolean success;
        boolean done;
      }
      final OutputWrapper ow = new OutputWrapper();
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP modifyGlobalRequestBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  boolean success = false;
                  try {
                    ClientRequest req = globalForeverClient.getRequest(identifier);
                    if (req != null) req.modifyRequest(newToken, newPriority, server);
                    success = true;
                  } finally {
                    synchronized (ow) {
                      ow.success = success;
                      ow.done = true;
                      ow.notifyAll();
                    }
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);

      synchronized (ow) {
        while (true) {
          if (!ow.done) {
            try {
              ow.wait();
            } catch (InterruptedException _) {
              Thread.currentThread().interrupt();
              return ow.success;
            }
            continue;
          }
          return ow.success;
        }
      }
    }
  }

  /**
   * Enqueues a persistent global request and blocks until registration completes.
   *
   * <p>The request creation runs on the persistent job runner to ensure a consistent database
   * state. Exceptions are captured and rethrown once the job finishes.
   *
   * @param params request parameter bundle describing the fetch.
   * @throws NotAllowedException when policy or DDA checks reject the request.
   * @throws IOException when preparing disk output fails.
   * @throws PersistenceDisabledException when persistence is unavailable or disabled.
   */
  void makePersistentGlobalRequestBlocking(PersistentGlobalRequestParams params)
      throws NotAllowedException, IOException, PersistenceDisabledException {
    final CountDownLatch done = new CountDownLatch(1);
    final AtomicReference<NotAllowedException> notAllowed = new AtomicReference<>();
    final AtomicReference<IOException> ioException = new AtomicReference<>();
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "FCP makePersistentGlobalRequestBlocking";
              }

              @Override
              public boolean run(ClientContext context) {
                try {
                  makePersistentGlobalRequest(params);
                  return true;
                } catch (NotAllowedException e) {
                  notAllowed.set(e);
                  return false;
                } catch (IOException e) {
                  ioException.set(e);
                  return false;
                } catch (Exception t) {
                  LOG.error("Failed to make persistent request: {}", t, t);
                  return false;
                } finally {
                  done.countDown();
                }
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);

    try {
      done.await();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
    if (ioException.get() != null) throw ioException.get();
    if (notAllowed.get() != null) throw notAllowed.get();
  }

  /**
   * Convenience overload that builds parameters for a persistent global request.
   *
   * <p>All arguments are forwarded into {@link PersistentGlobalRequestParams} and then queued via
   * {@link #makePersistentGlobalRequestBlocking(PersistentGlobalRequestParams)}.
   *
   * @param fetchURI URI describing the content to fetch; must not be {@code null}.
   * @param filterData whether to filter content before delivery to the client.
   * @param expectedMimeType optional MIME hint for filename selection; may be {@code null}.
   * @param persistenceTypeString persistence policy string such as {@code reboot}.
   * @param returnTypeString return handling string such as {@code disk} or {@code none}.
   * @param realTimeFlag whether to request real-time scheduling.
   * @param downloadsDir directory for disk outputs when the return type is disk.
   * @throws NotAllowedException when policy or DDA checks reject the request.
   * @throws IOException when preparing disk output fails.
   * @throws PersistenceDisabledException when persistence is unavailable or disabled.
   */
  void makePersistentGlobalRequestBlocking(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag,
      File downloadsDir)
      throws NotAllowedException, IOException, PersistenceDisabledException {
    makePersistentGlobalRequestBlocking(
        new PersistentGlobalRequestParams(
            fetchURI,
            filterData,
            expectedMimeType,
            persistenceTypeString,
            returnTypeString,
            realTimeFlag,
            downloadsDir));
  }

  void makePersistentGlobalRequest(PersistentGlobalRequestParams params)
      throws NotAllowedException, IOException {
    boolean persistence = params.persistenceType().equalsIgnoreCase("reboot");
    ReturnType returnType = ReturnType.valueOf(params.returnType().toUpperCase());
    File returnFilename = null;
    if (returnType == ReturnType.DISK) {
      returnFilename =
          makeReturnFilename(params.fetchURI(), params.expectedMimeType(), params.downloadsDir());
    }
    List<String> candidateIds = new ArrayList<>();
    candidateIds.add(FPROXY_PREFIX + params.fetchURI().getPreferredFilename());
    candidateIds.add(FPROXY_PREFIX + params.fetchURI().getDocName());
    candidateIds.add(FPROXY_PREFIX + params.fetchURI().toString(false, false));
    candidateIds.add("FProxy (" + System.currentTimeMillis() + ')');

    for (String candidateId : candidateIds) {
      if (candidateId == null) {
        continue;
      }
      PersistentGlobalRequestSpec spec =
          new PersistentGlobalRequestSpec(
              params.fetchURI(),
              params.filterData(),
              persistence,
              returnType,
              candidateId,
              returnFilename,
              params.realTimeFlag());
      if (tryPersistentGlobalRequest(spec)) {
        return;
      }
    }

    while (true) {
      byte[] buf = new byte[8];
      core.getRandom().nextBytes(buf);
      String id = FPROXY_PREFIX + Base64.encode(buf);
      PersistentGlobalRequestSpec spec =
          new PersistentGlobalRequestSpec(
              params.fetchURI(),
              params.filterData(),
              persistence,
              returnType,
              id,
              returnFilename,
              params.realTimeFlag());
      if (tryPersistentGlobalRequest(spec)) {
        return;
      }
    }
  }

  void makePersistentGlobalRequest(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag)
      throws NotAllowedException, IOException {
    makePersistentGlobalRequest(
        new PersistentGlobalRequestParams(
            fetchURI,
            filterData,
            expectedMimeType,
            persistenceTypeString,
            returnTypeString,
            realTimeFlag,
            core.getDownloadsDir()));
  }

  void makePersistentGlobalRequest(
      FreenetURI fetchURI,
      boolean filterData,
      String expectedMimeType,
      String persistenceTypeString,
      String returnTypeString,
      boolean realTimeFlag,
      File downloadsDir)
      throws NotAllowedException, IOException {
    makePersistentGlobalRequest(
        new PersistentGlobalRequestParams(
            fetchURI,
            filterData,
            expectedMimeType,
            persistenceTypeString,
            returnTypeString,
            realTimeFlag,
            downloadsDir));
  }

  private boolean tryPersistentGlobalRequest(PersistentGlobalRequestSpec spec)
      throws NotAllowedException, IOException {
    try {
      innerMakePersistentGlobalRequest(spec);
      return true;
    } catch (IdentifierCollisionException _) {
      return false;
    }
  }

  private File makeReturnFilename(FreenetURI uri, String expectedMimeType, File downloadsDir) {
    String ext;
    if ((expectedMimeType != null)
        && !expectedMimeType.isEmpty()
        && !expectedMimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE)) {
      ext = DefaultMIMETypes.getExtension(expectedMimeType);
    } else ext = null;
    String extAdd = (ext == null ? "" : '.' + ext);
    String preferred = uri.getPreferredFilename();
    String preferredWithExt = preferred;
    if (!(ext != null && preferredWithExt.endsWith(ext))) preferredWithExt += extAdd;
    File f = new File(downloadsDir, preferredWithExt);
    int x = 0;
    StringBuilder sb = new StringBuilder();
    for (; f.exists(); sb.setLength(0)) {
      sb.append(preferred);
      sb.append('-');
      sb.append(x);
      sb.append(extAdd);
      f = new File(downloadsDir, sb.toString());
      x++;
    }
    return f;
  }

  private void innerMakePersistentGlobalRequest(PersistentGlobalRequestSpec spec)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    FetchContext defaultFetchContext = core.getClientContext().getDefaultPersistentFetchContext();
    ClientGet.GlobalRequestConfig requestConfig =
        new ClientGet.GlobalRequestConfig(
            defaultFetchContext.getLocalRequestOnly(),
            defaultFetchContext.getIgnoreStore(),
            spec.filterData(),
            FCPServer.QUEUE_MAX_RETRIES,
            FCPServer.QUEUE_MAX_RETRIES,
            FCPServer.QUEUE_MAX_DATA_SIZE,
            spec.returnType(),
            spec.persistRebootOnly(),
            spec.identifier(),
            Integer.MAX_VALUE,
            RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
            spec.returnFilename(),
            null,
            false,
            spec.realTimeFlag(),
            false);
    final ClientGet cg =
        new ClientGet(
            spec.persistRebootOnly() ? globalRebootClient : globalForeverClient,
            spec.fetchURI(),
            requestConfig,
            core);
    cg.register(false);
    cg.start(core.getClientContext());
  }

  PersistentRequestClient getGlobalForeverClient() {
    return globalForeverClient;
  }

  ClientRequest getGlobalRequest(String identifier) {
    ClientRequest req = globalRebootClient.getRequest(identifier);
    if (req == null) req = globalForeverClient.getRequest(identifier);
    return req;
  }

  void setCompletionCallback(RequestCompletionCallback cb) {
    if (globalForeverClient != null) globalForeverClient.addRequestCompletionCallback(cb);
    globalRebootClient.addRequestCompletionCallback(cb);
  }

  void startBlocking(final ClientRequest req)
      throws IdentifierCollisionException, PersistenceDisabledException {
    if (req.persistence == Persistence.REBOOT) {
      req.start(core.getClientContext());
    } else {
      final CountDownLatch done = new CountDownLatch(1);
      final AtomicReference<IdentifierCollisionException> collision = new AtomicReference<>();
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP startBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  try {
                    req.register(false);
                    req.start(context);
                  } catch (IdentifierCollisionException e) {
                    collision.set(e);
                  } finally {
                    done.countDown();
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);

      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      if (collision.get() != null) {
        throw collision.get();
      }
    }
  }

  boolean restartBlocking(final String identifier, final boolean disableFilterData)
      throws PersistenceDisabledException {
    ClientRequest req = globalRebootClient.getRequest(identifier);
    if (req != null) {
      req.restart(core.getClientContext(), disableFilterData);
      return true;
    } else {
      final CountDownLatch done = new CountDownLatch(1);
      final AtomicBoolean success = new AtomicBoolean();
      if (LOG.isDebugEnabled()) LOG.debug("Queueing restart of {}", identifier);
      core.getClientContext()
          .jobRunner
          .queue(
              new PersistentJob() {

                @Override
                public String toString() {
                  return "FCP restartBlocking";
                }

                @Override
                public boolean run(ClientContext context) {
                  boolean restarted = false;
                  try {
                    ClientRequest req = globalForeverClient.getRequest(identifier);
                    if (LOG.isDebugEnabled()) LOG.debug("Restarting {} for {}", req, identifier);
                    if (req != null) {
                      req.restart(context, disableFilterData);
                      restarted = true;
                    }
                  } catch (PersistenceDisabledException e) {
                    LOG.error("Failed to restart {}: {}", identifier, e.getMessage(), e);
                  } finally {
                    success.set(restarted);
                    done.countDown();
                  }
                  return true;
                }
              },
              NativeThread.PriorityLevel.HIGH_PRIORITY.value);

      try {
        done.await();
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
      }
      return success.get();
    }
  }

  FetchResult getCompletedRequestBlocking(final FreenetURI key)
      throws PersistenceDisabledException {
    ClientGet get = globalRebootClient.getCompletedRequest(key);
    if (get != null) {
      return new FetchResult(
          new ClientMetadata(get.getMIMEType()), new NoFreeBucket(get.getBucket()));
    }

    FetchResult result = globalForeverClient.getRequestStatusCache().getShadowBucket(key, false);
    if (result != null) {
      return result;
    }

    final CountDownLatch done = new CountDownLatch(1);
    final AtomicReference<FetchResult> resultRef = new AtomicReference<>();
    core.getClientContext()
        .jobRunner
        .queue(
            new PersistentJob() {

              @Override
              public String toString() {
                return "FCP getCompletedRequestBlocking";
              }

              @Override
              public boolean run(ClientContext context) {
                try {
                  resultRef.set(lookup(key, false, context, false, null));
                } finally {
                  done.countDown();
                }
                return false;
              }
            },
            NativeThread.PriorityLevel.HIGH_PRIORITY.value);

    try {
      done.await();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
    return resultRef.get();
  }

  @Override
  public CacheFetchResult lookupInstant(
      FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred) {
    ClientGet get = globalRebootClient.getCompletedRequest(key);

    Bucket origData = null;
    String mime = null;
    boolean filtered = false;

    if (get != null) {
      boolean requestFiltered = get.filterData();
      if ((!noFilter) || (!requestFiltered)) {
        filtered = requestFiltered;
        origData = new NoFreeBucket(get.getBucket());
        mime = get.getMIMEType();
      }
    }

    if (origData == null && globalForeverClient != null) {
      CacheFetchResult result =
          globalForeverClient.getRequestStatusCache().getShadowBucket(key, noFilter);
      if (result != null) {
        mime = result.getMimeType();
        origData = result.asBucket();
        filtered = result.alreadyFiltered;
      }
    }

    if (origData == null) return null;

    if (!mustCopy) return new CacheFetchResult(new ClientMetadata(mime), origData, filtered);

    Bucket newData = preferred;
    try {
      if (newData == null) newData = core.getTempBucketFactory().makeBucket(origData.size());
      BucketTools.copy(origData, newData);
      if (origData.size() != newData.size()) {
        LOG.info("Maybe it disappeared under us?");
        newData.free();
        return null;
      }
      return new CacheFetchResult(new ClientMetadata(mime), newData, filtered);
    } catch (IOException e) {
      LOG.info("Unable to copy data: {}", e, e);
      return null;
    }
  }

  @Override
  public CacheFetchResult lookup(
      FreenetURI key, boolean noFilter, ClientContext context, boolean mustCopy, Bucket preferred) {
    if (globalForeverClient == null) return null;
    ClientGet get = globalForeverClient.getCompletedRequest(key);
    if (get != null) {
      boolean filtered = get.filterData();
      Bucket origData = get.getBucket();
      Bucket newData = null;
      if (!mustCopy) newData = origData.createShadow();
      if (newData == null) {
        try {
          if (preferred != null) newData = preferred;
          else newData = core.getTempBucketFactory().makeBucket(origData.size());
          BucketTools.copy(origData, newData);
        } catch (IOException e) {
          LOG.error("Unable to copy data: {}", e, e);
          return null;
        }
      }
      return new CacheFetchResult(new ClientMetadata(get.getMIMEType()), newData, filtered);
    }
    return null;
  }

  PersistentRequestClient getGlobalRebootClient() {
    return globalRebootClient;
  }
}
