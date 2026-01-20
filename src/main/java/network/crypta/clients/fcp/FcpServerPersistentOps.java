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

final class FcpServerPersistentOps implements DownloadCache {
  private static final Logger LOG = LoggerFactory.getLogger(FcpServerPersistentOps.class);
  private static final String FPROXY_PREFIX = "FProxy:";

  private final FCPServer server;
  private final NodeClientCore core;
  private final PersistentRequestRoot persistentRoot;
  private final WeakHashMap<String, PersistentRequestClient> rebootClientsByName;
  private final PersistentRequestClient globalRebootClient;
  private final PersistentRequestClient globalForeverClient;

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

  void load() {
    globalForeverClient.updateRequestStatusCache();
  }

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

  PersistentRequestClient registerForeverClient(String name, FCPConnectionHandler handler) {
    return persistentRoot.registerForeverClient(name, handler);
  }

  PersistentRequestClient getForeverClient(String name, FCPConnectionHandler handler) {
    return persistentRoot.getForeverClient(name, handler);
  }

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

  RequestStatus[] getGlobalRequests() throws PersistenceDisabledException {
    if (core.killedDatabase()) throw new PersistenceDisabledException();
    List<RequestStatus> v = new ArrayList<>();
    globalRebootClient.addPersistentRequestStatus(v);
    if (globalForeverClient != null) globalForeverClient.addPersistentRequestStatus(v);
    return v.toArray(new RequestStatus[0]);
  }

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
