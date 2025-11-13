package network.crypta.client.async;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.Metadata.SimpleManifestComposer;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class responsible for inserting a directory tree (a “manifest”) into the network. Subclasses
 * supply the “packing” strategy in {@link #makePutHandlers(HashMap, String)} while this class
 * coordinates asynchronous puts, metadata resolution, and container construction.
 *
 * <p>Usage overview: callers construct a concrete implementation, provide a map describing the
 * manifest structure and a default document, and then call {@link #start(ClientContext)}. The class
 * orchestrates insertion of files either directly (“freeform mode”) or inside one or more
 * containers (“container mode”), resolves metadata too large for inlining, and finally exposes the
 * resulting top-level {@link FreenetURI} via {@link #getURI()} and callbacks.
 *
 * <p>Design notes and invariants:
 *
 * <ul>
 *   <li>Internal container references are always redirects to CHK URIs; we never embed large
 *       metadata directly when it would hinder updates or reuse.
 *   <li>Container reuse between editions is assumed; having stable CHK-based redirects simplifies
 *       incremental updates and archival behavior.
 *   <li>Concurrency: multiple file puts and container builds may run concurrently; state
 *       transitions are synchronized at the handler level to ensure consistent completion and
 *       fetchability signaling.
 * </ul>
 *
 * <p>Operating modes:
 *
 * <dl>
 *   <dt>Container mode
 *   <dd>Metadata for items are stored inside a root container; the final URI points at that
 *       container’s archive.
 *   <dt>Freeform mode
 *   <dd>Metadata are inserted separately and referenced from a top-level manifest; the final URI
 *       points to a {@code SimpleManifest}.
 * </dl>
 *
 * <p>WARNING: Changing non-transient members on {@link java.io.Serializable} classes can cause
 * downloads to restart or uploads to be lost on persisted jobs.
 *
 * @see PlainManifestPutter
 * @see DefaultManifestPutter
 */
public abstract class BaseManifestPutter extends ManifestPutter {
  private static final Logger LOG = LoggerFactory.getLogger(BaseManifestPutter.class);

  @Serial private static final long serialVersionUID = 1L;

  // Shared log message patterns to avoid duplication (Sonar java:S1192)
  private static final String LOG_ON_ENCODE_FOR = "onEncode({}) for {}";
  private static final String LOG_COMPLETED_FOR = "Completed '{}' {}";
  private static final String DEBUG_STRING = "debug";

  @Override
  @SuppressWarnings("RedundantMethodOverride")
  public boolean equals(Object obj) {
    return this == obj;
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }

  /**
   * ArchivePutHandler - wrapper for ContainerInserter
   *
   * <p>Archives are not part of the site structure, they are used to group files that not fit into
   * a container (for example a directory with a bazillion files in it) Archives are always inserted
   * as CHK, references to items in it are normal redirects to CHK@blah,blub,AA/nameinarchive
   */
  private final class ArchivePutHandler extends PutHandler {

    @Serial private static final long serialVersionUID = 1L;

    private ArchivePutHandler(
        BaseManifestPutter bmp,
        PutHandler parent,
        String name,
        HashMap<String, Object> data,
        FreenetURI insertURI) {
      super(bmp, parent, name, null, containerPutHandlers);
      this.origSFI =
          new ContainerInserter(
              this,
              this,
              data,
              insertURI,
              ctx,
              new ContainerInserter.Options(
                  false,
                  false,
                  null,
                  ARCHIVE_TYPE.TAR,
                  forceCryptoKey,
                  cryptoAlgorithm,
                  realTimeFlag));
    }

    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled())
        LOG.debug(LOG_ON_ENCODE_FOR, key.getURI().toString(false, false), this);

      synchronized (BaseManifestPutter.this) {
        // transform the placeholders to redirects (redirects to 'uri/name') and
        // remove from waitfor lists
        ArrayList<PutHandler> phv = putHandlersArchiveTransformMap.get(this);
        if (phv == null) return; // Already encoded.
        for (PutHandler ph : phv) {
          Map<String, Object> hm = putHandlersTransformMap.get(ph);
          perContainerPutHandlersWaitingForMetadata.get(ph.parentPutHandler).remove(ph);
          if (ph.targetInArchive == null) throw new NullPointerException();
          Metadata m =
              new Metadata(
                  DocumentType.SIMPLE_REDIRECT,
                  null,
                  null,
                  key.getURI().setMetaString(new String[] {ph.targetInArchive}),
                  cm);
          hm.put(ph.itemName, m);
          putHandlersTransformMap.remove(ph);
          try {
            tryStartParentContainer(ph.parentPutHandler, context);
          } catch (InsertException e) {
            fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
            return;
          }
        }
        putHandlersArchiveTransformMap.remove(this);
      }
    }

    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug(LOG_COMPLETED_FOR, this.itemName, this);
      if (!containerPutHandlers.remove(this))
        throw new IllegalStateException("was not in containerPutHandlers");

      super.onSuccess(state, context);
    }
  }

  /**
   * ContainerPutHandler - wrapper for ContainerInserter
   *
   * <p>Containers are an integral part of the site structure, they are inserted as CHK, the root
   * container is inserted at targetURI. references to items in it are ARCHIVE_INTERNAL_REDIRECT
   */
  private final class ContainerPutHandler extends PutHandler {

    @Serial private static final long serialVersionUID = 1L;

    private ContainerPutHandler(
        BaseManifestPutter bmp,
        PutHandler parent,
        String name,
        HashMap<String, Object> data,
        FreenetURI insertURI,
        HashSet<PutHandler> runningMap) {
      super(bmp, parent, name, null, runningMap);
      this.origSFI =
          new ContainerInserter(
              this,
              this,
              data,
              insertURI,
              ctx,
              new ContainerInserter.Options(
                  false,
                  false,
                  null,
                  ARCHIVE_TYPE.TAR,
                  forceCryptoKey,
                  cryptoAlgorithm,
                  realTimeFlag));
    }

    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled())
        LOG.debug(LOG_ON_ENCODE_FOR, key.getURI().toString(false, false), this);

      if (rootContainerPutHandler == this) {
        finalURI = key.getURI();
        cb.onGeneratedURI(finalURI, this);
      } else {
        synchronized (BaseManifestPutter.this) {
          Map<String, Object> hm = putHandlersTransformMap.get(this);
          perContainerPutHandlersWaitingForMetadata.get(parentPutHandler).remove(this);
          Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, key.getURI(), cm);
          hm.put(this.itemName, m);
          putHandlersTransformMap.remove(this);

          try {
            tryStartParentContainer(parentPutHandler, context);
          } catch (InsertException e) {
            fail(e, context);
          }
        }
      }
    }

    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug(LOG_COMPLETED_FOR, this.itemName, this);

      if (rootContainerPutHandler == this) {
        if (containerPutHandlers.contains(this))
          throw new IllegalStateException("was in containerPutHandlers");
        rootContainerPutHandler = null;
      } else {
        if (!containerPutHandlers.remove(this))
          throw new IllegalStateException("was not in containerPutHandlers");
      }
      super.onSuccess(state, context);
    }
  }

  private final class ExternPutHandler extends PutHandler {

    @Serial private static final long serialVersionUID = 1L;

    private ExternPutHandler(
        BaseManifestPutter bmp,
        PutHandler parent,
        String name,
        RandomAccessBucket data,
        ClientMetadata cm2) {
      super(bmp, parent, name, cm2, runningPutHandlers);
      InsertBlock block = new InsertBlock(data, cm, FreenetURI.EMPTY_CHK_URI);
      this.origSFI =
          new SingleFileInserter(
              this,
              this,
              block,
              false,
              ctx,
              realTimeFlag,
              false,
              true,
              null,
              null,
              false,
              null,
              false,
              persistent(),
              0,
              0,
              null,
              cryptoAlgorithm,
              forceCryptoKey,
              -1);
    }

    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug(LOG_ON_ENCODE_FOR, key, this);

      if (metadata != null) {
        LOG.warn("Reassigning metadata: {}", metadata);
      }
      // The file was too small to have its own metadata, we get this instead.
      // So we make the key into metadata.
      Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, key.getURI(), cm);
      onMetadata(m, state, context);
    }

    @Override
    public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Assigning metadata: {} for '{}' {} from {} persistent={}",
            m,
            this.itemName,
            this,
            state,
            persistent);
      if (metadata != null) {
        LOG.warn("Reassigning metadata");
        return;
      }
      metadata = m;

      if (freeformMode) {
        handleFreeformOnMetadata(m, context);
      } else if (containerMode) {
        handleContainerOnMetadata(m, context);
      } else {
        throw new IllegalStateException("Neiter container nor freeform mode. Hu?");
      }
    }

    private void handleFreeformOnMetadata(Metadata m, ClientContext context) {
      boolean allMetadatas;
      synchronized (BaseManifestPutter.this) {
        putHandlersWaitingForMetadata.remove(this);
        allMetadatas = putHandlersWaitingForMetadata.isEmpty();
        if (!allMetadatas && LOG.isDebugEnabled())
          LOG.debug("Still waiting for metadata: {}", putHandlersWaitingForMetadata.size());
      }
      if (allMetadatas) {
        gotAllMetadata(context);
        return;
      }
      try {
        if (m.writtenLength() > Metadata.MAX_SIZE_IN_MANIFEST)
          throw new MetadataUnresolvedException(new Metadata[] {m}, "Too big");
      } catch (MetadataUnresolvedException e) {
        try {
          resolve(e, context);
        } catch (IOException e1) {
          fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e1, null), context);
        } catch (InsertException e1) {
          fail(e1, context);
        }
      }
    }

    private void handleContainerOnMetadata(Metadata m, ClientContext context) {
      Map<String, Object> hm = putHandlersTransformMap.get(this);
      perContainerPutHandlersWaitingForMetadata.get(parentPutHandler).remove(this);
      hm.put(this.itemName, m);
      putHandlersTransformMap.remove(this);
      try {
        tryStartParentContainer(parentPutHandler, context);
      } catch (InsertException e) {
        fail(e, context);
      }
    }

    // Inherit onSuccess behavior from PutHandler
  }

  // metadata inserter / resolver
  // these MPH are usually created on demand, so they are outside (main)constructor
  private final class MetaPutHandler extends PutHandler {

    // Metadata is not put with a cryptokey. It is derived from other stuff that is already
    // encrypted with random keys.

    @Serial private static final long serialVersionUID = 1L;

    // final metadata
    private MetaPutHandler(BaseManifestPutter smp, PutHandler parent, InsertBlock insertBlock) {
      super(smp, parent, null, null, null);
      // Treat as splitfile for purposes of determining number of reinserts.
      this.origSFI =
          new SingleFileInserter(
              this,
              this,
              insertBlock,
              true,
              ctx,
              realTimeFlag,
              false,
              false,
              null,
              null,
              true,
              null,
              true,
              persistent(),
              0,
              0,
              null,
              cryptoAlgorithm,
              null,
              -1);
      if (LOG.isDebugEnabled()) LOG.debug("Inserting root metadata: {}", origSFI);
    }

    // resolver
    private MetaPutHandler(
        BaseManifestPutter smp, PutHandler parent, Metadata toResolve, BucketFactory bf)
        throws MetadataUnresolvedException, IOException {
      super(smp, parent, null, null, runningPutHandlers);
      RandomAccessBucket b = toResolve.toBucket(bf);
      metadata = toResolve;
      // Treat as splitfile for purposes of determining number of reinserts.
      InsertBlock ib = new InsertBlock(b, null, FreenetURI.EMPTY_CHK_URI);
      this.origSFI =
          new SingleFileInserter(
              this,
              this,
              ib,
              true,
              ctx,
              realTimeFlag,
              false,
              false,
              toResolve,
              null,
              true,
              null,
              true,
              persistent(),
              0,
              0,
              null,
              cryptoAlgorithm,
              null,
              -1);
      if (LOG.isDebugEnabled())
        LOG.debug("Inserting subsidiary metadata: {} for {}", origSFI, toResolve);
    }

    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled())
        LOG.debug(LOG_ON_ENCODE_FOR, key.getURI().toString(false, false), this);

      if (rootMetaPutHandler == this) {
        finalURI = key.getURI();
        cb.onGeneratedURI(finalURI, this);
        return;
      }

      metadata.resolve(key.getURI());
    }

    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      boolean wasRoot = false;
      synchronized (BaseManifestPutter.this) {
        if (rootMetaPutHandler == this) {
          rootMetaPutHandler = null;
          wasRoot = true;
        }
      }
      if (!wasRoot) resolveAndStartBase(context);
      super.onSuccess(state, context);
    }
  }

  /** Placeholder for Metadata, don't run it! */
  private final class JokerPutHandler extends PutHandler {

    @Serial private static final long serialVersionUID = 1L;

    /** a normal ( freeform) redirect */
    public JokerPutHandler(
        BaseManifestPutter bmp, String name, FreenetURI targetURI2, ClientMetadata cm2) {
      super(bmp, null, name, null, null, cm2);
      metadata = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI2, cm2);
    }

    /** an archive redirect */
    public JokerPutHandler(
        BaseManifestPutter bmp, PutHandler parent, String name, ClientMetadata cm2) {
      super(bmp, parent, name, name, null, cm2);
    }

    /** a short symlink */
    public JokerPutHandler(BaseManifestPutter bmp, PutHandler parent, String name, String target) {
      super(bmp, parent, name, name, null, null);
      metadata = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, target, null);
    }
  }

  // Only implements PutCompletionCallback for the final metadata insert
  abstract class PutHandler extends BaseClientPutter implements PutCompletionCallback {

    @Serial private static final long serialVersionUID = 1L;

    @Override
    @SuppressWarnings("RedundantMethodOverride")
    public boolean equals(Object obj) {
      return this == obj;
    }

    @Override
    public int hashCode() {
      return super.hashCode();
    }

    // run me
    private PutHandler(
        final BaseManifestPutter bmp,
        PutHandler parent,
        String name,
        ClientMetadata cm,
        HashSet<PutHandler> runningMap) {
      super(bmp.priorityClass, bmp.cb.getRequestClient());
      this.persistent = bmp.persistent();
      this.cm = cm;
      this.itemName = name;
      metadata = null;
      parentPutHandler = parent;

      if (runningMap != null) registerInRunningMap(runningMap);

      synchronized (putHandlerWaitingForBlockSets) {
        if (putHandlerWaitingForBlockSets.contains(this)) {
          LOG.warn("PutHandler already in 'waitingForBlockSets'!");
        } else {
          putHandlerWaitingForBlockSets.add(this);
        }
      }

      synchronized (putHandlersWaitingForFetchable) {
        if (putHandlersWaitingForFetchable.contains(this)) {
          LOG.warn("PutHandler already in 'waitingForFetchable'!");
        } else {
          putHandlersWaitingForFetchable.add(this);
        }
      }
    }

    private void registerInRunningMap(HashSet<PutHandler> runningMap) {
      // Avoid synchronizing on a local variable; synchronize on the owning field directly.
      if (runningMap == containerPutHandlers) {
        synchronized (containerPutHandlers) {
          if (containerPutHandlers.contains(this)) {
            LOG.warn("PutHandler already in 'runningMap': {}", containerPutHandlers);
          } else {
            containerPutHandlers.add(this);
          }
        }
      } else { // runningMap == runningPutHandlers
        synchronized (runningPutHandlers) {
          if (runningPutHandlers.contains(this)) {
            LOG.warn("PutHandler already in 'runningMap': {}", runningPutHandlers);
          } else {
            runningPutHandlers.add(this);
          }
        }
      }
    }

    // placeholder, don't run it
    private PutHandler(
        final BaseManifestPutter bmp,
        PutHandler parent,
        String name,
        String nameInArchive,
        Metadata md,
        ClientMetadata cm) {
      super(bmp.priorityClass, bmp.cb.getRequestClient());
      this.persistent = bmp.persistent();
      this.cm = cm;
      this.itemName = name;
      this.origSFI = null;
      metadata = md;
      parentPutHandler = parent;
      this.targetInArchive = nameInArchive;
    }

    @SuppressWarnings("java:S1948")
    protected ClientPutState origSFI;

    @SuppressWarnings("java:S1948")
    private ClientPutState currentState;

    protected ClientMetadata cm;
    protected Metadata metadata;
    private String targetInArchive;
    protected final String itemName;
    protected final boolean persistent;
    protected final PutHandler parentPutHandler;

    public void start(ClientContext context) throws InsertException {
      if (LOG.isTraceEnabled()) LOG.trace("Starting a PutHandler for '{}' {}", this.itemName, this);

      if (origSFI == null) {
        failOuter(new IllegalStateException("origSFI is null on start(), impossible"), context);
      }

      if ((!(this instanceof MetaPutHandler)) && (metadata != null)) {
        failOuter(
            new IllegalStateException("metdata=" + metadata + " on start(), impossible"), context);
      }
      validatePlacement();
      validateWaitingForBlockSets();

      ClientPutState sfi;
      synchronized (this) {
        sfi = origSFI;
        currentState = sfi;
        origSFI = null;
      }
      sfi.schedule(context);
    }

    private void validatePlacement() {
      boolean ok;
      if ((this instanceof ContainerPutHandler) || (this instanceof ArchivePutHandler)) {
        if (this != rootContainerPutHandler) {
          synchronized (containerPutHandlers) {
            ok = containerPutHandlers.contains(this);
          }
          if (!ok) {
            throw new IllegalStateException(
                "Starting a PutHandler thats not in 'containerPutHandlers'! " + this);
          }
        }
      } else {
        if (this != rootMetaPutHandler) {
          synchronized (runningPutHandlers) {
            ok = runningPutHandlers.contains(this);
          }
          if (!ok) {
            throw new IllegalStateException(
                "Starting a PutHandler thats not in 'runningPutHandlers'! " + this);
          }
        }
      }
    }

    private void validateWaitingForBlockSets() {
      boolean ok;
      synchronized (putHandlerWaitingForBlockSets) {
        ok = putHandlerWaitingForBlockSets.contains(this);
      }
      if (!ok) {
        LOG.error(
            "Starting a PutHandler thats not in 'waitingForBlockSets'! {}",
            this,
            new Error("error"));
      }
    }

    @Override
    public void cancel(ClientContext context) {
      if (LOG.isDebugEnabled()) LOG.debug("Cancelling {}", this);
      ClientPutState oldState;
      synchronized (this) {
        if (cancelled) return;
        super.cancel();
        oldState = currentState;
      }
      if (oldState != null) oldState.cancel(context);
      onFailure(new InsertException(InsertExceptionMode.CANCELLED), oldState, context);
    }

    @Override
    public FreenetURI getURI() {
      return null;
    }

    @Override
    public boolean isFinished() {
      if (LOG.isDebugEnabled()) LOG.debug("Finished {}", this);
      return BaseManifestPutter.this.finished || cancelled || BaseManifestPutter.this.cancelled;
    }

    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      if (LOG.isDebugEnabled()) {
        // temp hack, ignored if called via super
        Throwable t = new Throwable("DEBUG onSuccess");
        StackTraceElement te = t.getStackTrace()[1];
        if (!("BaseManifestPutter.java".equals(te.getFileName())
            && "onSuccess".equals(te.getMethodName()))) {
          LOG.error("Not called via super", t);
        }
        // temp hack end
      }

      if (LOG.isDebugEnabled()) LOG.debug(LOG_COMPLETED_FOR, this.itemName, this);

      if (putHandlersWaitingForFetchable.contains(this)) this.maybeNotifyFetchable();

      synchronized (this) {
        currentState = null;
      }
      synchronized (BaseManifestPutter.this) {
        runningPutHandlers.remove(this);
        if (putHandlersWaitingForMetadata.remove(this)) {
          LOG.error(
              "PutHandler '{}' was in waitingForMetadata in onSuccess() on {} for {}",
              this.itemName,
              this,
              BaseManifestPutter.this,
              new Error(DEBUG_STRING));
        }

        if (putHandlerWaitingForBlockSets.remove(this)) {
          LOG.error(
              "PutHandler was in waitingForBlockSets in onSuccess() on {} for {}",
              this,
              BaseManifestPutter.this,
              new Error(DEBUG_STRING));
        }
        if (putHandlersWaitingForFetchable.remove(this)) {
          LOG.error(
              "PutHandler was in waitingForFetchable in onSuccess() on {} for {}",
              this,
              BaseManifestPutter.this,
              new Error(DEBUG_STRING));
        }

        if (!runningPutHandlers.isEmpty() && LOG.isDebugEnabled()) {
          LOG.debug("Running put handlers: {}", runningPutHandlers.size());
          for (Object o : runningPutHandlers) {
            LOG.debug("Still running: {}", o);
          }
        }
      }
      tryCompleteOuter();
    }

    @Override
    public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
      synchronized (this) {
        currentState = null;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Failed: {} - {}", this, e, e);
      fail(e, context);
    }

    private void failOuter(Exception e, ClientContext context) {
      BaseManifestPutter.this.fail(
          new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
    }

    private void tryCompleteOuter() {
      if (LOG.isTraceEnabled()) LOG.trace("try complete");
      synchronized (BaseManifestPutter.this) {
        if (finished || cancelled) {
          if (LOG.isDebugEnabled()) LOG.debug("Already {}", finished ? "finished" : "cancelled");
          return;
        }
        if (hasOutstandingWork()) return;
        finished = true;
      }
      // complete(): notify success
      cb.onSuccess(BaseManifestPutter.this);
    }

    private boolean hasOutstandingWork() {
      return hasRunningWork() || hasContainerWork() || hasRootWork();
    }

    private boolean hasRunningWork() {
      if (!runningPutHandlers.isEmpty()) {
        if (LOG.isTraceEnabled()) LOG.trace("Not finished, runningPutHandlers not empty.");
        return true;
      }
      return false;
    }

    private boolean hasContainerWork() {
      if (!containerPutHandlers.isEmpty()) {
        if (LOG.isTraceEnabled()) LOG.trace("Not finished, containerPutHandlers not empty.");
        return true;
      }
      return false;
    }

    private boolean hasRootWork() {
      if (containerMode) {
        if (rootContainerPutHandler != null) {
          if (LOG.isTraceEnabled()) LOG.trace("Not finished, rootContainerPutHandler not empty.");
          return true;
        }
      } else {
        if (rootMetaPutHandler != null) {
          if (LOG.isTraceEnabled()) LOG.trace("Not finished, rootMetaPutHandler not empty.");
          return true;
        }
      }
      return false;
    }

    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void onTransition(
        ClientPutState oldState, ClientPutState newState, ClientContext context) {
      if (newState == null) throw new NullPointerException();

      // onTransition is *not* responsible for removing the old state, the caller is.
      synchronized (this) {
        if (currentState == oldState) {
          currentState = newState;
          if (LOG.isDebugEnabled())
            LOG.debug(
                "onTransition: cur={}, old={}, new={} for {}",
                currentState,
                oldState,
                newState,
                this);
          return;
        }
        LOG.error(
            "Ignoring onTransition: cur={}, old={}, new={} for {}",
            currentState,
            oldState,
            newState,
            this);
      }
    }

    @Override
    public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
      throw new UnsupportedOperationException();
    }

    /**
     * The number of blocks that will be needed to fetch the data. We put this in the top block
     * metadata.
     */
    protected int minSuccessFetchBlocks;

    @Override
    public void addBlock() {
      BaseManifestPutter.this.addBlock();
      synchronized (this) {
        minSuccessFetchBlocks++;
      }
    }

    @Override
    public void addBlocks(int num) {
      BaseManifestPutter.this.addBlocks(num);
      synchronized (this) {
        minSuccessFetchBlocks += num;
      }
    }

    @Override
    public void completedBlock(boolean dontNotify, ClientContext context) {
      BaseManifestPutter.this.completedBlock(dontNotify, context);
    }

    @Override
    public void failedBlock(ClientContext context) {
      BaseManifestPutter.this.failedBlock(context);
    }

    @Override
    public void fatallyFailedBlock(ClientContext context) {
      BaseManifestPutter.this.fatallyFailedBlock(context);
    }

    @Override
    public synchronized void addMustSucceedBlocks(int blocks) {
      BaseManifestPutter.this.addMustSucceedBlocks(blocks);
      synchronized (this) {
        minSuccessFetchBlocks += blocks;
      }
    }

    @Override
    public synchronized void addRedundantBlocksInsert(int blocks) {
      BaseManifestPutter.this.addRedundantBlocksInsert(blocks);
    }

    @Override
    public synchronized int getMinSuccessFetchBlocks() {
      return minSuccessFetchBlocks;
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      BaseManifestPutter.this.notifyClients(context);
    }

    private void maybeNotifyFetchable() {
      synchronized (BaseManifestPutter.this) {
        if (!putHandlersWaitingForFetchable.remove(this)) {
          throw new IllegalStateException("was not in putHandlersWaitingForFetchable! : " + this);
        }
        if (fetchable) return;
        if (!putHandlersWaitingForFetchable.isEmpty()) return;
        fetchable = true;
      }
      cb.onFetchable(BaseManifestPutter.this);
    }

    @Override
    public void onBlockSetFinished(ClientPutState state, ClientContext context) {
      boolean allBlockSets;
      synchronized (BaseManifestPutter.this) {
        putHandlerWaitingForBlockSets.remove(this);
        if (freeformMode) {
          allBlockSets = hasResolvedBase && putHandlerWaitingForBlockSets.isEmpty();
        } else {
          allBlockSets = putHandlerWaitingForBlockSets.isEmpty();
        }
      }
      if (allBlockSets) BaseManifestPutter.this.blockSetFinalized(context);
    }

    @Override
    public void onFetchable(ClientPutState state) {
      if (LOG.isDebugEnabled()) LOG.debug("onFetchable {}", this);
      this.maybeNotifyFetchable();
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Ignore
    }

    @Override
    public String toString() {
      if (LOG.isDebugEnabled()) return super.toString() + " {" + this.itemName + '}';
      return super.toString();
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      // Ignore
    }

    @Override
    public void innerOnResume(ClientContext context) throws ResumeFailedException {
      super.innerOnResume(context);
      try {
        if (currentState != null) currentState.onResume(context);
        if (origSFI != null) origSFI.onResume(context);
      } catch (InsertException e) {
        throw new ResumeFailedException(e);
      }
    }

    @Override
    public void onShutdown(ClientContext context) {
      ClientPutState s;
      synchronized (this) {
        s = currentState;
      }
      if (s != null) s.onShutdown(context);
    }

    @Override
    protected ClientBaseCallback getCallback() {
      return cb;
    }

    /** What is our priority class? */
    @Override
    public short getPriorityClass() {
      return BaseManifestPutter.this.getPriorityClass();
    }

    @Override
    public ClientRequestSchedulerGroup getSchedulerGroup() {
      return BaseManifestPutter.this;
    }
  }

  private static final String[] defaultDefaultNames =
      new String[] {"index.html", "index.htm", "default.html", "default.htm"};

  // All the default names are in the root.
  // Code will need to be changed if we have index/index.html or similar.

  /** if true top level metadata is a container */
  private boolean containerMode = false;

  /** if true top level metadata is a single chunk */
  private boolean freeformMode = false;

  /* common stuff, fields used in freeform and container mode */
  /** put is finalized if empty */
  private final HashSet<PutHandler> putHandlerWaitingForBlockSets;

  /** if empty put is fetchable */
  private final HashSet<PutHandler> putHandlersWaitingForFetchable;

  /**
   * Tracks all currently running leaf put handlers (files or metadata inserts). Access is
   * synchronized externally; an empty set indicates there is no outstanding leaf work.
   */
  private final HashSet<PutHandler> runningPutHandlers;

  // container stuff, all fields can be null'ed in freeform mode
  /** Builder for the root container when operating in container mode; otherwise {@code null}. */
  private ContainerBuilder rootContainerBuilder;

  /** Put handler for the root container; only set while that container is live. */
  private ContainerPutHandler rootContainerPutHandler;

  /** Set of active container put handlers (excluding the root) in container mode. */
  private final HashSet<PutHandler> containerPutHandlers;

  /**
   * Per-container tracking of child handlers that must produce metadata before the container can be
   * started.
   */
  private final HashMap<PutHandler, HashSet<PutHandler>> perContainerPutHandlersWaitingForMetadata;

  /**
   * Mapping used during container assembly.
   *
   * <p>Keys are the {@code PutHandler} instances responsible for inserting items; values are the
   * <em>metadata directory</em> maps into which their result should be written. In other words: the
   * {@code PutHandler} fills its resolved {@link Metadata} into the referenced {@code Map<String,
   * Object>} under the item name when available.
   */
  @SuppressWarnings("java:S1948")
  private final HashMap<PutHandler, Map<String, Object>> putHandlersTransformMap;

  /**
   * Tracks placeholders to be rewritten once an {@link ArchivePutHandler} produces its final URI.
   */
  private final HashMap<ArchivePutHandler, ArrayList<PutHandler>> putHandlersArchiveTransformMap;

  // freeform stuff, all fields can be null'ed in container mode
  /** Root builder in freeform mode; {@code null} in container mode. */
  private FreeFormBuilder rootBuilder;

  /** Put handler responsible for inserting the top-level metadata in freeform mode. */
  private MetaPutHandler rootMetaPutHandler;

  /** The logical root directory map for freeform mode composition. */
  @SuppressWarnings("java:S1948")
  private HashMap<String, Object> rootDir;

  /**
   * Put handlers awaiting metadata production (freeform mode) to determine when the base manifest
   * can be finalized.
   */
  private final HashSet<PutHandler> putHandlersWaitingForMetadata;

  /** Final URI of the inserted manifest/container, available after encode of the root. */
  private FreenetURI finalURI;

  /** Target URI (e.g., SSK) for the root container or base metadata. */
  private final FreenetURI targetURI;

  /** True when the overall operation has finished (successfully or due to cancellation). */
  private boolean finished;

  /** Insert context providing policy, compatibility mode and storage factories. */
  private final InsertContext ctx;

  final transient ClientPutCallback cb;

  /** Count of files encountered during composition; used for progress reporting. */
  private int numberOfFiles;

  /** Aggregate size in bytes of all file data encountered during composition. */
  private long totalSize;

  /**
   * The composed base metadata for freeform mode, resolved from the directory tree into a single
   * manifest structure.
   */
  private Metadata baseMetadata;

  /** Whether the base metadata has been resolved to a bucket or sub-parts that can be inserted. */
  private boolean hasResolvedBase; // if this is true, the final block is ready for insert

  /**
   * True once all running handlers indicate the content is fetchable (i.e., enough blocks exist).
   */
  private boolean fetchable;

  /** Forced splitfile crypto key; when {@code null} a random key may be generated. */
  final byte[] forceCryptoKey;

  /** Crypto algorithm identifier to use for underlying splitfile inserts. */
  final byte cryptoAlgorithm;

  /**
   * Creates a new putter with the provided initialization parameters.
   *
   * <p>The constructor wires the callback client, target URI, insertion context and optional
   * cryptographic key material. When {@code randomiseCryptoKeys} is requested and {@code
   * forceCryptoKey} is absent, a random 32‑byte key is generated using the provided {@link
   * ClientContext} RNG. This does not start any work; callers must invoke {@link
   * #start(ClientContext)}.
   *
   * @param p initialization parameters including callback, target, context and crypto options. Must
   *     be non-null and internally consistent (e.g., a non-null callback/client).
   * @throws TooManyFilesInsertException when the manifest would exceed implementation limits on the
   *     number of concurrently handled files or containers.
   */
  protected BaseManifestPutter(InitParams p) throws TooManyFilesInsertException {
    super(p.prioClass, p.cb.getRequestClient());
    this.targetURI = p.target;
    this.cb = p.cb;
    this.ctx = p.ctx;
    byte[] key = p.forceCryptoKey;
    if (p.randomiseCryptoKeys && key == null) {
      key = new byte[32];
      p.context.random.nextBytes(key);
    }
    this.forceCryptoKey = key;

    CompatibilityMode mode = ctx.getCompatibilityMode();
    if (!(mode == CompatibilityMode.COMPAT_CURRENT
        || mode.ordinal() >= CompatibilityMode.COMPAT_1416.ordinal()))
      this.cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
    else this.cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
    runningPutHandlers = new HashSet<>();
    putHandlersWaitingForMetadata = new HashSet<>();
    putHandlersWaitingForFetchable = new HashSet<>();
    putHandlerWaitingForBlockSets = new HashSet<>();
    containerPutHandlers = new HashSet<>();
    perContainerPutHandlersWaitingForMetadata = new HashMap<>();
    putHandlersTransformMap = new HashMap<>();
    putHandlersArchiveTransformMap = new HashMap<>();
    String defName = p.defaultName;
    Map<String, Object> elements = p.manifestElements;
    if (defName == null) defName = findDefaultName(new HashMap<>(elements));
    makePutHandlers(new HashMap<>(elements), defName);
    // builders are no longer needed after constructor
    rootBuilder = null;
    rootContainerBuilder = null;
  }

  /**
   * Aggregates constructor arguments to keep parameter count reasonable (Sonar S107). This is a
   * simple data holder; behavior is unchanged.
   */
  protected static final class InitParams {
    ClientPutCallback cb;
    Map<String, Object> manifestElements;
    short prioClass;
    FreenetURI target;
    String defaultName;
    InsertContext ctx;
    boolean randomiseCryptoKeys;
    byte[] forceCryptoKey;
    ClientContext context;

    InitParams() {}

    InitParams withCb(ClientPutCallback cb) {
      this.cb = cb;
      return this;
    }

    InitParams withManifestElements(Map<String, Object> manifestElements) {
      this.manifestElements = manifestElements;
      return this;
    }

    InitParams withPrioClass(short prioClass) {
      this.prioClass = prioClass;
      return this;
    }

    InitParams withTarget(FreenetURI target) {
      this.target = target;
      return this;
    }

    InitParams withDefaultName(String defaultName) {
      this.defaultName = defaultName;
      return this;
    }

    InitParams withCtx(InsertContext ctx) {
      this.ctx = ctx;
      return this;
    }

    InitParams withRandomiseCryptoKeys(boolean randomiseCryptoKeys) {
      this.randomiseCryptoKeys = randomiseCryptoKeys;
      return this;
    }

    InitParams withForceCryptoKey(byte[] forceCryptoKey) {
      this.forceCryptoKey = forceCryptoKey;
      return this;
    }

    InitParams withContext(ClientContext context) {
      this.context = context;
      return this;
    }
  }

  private String findDefaultName(HashMap<String, Object> manifestElements) {
    // Try exact-case matches first
    String exact = findDefaultNameExact(manifestElements);
    if (!exact.isEmpty()) return exact;
    // Then try case-insensitive matches
    return findDefaultNameCaseInsensitive(manifestElements);
  }

  private String findDefaultNameExact(HashMap<String, Object> manifestElements) {
    for (String name : defaultDefaultNames) {
      Object o = manifestElements.get(name);
      if (o == null || o instanceof HashMap) continue;
      return name;
    }
    return "";
  }

  private String findDefaultNameCaseInsensitive(HashMap<String, Object> manifestElements) {
    for (String canonicalName : defaultDefaultNames) {
      for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
        Object o = entry.getValue();
        if (o == null || o instanceof HashMap) continue;
        if (entry.getKey().equalsIgnoreCase(canonicalName)) {
          return entry.getKey();
        }
      }
    }
    return "";
  }

  /**
   * Starts asynchronous insertion of the prepared manifest.
   *
   * <p>Depending on the chosen mode, this launches individual file puts, container builds, or both
   * and tracks their progress. If no container work is necessary and all leaf metadata are already
   * available, this method proceeds to building the top‑level metadata.
   *
   * @param context the client execution context providing schedulers, bucket factories and RNGs;
   *     must be non-null and match the constructor’s {@link InsertContext} origin.
   * @throws InsertException if starting any handler fails (e.g., due to bucket access errors or
   *     scheduler issues). On failure the putter cancels outstanding work and marks itself
   *     finished.
   */
  public void start(ClientContext context) throws InsertException {
    if (LOG.isDebugEnabled())
      LOG.debug("Starting {} persistence={} containermode={}", this, persistent(), containerMode);
    PutHandler[] running;
    PutHandler[] containers;
    boolean doContainers;

    synchronized (this) {
      running = runningPutHandlers.toArray(new PutHandler[0]);
      doContainers = containerMode;
      containers = doContainers ? getContainersToStart(running.length > 0) : new PutHandler[0];
    }

    try {
      startHandlers(context, running, "");
      if (doContainers) startHandlers(context, containers, " (containers)");
      if (!doContainers && running.length == 0) {
        gotAllMetadata(context);
      }
    } catch (InsertException e) {
      synchronized (this) {
        finished = true;
      }
      cancelAndFinish(context);
      throw e;
    }
  }

  private void startHandlers(ClientContext context, PutHandler[] handlers, String label)
      throws InsertException {
    for (int i = 0; i < handlers.length; i++) {
      handlers[i].start(context);
      if (LOG.isDebugEnabled()) LOG.debug("Started {} of {}{}", i, handlers.length, label);
      if (isFinished()) {
        if (LOG.isDebugEnabled()) LOG.debug("Already finished, killing start() on {}", this);
        return;
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Started {} PutHandler's{} for {}", handlers.length, label, this);
  }

  private PutHandler[] getContainersToStart(boolean excludeRoot) {
    PutHandler[] maybeStartPH = containerPutHandlers.toArray(new PutHandler[0]);
    ArrayList<PutHandler> phToStart = new ArrayList<>();

    for (PutHandler ph : maybeStartPH) {
      if (perContainerPutHandlersWaitingForMetadata.get(ph).isEmpty()) {
        phToStart.add(ph);
      }
    }
    if ((!excludeRoot) && (maybeStartPH.length == 0)) {
      phToStart.add(rootContainerPutHandler);
    }
    return phToStart.toArray(new PutHandler[0]);
  }

  /**
   * Implement the packing strategy that turns a logical manifest into concrete insert handlers.
   *
   * <p>Subclasses walk {@code manifestElements}, decide which items should be bundled into
   * containers versus inserted externally, and populate the appropriate handler structures. This
   * method must be deterministic with respect to the provided inputs.
   *
   * @param manifestElements map from item name to either a {@link ManifestElement} (file/redirect)
   *     or a nested {@code Map<String, Object>} representing a subdirectory. Implementations may
   *     mutate nested maps to attach handler placeholders.
   * @param defaultName the default document name to use for the root directory (e.g., {@code
   *     index.html}); may be empty when no suitable default is present.
   * @throws TooManyFilesInsertException if the number of files or containers would exceed safe
   *     limits for the current configuration.
   */
  protected abstract void makePutHandlers(
      HashMap<String, Object> manifestElements, String defaultName)
      throws TooManyFilesInsertException;

  @Override
  public FreenetURI getURI() {
    return finalURI;
  }

  @Override
  public synchronized boolean isFinished() {
    return finished || cancelled;
  }

  @Override
  public byte[] getSplitfileCryptoKey() {
    return forceCryptoKey;
  }

  /**
   * Called when metadata for all leaf put handlers is available.
   *
   * <p>This does not necessarily mean the final metadata can be inserted immediately. When the
   * aggregated metadata exceeds the inline threshold, it must first be resolved into subsidiary
   * metadata inserts. See {@link #resolveAndStartBase(ClientContext)} for the next steps.
   *
   * @param context execution context used for creating buckets and scheduling work.
   */
  private void gotAllMetadata(ClientContext context) {
    if (containerMode) throw new IllegalStateException();
    if (LOG.isDebugEnabled()) LOG.debug("Got all metadata");
    baseMetadata = makeMetadata(rootDir);
    context.jobRunner.setCheckpointASAP();
    resolveAndStartBase(context);
  }

  private Metadata makeMetadata(Map<String, Object> dir) {
    SimpleManifestComposer smc = new SimpleManifestComposer();
    for (Map.Entry<String, Object> entry : dir.entrySet()) {
      String name = entry.getKey();
      Object item = entry.getValue();
      if (item == null) throw new NullPointerException();
      Metadata m;
      if (item instanceof Map) {
        m = makeMetadata(Metadata.forceMap(item));
        if (m == null) throw new NullPointerException("HERE!!");
      } else {
        m = ((PutHandler) item).metadata;
        if (m == null) throw new NullPointerException("HERE!!" + item);
      }
      smc.addItem(name, m);
    }
    return smc.getMetadata();
  }

  /**
   * Attempts to insert the top‑level metadata or resolve it into smaller parts when necessary.
   *
   * <p>If {@code baseMetadata} cannot be serialized inline (due to size or unresolved references),
   * this method starts subsidiary metadata inserts for the unresolved parts and records their
   * outputs. Once enough pieces resolve to URIs, it is invoked again to finalize the top‑level
   * metadata and schedule its insertion.
   *
   * @param context execution context used to allocate buckets and schedule work.
   */
  private void resolveAndStartBase(ClientContext context) {
    synchronized (this) {
      if (hasResolvedBase) return;
    }
    RandomAccessBucket bucket = tryCreateMetadataBucket(context);
    if (bucket == null) return;
    synchronized (this) {
      if (hasResolvedBase) return;
      hasResolvedBase = true;
    }
    scheduleRootMetadataInsert(context, bucket);
  }

  private RandomAccessBucket tryCreateMetadataBucket(ClientContext context) {
    try {
      RandomAccessBucket bucket = baseMetadata.toBucket(context.getBucketFactory(persistent()));
      if (LOG.isDebugEnabled()) LOG.debug("Metadata bucket is {} bytes long", bucket.size());
      return bucket;
    } catch (IOException e) {
      fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
      return null;
    } catch (MetadataUnresolvedException e) {
      if (LOG.isDebugEnabled()) LOG.debug("Main metadata needs resolving: {}", String.valueOf(e));
      try {
        resolve(e, context);
      } catch (IOException ioe) {
        fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
      } catch (InsertException ie) {
        fail(ie, context);
      }
      return null;
    }
  }

  private void scheduleRootMetadataInsert(ClientContext context, RandomAccessBucket bucket) {
    InsertBlock block = new InsertBlock(bucket, null, targetURI);
    try {
      rootMetaPutHandler = new MetaPutHandler(this, null, block);
      if (LOG.isDebugEnabled())
        LOG.debug("Inserting main metadata: {} for {}", rootMetaPutHandler, baseMetadata);
      rootMetaPutHandler.start(context);
    } catch (InsertException e) {
      fail(e, context);
    }
  }

  /**
   * Starts inserts for metadata parts that could not be inlined.
   *
   * <p>Each unresolved {@link Metadata} instance is turned into a subsidiary insert. When a part
   * becomes fetchable and its key is known (via {@code onEncode()}), we can proceed to {@link
   * #resolveAndStartBase(ClientContext)} to rebuild the top‑level metadata and continue.
   *
   * @param e the unresolved metadata exception holding the {@code mustResolve} parts.
   * @param context execution context used to allocate buckets and schedule the subsidiary inserts.
   * @throws InsertException if scheduling a subsidiary insert fails.
   * @throws IOException if converting metadata to a bucket fails.
   */
  private void resolve(MetadataUnresolvedException e, ClientContext context)
      throws InsertException, IOException {
    Metadata[] metas = e.mustResolve;
    for (Metadata m : metas) {
      if (LOG.isDebugEnabled()) LOG.debug("Resolving {}", m);
      if (m.isResolved()) {
        LOG.error("Already resolved: {} in resolve() - race condition???", m);
        continue;
      }
      try {
        MetaPutHandler ph =
            new MetaPutHandler(this, null, m, context.getBucketFactory(persistent()));
        ph.start(context);
      } catch (MetadataUnresolvedException e1) {
        resolve(e1, context);
      }
    }
  }

  // completion logic moved into PutHandler.tryCompleteOuter()

  // Wrapper moved into PutHandler as failOuter(...)

  private void fail(InsertException e, ClientContext context) {
    // Cancel all, then call the callback
    synchronized (this) {
      if (finished) return;
      finished = true;
    }
    cancelAndFinish(context);

    cb.onFailure(e, this);
  }

  /** Cancel all running inserters. */
  private void cancelAndFinish(ClientContext context) {
    PutHandler[] running;
    synchronized (this) {
      running = runningPutHandlers.toArray(new PutHandler[0]);
    }

    if (LOG.isDebugEnabled()) LOG.debug("PutHandler's to cancel: {}", running.length);
    for (PutHandler putter : running) {
      putter.cancel(context);
    }
    // Note: if we add additional metadata put states, they should be cancelled here as well.
  }

  @Override
  public void cancel(ClientContext context) {
    synchronized (this) {
      if (finished) return;
      if (super.cancel()) return;
    }
    fail(new InsertException(InsertExceptionMode.CANCELLED), context);
  }

  /**
   * The number of blocks that will be needed to fetch the data. We put this in the top block
   * metadata.
   */
  protected int minSuccessFetchBlocks;

  @Override
  public void addBlock() {
    synchronized (this) {
      minSuccessFetchBlocks++;
    }
    super.addBlock();
  }

  @Override
  public void addBlocks(int num) {
    synchronized (this) {
      minSuccessFetchBlocks += num;
    }
    super.addBlocks(num);
  }

  /** Add one or more blocks to the number of requires blocks, and don't notify the clients. */
  @Override
  public synchronized void addMustSucceedBlocks(int blocks) {
    synchronized (this) {
      minSuccessFetchBlocks += blocks;
    }
    super.addMustSucceedBlocks(blocks);
  }

  /**
   * Add one or more blocks to the number of requires blocks, and don't notify the clients. These
   * blocks are added to the minSuccessFetchBlocks for the insert, but not to the counter for what
   * the requestor must fetch.
   */
  @Override
  public synchronized void addRedundantBlocksInsert(int blocks) {
    super.addMustSucceedBlocks(blocks);
  }

  @Override
  public void innerNotifyClients(ClientContext context) {
    SplitfileProgressEvent e;
    synchronized (this) {
      e =
          new SplitfileProgressEvent(
              this.totalBlocks,
              this.successfulBlocks,
              this.latestSuccess,
              this.failedBlocks,
              this.fatallyFailedBlocks,
              this.latestFailure,
              this.minSuccessBlocks,
              this.minSuccessFetchBlocks,
              this.blockSetFinalized);
    }
    ctx.eventProducer.produceEvent(e, context);
  }

  @Override
  public int getMinSuccessFetchBlocks() {
    return minSuccessFetchBlocks;
  }

  // Inherit blockSetFinalized behavior from parent

  public int countFiles() {
    return numberOfFiles;
  }

  public long totalSize() {
    return totalSize;
  }

  // fetchable handling moved into PutHandler.maybeNotifyFetchable()

  @Override
  public void onTransition(
      ClientGetState oldState, ClientGetState newState, ClientContext context) {}

  @Override
  public void onTransition(ClientPutState from, ClientPutState to, ClientContext context) {
    LOG.error("Ignoring transition from {} to {} on {}", from, to, this);
  }

  @Override
  protected void innerToNetwork(ClientContext context) {}

  private void tryStartParentContainer(PutHandler containerHandle2, ClientContext context)
      throws InsertException {

    if (containerHandle2 == null) throw new NullPointerException();

    if (perContainerPutHandlersWaitingForMetadata.get(containerHandle2).isEmpty()) {
      perContainerPutHandlersWaitingForMetadata.remove(containerHandle2);
      containerHandle2.start(context);
    } else {

      if (LOG.isDebugEnabled())
        LOG.debug(
            "(spc) waiting m:{} for {}",
            perContainerPutHandlersWaitingForMetadata.get(containerHandle2).size(),
            containerHandle2);
    }
  }

  // compose helper stuff

  /**
   * Best-effort MIME type inference for a file name with an optional override.
   *
   * <p>The override takes precedence when non-blank. Otherwise, the method delegates to {@link
   * DefaultMIMETypes#guessMIMEType(String, boolean)} with strict matching enabled. Trivial or
   * default types may be returned as {@code null} to keep manifests compact.
   *
   * @param name the file name used for type inference; may be {@code null} when only {@code
   *     mimetype} is provided.
   * @param mimetype explicit MIME type to use when non-null/non-empty; whitespace is ignored.
   * @return a {@link ClientMetadata} instance when a meaningful type is available; otherwise {@code
   *     null} indicating no explicit content type is necessary.
   */
  protected final ClientMetadata guessMime(String name, String mimetype) {
    String mimeType = mimetype;
    if ((mimeType == null) && (name != null)) mimeType = DefaultMIMETypes.guessMIMEType(name, true);
    ClientMetadata cm;
    if (mimeType == null || mimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE)) cm = null;
    else cm = new ClientMetadata(mimeType);
    return cm;
  }

  /**
   * Creates a {@link ContainerBuilder} that represents a standalone archive container.
   *
   * <p>Use this when a logical directory cannot fit into the primary container structure (e.g.,
   * extremely large fan‑out) but should still be grouped and referenced by redirects.
   *
   * @return a builder preconfigured for archive semantics.
   */
  protected ContainerBuilder makeArchive() {
    return new ContainerBuilder(false, null, null, true);
  }

  /**
   * Returns the root {@link ContainerBuilder}, switching the putter into container mode on first
   * use.
   *
   * <p>Subsequent calls return the same builder. Calling this after {@link #getRootBuilder()} has
   * been used results in an {@link IllegalStateException} because modes are mutually exclusive.
   *
   * @return the root container builder.
   * @throws IllegalStateException if the putter is already in freeform mode.
   */
  protected ContainerBuilder getRootContainer() {
    if (freeformMode) throw new IllegalStateException("Already in freeform mode!");
    if (!containerMode) {
      containerMode = true;
      rootContainerBuilder = new ContainerBuilder(true);
    }
    return rootContainerBuilder;
  }

  /**
   * Returns the root {@link FreeFormBuilder}, switching the putter into freeform mode on first use.
   *
   * <p>Subsequent calls return the same builder. Calling this after {@link #getRootContainer()} has
   * been used results in an {@link IllegalStateException} because modes are mutually exclusive.
   *
   * @return the root freeform builder.
   * @throws IllegalStateException if the putter is already in container mode.
   */
  protected FreeFormBuilder getRootBuilder() {
    if (containerMode) throw new IllegalStateException("Already in container mode!");
    if (!freeformMode) {
      freeformMode = true;
      rootBuilder = new FreeFormBuilder();
    }
    return rootBuilder;
  }

  /**
   * Base class for building a manifest tree prior to insertion.
   *
   * <p>Implementations maintain a logical “current directory” and allow callers to add external
   * files, redirects, or nested subdirectories. The builder does not perform any network activity;
   * it merely records structure so the enclosing {@link BaseManifestPutter} can create {@code
   * PutHandler}s and schedule work.
   *
   * <p>Thread-safety: instances are not thread-safe. Callers should confine a builder to a single
   * thread and synchronize externally when composing of multiple threads.
   */
  protected abstract static class ManifestBuilder implements Serializable {

    @Serial private static final long serialVersionUID = 1L;
    private final transient Deque<Map<String, Object>> dirStack;

    /**
     * Map from name to either a Metadata (to be included as-is), a ManifestElement (either a
     * redirect or a file), or another HashMap. Eventually processed by e.g.
     * ContainerInserter.makeManifest() (for a ContainerBuilder).
     */
    protected transient Map<String, Object> currentDir;

    private ClientMetadata makeClientMetadata(String mime) {
      if (mime == null) return null;
      ClientMetadata cm = new ClientMetadata(mime.trim());
      if (cm.isTrivial()) return null;
      return cm;
    }

    ManifestBuilder() {
      dirStack = new ArrayDeque<>();
    }

    /** Saves the current directory on an internal stack so the caller can return to it later. */
    public void pushCurrentDir() {
      dirStack.push(currentDir);
    }

    /**
     * Restores the most recently saved directory from the internal stack.
     *
     * @throws java.util.NoSuchElementException if the stack is empty.
     */
    public void popCurrentDir() {
      currentDir = dirStack.pop();
    }

    /**
     * Changes into the named subdirectory, creating it if necessary.
     *
     * @param name subdirectory name relative to the current directory; must be a simple name
     *     without separators.
     * @throws IllegalStateException if an entry with the same name already exists and is not a
     *     directory.
     */
    public void makeSubDirCD(String name) {
      Object dir = currentDir.get(name);
      if (dir != null) {
        currentDir = Metadata.forceMap(dir);
      } else {
        currentDir = makeSubDir(currentDir, name);
      }
    }

    private Map<String, Object> makeSubDir(Map<String, Object> parentDir, String name) {
      if (parentDir.containsKey(name)) {
        throw new IllegalStateException("Item '" + name + "' already exist!");
      }
      HashMap<String, Object> newDir = new HashMap<>();
      parentDir.put(name, newDir);
      return newDir;
    }

    /**
     * Adds a {@link ManifestElement} representing either a redirect or an external file.
     *
     * @param name logical entry name within the current directory; used as the manifest key.
     * @param element the element to add. When {@code element.getData() != null} it is treated as an
     *     external file; when {@code element.targetURI != null} it is treated as a redirect.
     * @param isDefaultDoc when {@code true}, records this element as the directory’s default
     *     document by also inserting an empty-name shortlink.
     * @throws IllegalStateException if the element is neither a redirect nor external data.
     */
    public final void addElement(String name, ManifestElement element, boolean isDefaultDoc) {
      ClientMetadata cm = makeClientMetadata(element.mimeOverride);

      if (element.getData() != null) {
        addExternal(name, element.getData(), cm, isDefaultDoc);
        return;
      }
      if (element.targetURI != null) {
        addRedirect(name, element.targetURI, cm, isDefaultDoc);
        return;
      }
      throw new IllegalStateException("ME is neither a redirect nor dircet data. " + element);
    }

    /**
     * Add a file as an external. It will be inserted separately, and we will add a redirect to the
     * metadata.
     *
     * @param name The name of the file (short name within the original folder, it's not in a
     *     container).
     * @param data The data to be inserted.
     * @param mimeOverride Optional MIME type override.
     * @param isDefaultDoc If true, make this the default document.
     */
    public final void addExternal(
        String name, RandomAccessBucket data, String mimeOverride, boolean isDefaultDoc) {
      if (data == null) throw new NullPointerException("data");
      ClientMetadata cm = makeClientMetadata(mimeOverride);
      addExternal(name, data, cm, isDefaultDoc);
    }

    /**
     * Adds a redirect entry with an optional MIME type override.
     *
     * @param name logical name within the current directory.
     * @param targetUri target {@link FreenetURI} to redirect to.
     * @param mimeOverride optional MIME type override; when null or blank, type inference may be
     *     applied later.
     * @param isDefaultDoc when {@code true}, also marks this entry as the default document.
     */
    @SuppressWarnings("unused")
    public final void addRedirect(
        String name, FreenetURI targetUri, String mimeOverride, boolean isDefaultDoc) {
      ClientMetadata cm = makeClientMetadata(mimeOverride);
      addRedirect(name, targetUri, cm, isDefaultDoc);
    }

    /**
     * Adds an external file to the current directory.
     *
     * @param name logical name within the current directory.
     * @param data data bucket to be inserted; must be non-null.
     * @param cm optional {@link ClientMetadata} such as MIME type; may be {@code null}.
     * @param isDefaultDoc when {@code true}, also marks this entry as the default document.
     */
    public abstract void addExternal(
        String name, RandomAccessBucket data, ClientMetadata cm, boolean isDefaultDoc);

    /**
     * Adds a redirect entry to the current directory.
     *
     * @param name logical name within the current directory.
     * @param targetUri target {@link FreenetURI} to redirect to.
     * @param cm optional {@link ClientMetadata} such as MIME type; may be {@code null}.
     * @param isDefaultDoc when {@code true}, also marks this entry as the default document.
     */
    public abstract void addRedirect(
        String name, FreenetURI targetUri, ClientMetadata cm, boolean isDefaultDoc);
  }

  /**
   * Builder used in freeform mode where individual files are inserted separately and referenced
   * from a top-level manifest.
   */
  protected final class FreeFormBuilder extends ManifestBuilder {

    @Serial private static final long serialVersionUID = 1L;

    /** Creates a new freeform builder with an empty root directory. */
    protected FreeFormBuilder() {
      rootDir = new HashMap<>();
      currentDir = rootDir;
    }

    @Override
    public void addExternal(
        String name, RandomAccessBucket data, ClientMetadata cm, boolean isDefaultDoc) {
      PutHandler ph;
      ph = new ExternPutHandler(BaseManifestPutter.this, null, name, data, cm);
      // Track pending metadata for freeform mode so we know when all are available
      putHandlersWaitingForMetadata.add(ph);

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Inserting separately as PutHandler: {} : {} persistent={}", name, ph, ph.persistent());
      numberOfFiles++;
      totalSize += data.size();
      currentDir.put(name, ph);
      if (isDefaultDoc) {
        ph = new JokerPutHandler(BaseManifestPutter.this, null, name, name);
        currentDir.put("", ph);
      }
    }

    @Override
    public void addRedirect(
        String name, FreenetURI targetURI2, ClientMetadata cm, boolean isDefaultDoc) {
      PutHandler ph;
      ph = new JokerPutHandler(BaseManifestPutter.this, name, targetURI2, cm);
      currentDir.put(name, ph);
      if (isDefaultDoc) currentDir.put("", ph);
    }
  }

  /**
   * Builder used in container mode for composing items into container archives.
   *
   * <p>Each instance represents one container. The root container is inserted at the target URI;
   * nested containers are inserted as CHKs and referenced from their parent structures.
   */
  protected final class ContainerBuilder extends ManifestBuilder {

    @Serial private static final long serialVersionUID = 1L;

    /** Backing put handler representing this container in the insertion pipeline. */
    private final PutHandler selfHandle;

    private ContainerBuilder(boolean isRoot) {
      this(isRoot, null, null, false);
    }

    private ContainerBuilder(PutHandler parent, String name) {
      this(false, parent, name, false);
    }

    private ContainerBuilder(boolean isRoot, PutHandler parent, String name, boolean isArchive) {
      if (!containerMode) {
        throw new IllegalStateException("You can not add containers in free form mode!");
      }
      /*
       * Tree containing the status of the insert. Can have ManifestElement's (original files to
       * insert or bundle inside a container), HashMap's (more subdirs), Metadata (to be put into a
       * container as metadata for e.g. an external file), a ContainerPutHandler or an
       * ArchivePutHandler (for containers that are part of the structure, and external containers
       * for overflow, respectively).
       */
      HashMap<String, Object> rootDirMap = new HashMap<>();
      if (isArchive)
        selfHandle =
            new ArchivePutHandler(
                BaseManifestPutter.this,
                parent,
                name,
                rootDirMap,
                (isRoot ? BaseManifestPutter.this.targetURI : FreenetURI.EMPTY_CHK_URI));
      else
        selfHandle =
            new ContainerPutHandler(
                BaseManifestPutter.this,
                parent,
                name,
                rootDirMap,
                (isRoot ? BaseManifestPutter.this.targetURI : FreenetURI.EMPTY_CHK_URI),
                (isRoot ? null : containerPutHandlers));
      currentDir = rootDirMap;
      if (isRoot) {
        if (selfHandle instanceof ContainerPutHandler cph) {
          rootContainerPutHandler = cph;
        } else {
          throw new IllegalStateException("Root builder must use a container, not an archive");
        }
      } else {
        containerPutHandlers.add(selfHandle);
      }
      perContainerPutHandlersWaitingForMetadata.put(selfHandle, new HashSet<>());

      if (isArchive)
        putHandlersArchiveTransformMap.put((ArchivePutHandler) selfHandle, new ArrayList<>());
    }

    /**
     * Creates and wires a nested container under the current directory.
     *
     * @param name sub-container name within the current directory.
     * @return the newly created {@code ContainerBuilder}.
     */
    public ContainerBuilder makeSubContainer(String name) {
      ContainerBuilder subCon = new ContainerBuilder(selfHandle, name);
      currentDir.put(name, subCon.selfHandle);
      putHandlersTransformMap.put(subCon.selfHandle, currentDir);
      perContainerPutHandlersWaitingForMetadata.get(selfHandle).add(subCon.selfHandle);
      return subCon;
    }

    /**
     * Add a ManifestElement, which can be a file in an archive, or a redirect.
     *
     * @param name The original name of the file (e.g. index.html).
     * @param nameInArchive The fully qualified name of the file in the archive (e.g.
     *     testing/index.html).
     * @param element The ManifestElement specifying the data, redirect, etc. Note that redirects
     *     are still included in containers, both for structural reasons and because the metadata
     *     can be large enough that we need to split it.
     * @param isDefaultDoc If true, add a link from "" to this element, making it the default
     *     document in this container.
     */
    public void addItem(
        String name, String nameInArchive, ManifestElement element, boolean isDefaultDoc) {
      ManifestElement me = new ManifestElement(element, name, nameInArchive);
      addItem(name, me, isDefaultDoc);
    }

    /**
     * Adds a manifest element into this container’s current directory.
     *
     * @param name entry name (e.g., {@code index.html}).
     * @param element element to add; external data increases the container’s total size.
     * @param isDefaultDoc whether to mark this element as the default document.
     */
    public void addItem(String name, ManifestElement element, boolean isDefaultDoc) {
      currentDir.put(name, element);
      if (isDefaultDoc) {
        Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, name, null);
        currentDir.put("", m);
      }
      numberOfFiles++;
      if (element.getData() != null) totalSize += element.getSize();
    }

    @Override
    public void addRedirect(
        String name, FreenetURI targetUri, ClientMetadata cm, boolean isDefaultDoc) {
      Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetUri, cm);
      currentDir.put(name, m);
      if (isDefaultDoc) {
        currentDir.put("", m);
      }
    }

    /**
     * Adds an external file to this container; the file is inserted separately and referenced by
     * metadata once its URI is known.
     *
     * @param name entry name within the container.
     * @param data data bucket to insert.
     * @param cm optional {@link ClientMetadata} such as MIME type; may be {@code null}.
     * @param isDefaultDoc whether to mark this entry as the default document.
     */
    @Override
    public void addExternal(
        String name, RandomAccessBucket data, ClientMetadata cm, boolean isDefaultDoc) {
      PutHandler ph = new ExternPutHandler(BaseManifestPutter.this, selfHandle, name, data, cm);
      perContainerPutHandlersWaitingForMetadata.get(selfHandle).add(ph);
      putHandlersTransformMap.put(ph, currentDir);
      if (isDefaultDoc) {
        Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, name, null);
        currentDir.put("", m);
      }
      numberOfFiles++;
      totalSize += data.size();
    }

    /**
     * Adds an item into an archive container and creates a companion redirect placeholder.
     *
     * <p>This preserves historical behavior where some code paths expected an explicit {@code
     * JokerPutHandler} for archive-internal redirects instead of relying solely on {@link
     * #addItem(String, ManifestElement, boolean)}.
     *
     * @param archive the destination archive builder; must represent an archive container.
     * @param name entry name within the archive.
     * @param element source element; must include data.
     * @param isDefaultDoc whether to mark this entry as the default document.
     * @throws NullPointerException if {@code element.getData()} is {@code null}.
     * @throws IllegalStateException if {@code archive} is not an archive container.
     */
    public void addArchiveItem(
        ContainerBuilder archive, String name, ManifestElement element, boolean isDefaultDoc) {
      if (element.getData() == null) throw new NullPointerException("element.data");
      archive.addItem(name, new ManifestElement(element, name, name), false);
      PutHandler ph =
          new JokerPutHandler(
              BaseManifestPutter.this, selfHandle, name, guessMime(name, element.mimeOverride));
      putHandlersTransformMap.put(ph, currentDir);
      perContainerPutHandlersWaitingForMetadata.get(selfHandle).add(ph);
      if (!(archive.selfHandle instanceof ArchivePutHandler aph)) {
        throw new IllegalStateException("addArchiveItem called on non-archive builder");
      }
      putHandlersArchiveTransformMap.get(aph).add(ph);
      if (isDefaultDoc) {
        Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, name, null);
        currentDir.put("", m);
      }
      numberOfFiles++;
      if (element.getData() != null) totalSize += element.getSize();
    }
  }

  @Override
  protected ClientBaseCallback getCallback() {
    return cb;
  }

  /**
   * Converts a mixed map of buckets/elements/subdirectories into a manifest-entry map.
   *
   * <p>Entries that are already {@link ManifestElement}s are passed through. {@link Bucket}
   * instances are wrapped into new elements using their names and sizes. Nested maps are processed
   * recursively.
   *
   * @param bucketsByName input map where values are {@code ManifestElement}, {@code Bucket}, or a
   *     nested {@code Map<String, Object>}.
   * @return a new map suitable for composing metadata/manifests.
   */
  public static Map<String, Object> bucketsByNameToManifestEntries(
      Map<String, Object> bucketsByName) {
    Map<String, Object> manifestEntries = new HashMap<>();
    for (Map.Entry<String, Object> entry : bucketsByName.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      switch (o) {
        case ManifestElement me -> manifestEntries.put(name, me);
        case Bucket b -> {
          RandomAccessBucket data = (RandomAccessBucket) b;
          manifestEntries.put(name, new ManifestElement(name, data, null, data.size()));
        }
        case HashMap<?, ?> map ->
            manifestEntries.put(name, bucketsByNameToManifestEntries(Metadata.forceMap(map)));
        default -> throw new IllegalArgumentException(String.valueOf(o));
      }
    }
    return manifestEntries;
  }

  /**
   * Flattens a hierarchical manifest map into a list of manifest elements with fully qualified
   * names.
   *
   * @param manifestElements hierarchical map produced by the builders.
   * @return a new array with entries in depth-first enumeration order.
   */
  public static ManifestElement[] flatten(Map<String, Object> manifestElements) {
    List<ManifestElement> v = new ArrayList<>();
    flatten(manifestElements, v, "");
    return v.toArray(new ManifestElement[0]);
  }

  /**
   * Flattens a hierarchical manifest map into an output list, prefixing names with the provided
   * path.
   *
   * @param manifestElements hierarchical map produced by the builders.
   * @param v destination list receiving elements; not cleared.
   * @param prefix directory prefix (empty or of form {@code a/b/c}).
   * @throws IllegalStateException if a value is neither a map nor a manifest element.
   */
  public static void flatten(
      Map<String, Object> manifestElements, List<ManifestElement> v, String prefix) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      String fullName = prefix.isEmpty() ? name : prefix + '/' + name;
      Object o = entry.getValue();
      if (o instanceof HashMap) {
        flatten(Metadata.forceMap(o), v, fullName);
      } else if (o instanceof ManifestElement me) {
        v.add(new ManifestElement(me, fullName));
      } else throw new IllegalStateException(String.valueOf(o));
    }
  }

  @Override
  public void onShutdown(ClientContext context) {
    for (PutHandler h : runningPutHandlers) h.onShutdown(context);
    if (rootContainerPutHandler != null) rootContainerPutHandler.onShutdown(context);
    if (containerPutHandlers != null) {
      for (PutHandler h : containerPutHandlers) h.onShutdown(context);
    }
    if (rootMetaPutHandler != null) rootMetaPutHandler.onShutdown(context);
  }

  @Override
  protected void innerOnResume(ClientContext context) throws ResumeFailedException {
    super.innerOnResume(context);
    for (PutHandler h : runningPutHandlers) h.onResume(context);
    if (rootContainerPutHandler != null) rootContainerPutHandler.onResume(context);
    if (containerPutHandlers != null) {
      for (PutHandler h : containerPutHandlers) h.onResume(context);
    }
    if (rootMetaPutHandler != null) rootMetaPutHandler.onResume(context);
  }
}
