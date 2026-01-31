package network.crypta.client.async;

import java.io.Serial;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import network.crypta.client.Metadata;
import network.crypta.support.ContainerSizeEstimator;
import network.crypta.support.ContainerSizeEstimator.ContainerSize;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default strategy for packaging a directory tree (a “manifest”) into one or more containers.
 *
 * <p>This implementation focuses on producing fetchable, size‑bounded container archives while
 * preserving stable internal structure for redirects. Callers provide a hierarchical map of names
 * to {@link network.crypta.support.api.ManifestElement} (or nested maps for subdirectories) and a
 * default document name. The putter then decides which files become in‑container items, which
 * become separate CHK inserts referenced via redirects, and when to generate overflow archives for
 * directories with many files. The resulting root container is inserted at the supplied target
 * {@link network.crypta.keys.FreenetURI}, and callers receive progress and completion callbacks.
 *
 * <p>Use this class when you want reasonable, deterministic packing without tuning numerous
 * parameters. The algorithm aims to balance container size limits with practical fetchability:
 * small sites often fit in a single container, while larger ones are split into additional
 * structures with redirects. Insert operations are coordinated asynchronously by the base class;
 * instances are not thread‑safe and should be used from the client’s request context.
 *
 * <p><strong>Packing limits</strong>
 *
 * <ul>
 *   <li>Maximum container size: 2&nbsp;MiB (effective usable budget is slightly lower).
 *   <li>Maximum in‑container item size: 1&nbsp;MiB. Larger items are inserted externally unless a
 *       special case allows otherwise.
 *   <li>Reserved headroom (“spare”): approximately 192&nbsp;KiB to absorb metadata overhead and
 *       estimation error.
 * </ul>
 *
 * <p><strong>Behavioral rules</strong>
 *
 * <ol>
 *   <li>If all files and required metadata fit, the whole tree goes into the container.
 *   <li>Otherwise, files larger than the per‑item threshold are stored externally and referenced
 *       from the container.
 * </ol>
 *
 * <p><em>Default document:</em> {@code defaultName} is a simple file name (no path separators).
 * When present in a directory, that entry also becomes the default document for that directory.
 *
 * <p><em>Client hint:</em> If the files in the site’s root directory fit into one container, they
 * will be placed in the root container (the first fetched container). A rough check is: {@code
 * accumulatedFileSize + 512 * subdirCount < 1.8 MiB}.
 */
public class DefaultManifestPutter extends BaseManifestPutter {
  private static final Logger LOG = LoggerFactory.getLogger(DefaultManifestPutter.class);

  @Serial private static final long serialVersionUID = 1L;

  // no static initialization required

  private long processSubdirsFit(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      ContainerSize wholeSize,
      boolean unlimited) {
    if (unlimited) {
      if (LOG.isDebugEnabled()) LOG.debug(" (unlimited)");
      addAllSubdirsUnlimited(containerBuilder, manifestElements, defaultName);
      return wholeSize.getSizeSubTreesNoLimit();
    } else {
      if (LOG.isDebugEnabled()) LOG.debug(" (limited)");
      addAllSubdirsLimited(containerBuilder, manifestElements, defaultName);
      return wholeSize.getSizeSubTrees();
    }
  }

  private void addAllSubdirsUnlimited(
      ContainerBuilder containerBuilder, Map<String, Object> manifestElements, String defaultName) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof Map) {
        Map<String, Object> hm = Metadata.forceMap(o);
        containerBuilder.pushCurrentDir();
        containerBuilder.makeSubDirCD(name);
        makeEveryThingUnlimitedPutHandlers(containerBuilder, hm, defaultName);
        containerBuilder.popCurrentDir();
      }
    }
  }

  private void addAllSubdirsLimited(
      ContainerBuilder containerBuilder, Map<String, Object> manifestElements, String defaultName) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof Map) {
        Map<String, Object> hm = Metadata.forceMap(o);
        containerBuilder.pushCurrentDir();
        containerBuilder.makeSubDirCD(name);
        makeEveryThingPutHandlers(containerBuilder, hm, defaultName);
        containerBuilder.popCurrentDir();
      }
    }
  }

  private long addEachSubdirInOwnContainer(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      long tmpSize)
      throws TooManyFilesInsertException {
    if (LOG.isDebugEnabled())
      LOG.debug("PackStat2: sub dirs does not fit into container, make each its own");
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof Map) {
        Map<String, Object> hm = Metadata.forceMap(o);
        ContainerBuilder subC = containerBuilder.makeSubContainer(name);
        makePutHandlers(subC, hm, defaultName, DEFAULT_MAX_CONTAINERSIZE, name);
        tmpSize += 512;
      }
    }
    return tmpSize;
  }

  /**
   * Upper bound for a single container’s serialized size in bytes.
   *
   * <p>This is a hard limit guided by fetchability constraints. Packing logic treats values close
   * to this limit as full to avoid overhead underestimation. Clients should not rely on the exact
   * value and must not assume that every insert attempts to fill containers to capacity.
   */
  public static final long DEFAULT_MAX_CONTAINERSIZE = 2048L * 1024L;

  /**
   * Maximum size for a single item to be placed inside a container, in bytes.
   *
   * <p>Items larger than this threshold are inserted as external splitfiles and referenced by a
   * redirect from the container. The threshold accounts for typical archive overhead but does not
   * include outer container padding or metadata growth.
   */
  public static final long DEFAULT_MAX_CONTAINERITEMSIZE = 1024L * 1024L;

  /**
   * Reserved headroom per container, in bytes, to accommodate metadata and estimation error.
   *
   * <p>When the accumulated size within a container exceeds {@code DEFAULT_MAX_CONTAINERSIZE -
   * DEFAULT_CONTAINERSIZE_SPARE}, the container is considered full and additional content is
   * deferred to subcontainers or external archives. This improves predictability and reduces
   * re‑packing churn.
   */
  public static final long DEFAULT_CONTAINERSIZE_SPARE = 196L * 1024L;

  /**
   * Creates a putter that packs and inserts the provided manifest tree.
   *
   * <p>The constructor wires callbacks, establishes packing thresholds, and derives security
   * parameters (e.g., randomized splitfile keys for SSK targets). No network I/O occurs until
   * {@code start(...)} is invoked on the enclosing put workflow.
   *
   * @param params shared manifest putter parameters, including callback, manifest map, priorities
   *     and context. The manifest map is defensively copied before packing.
   * @param persistent whether the job participates in persistence across restarts; when {@code
   *     true}, the putter coordinates with persistent job runners.
   * @throws TooManyFilesInsertException if the input contains an excessive number of files within a
   *     single directory such that reasonable packing cannot proceed.
   */
  public DefaultManifestPutter(ManifestPutterParams params, boolean persistent)
      throws TooManyFilesInsertException {
    // If the top level key is an SSK, all CHK blocks and particularly splitfiles below it should
    // have
    // randomized keys. This substantially improves security by making it impossible to identify
    // blocks
    // even if you know the content. In the user interface, we will offer the option of inserting as
    // a
    // random SSK to take advantage of this.
    super(
        new InitParams()
            .withCb(params.clientCallback())
            .withManifestElements(new HashMap<>(params.manifestElements()))
            .withPrioClass(params.prioClass())
            .withTarget(params.target())
            .withDefaultName(params.defaultName())
            .withCtx(params.ctx())
            .withRandomiseCryptoKeys(
                ClientPutter.randomiseSplitfileKeys(params.target(), params.ctx()))
            .withForceCryptoKey(params.forceCryptoKey())
            .withContext(params.context()));
    if (LOG.isDebugEnabled()) LOG.debug("DefaultManifestPutter persistent={}", persistent);
  }

  /**
   * {@inheritDoc}
   *
   * <p>For the default strategy, this method estimates the total size of the subtree, chooses an
   * appropriate packing path (everything in one container, files first then subdirectories, or
   * subdirectories first), and schedules inserts accordingly. Large items are redirected as
   * externals; leftovers are grouped into overflow archives to keep containers within limits.
   *
   * @param manifestElements hierarchical map of file names to elements or nested maps; must contain
   *     only supported types as validated by {@link #verifyManifest(Map)}.
   * @param defaultName default document name to apply within directories where a matching entry
   *     exists.
   * @throws TooManyFilesInsertException if a directory contains so many entries that a reasonable
   *     packing plan cannot be constructed within the configured limits.
   * @see BaseManifestPutter#makePutHandlers(Map, String)
   */
  @Override
  protected void makePutHandlers(Map<String, Object> manifestElements, String defaultName)
      throws TooManyFilesInsertException {
    verifyManifest(manifestElements);
    makePutHandlers(
        getRootContainer(), manifestElements, defaultName, DEFAULT_MAX_CONTAINERSIZE, null);
  }

  /**
   * Ensure the tree contains only elements we understand, so we do not need further checking in the
   * pack algorithm
   */
  private void verifyManifest(Map<String, Object> metadata) {
    for (Map.Entry<String, Object> entry : metadata.entrySet()) {
      Object o = entry.getValue();
      if (o instanceof Map) {
        Map<String, Object> hm = Metadata.forceMap(o);
        verifyManifest(hm);
      } else if (!(o instanceof ManifestElement)) {
        throw new IllegalArgumentException("FATAL: unknown manifest element: " + o);
      }
    }
  }

  /**
   * Implements the internal packing flow for a single directory level.
   *
   * @param containerBuilder container builder representing the current directory context where
   *     items and subcontainers are recorded; must be non-null.
   * @param manifestElements map of entry names to either {@link ManifestElement} or nested maps for
   *     subdirectories; must contain supported types only.
   * @param defaultName default document name to mark when a matching entry exists in this level; a
   *     simple file name without separators.
   * @param maxSize soft budget in bytes for this container level; packing may reserve spare space
   *     below this value to accommodate metadata overhead.
   * @param parentName human-readable name used for logging to identify the directory being packed;
   *     may be {@code null} for the root.
   * @return the total accounted container size contribution from this level, including metadata
   *     overhead estimates.
   * @throws TooManyFilesInsertException If there are a ridiculous number of files in a single
   *     directory so we cannot complete the insert.
   */
  private long makePutHandlers(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      long maxSize,
      String parentName)
      throws TooManyFilesInsertException {
    if (LOG.isDebugEnabled())
      LOG.debug("STAT: handling {}", (parentName == null) ? "<root>?" : parentName);
    if (maxSize == DEFAULT_MAX_CONTAINERSIZE)
      maxSize = DEFAULT_MAX_CONTAINERSIZE - DEFAULT_CONTAINERSIZE_SPARE;

    // first get the size (the whole one)
    ContainerSize wholeSize =
        ContainerSizeEstimator.getSubTreeSize(
            manifestElements, DEFAULT_MAX_CONTAINERITEMSIZE, maxSize, Integer.MAX_VALUE);

    // Handle simple cases where the whole tree fits
    long handled =
        handleWholeTreeFits(containerBuilder, manifestElements, defaultName, maxSize, wholeSize);
    if (handled >= 0) return handled;

    long tmpSize = 0;

    // Handle case where root files fit into the container
    handled =
        handleRootFilesFit(containerBuilder, manifestElements, defaultName, maxSize, wholeSize);
    if (handled >= 0) return handled;

    // Space used by regular files if they are all put in as redirects.
    int minUsageForFiles = 0;

    // Redirects have to go first since we can't move them.
    RedirectStats redirectStats = extractRedirects(containerBuilder, manifestElements, defaultName);
    tmpSize += redirectStats.tmpSizeDelta;
    minUsageForFiles += redirectStats.minUsageForFiles;

    // (last) step three: handle subdirectories
    tmpSize =
        handleSubdirs(
            containerBuilder,
            manifestElements,
            defaultName,
            new SubdirContext(maxSize, wholeSize, minUsageForFiles),
            tmpSize);
    // fill up container with files
    FillFilesResult fillRes =
        fillContainerWithFiles(
            containerBuilder, manifestElements, defaultName, maxSize, tmpSize, minUsageForFiles);
    tmpSize = fillRes.tmpSize;
    minUsageForFiles = fillRes.minUsageForFiles;
    HashMap<String, Object> itemsLeft = new HashMap<>(fillRes.itemsLeft);
    assert (minUsageForFiles == 0);

    if (tmpSize > maxSize) throw new TooManyFilesInsertException();

    // group files left into external archives ('CHK@.../name' redirects)
    tmpSize = groupRemainingIntoArchives(containerBuilder, itemsLeft, defaultName, tmpSize);
    return tmpSize;
  }

  private long handleWholeTreeFits(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      long maxSize,
      ContainerSize wholeSize) {
    if (wholeSize.getSizeTotalNoLimit() <= maxSize) {
      if (LOG.isDebugEnabled())
        LOG.debug("PackStat2: the whole tree (unlimited) fits into container (no externals)");
      makeEveryThingUnlimitedPutHandlers(containerBuilder, manifestElements, defaultName);
      return wholeSize.getSizeTotalNoLimit();
    }

    if (wholeSize.getSizeTotal() <= maxSize) {
      if (LOG.isDebugEnabled())
        LOG.debug("PackStat2: the whole tree fits into container (with externals)");
      makeEveryThingPutHandlers(containerBuilder, manifestElements, defaultName);
      return wholeSize.getSizeTotal();
    }
    return -1;
  }

  private long handleRootFilesFit(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      long maxSize,
      ContainerSize wholeSize)
      throws TooManyFilesInsertException {
    if (!((wholeSize.getSizeFiles() < maxSize) || (wholeSize.getSizeFilesNoLimit() < maxSize))) {
      return -1;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "PackStat2: the files in dir fits into container with spare, so it need to grab stuff"
              + " from sub's to fill container up");
    boolean useNoLimit = (wholeSize.getSizeFilesNoLimit() < maxSize);
    long tmpSize =
        addRootFilesWhenFit(containerBuilder, manifestElements, defaultName, useNoLimit, wholeSize);
    tmpSize =
        fillSubdirsAfterRootFiles(
            containerBuilder, manifestElements, defaultName, maxSize, tmpSize);
    return tmpSize;
  }

  private long addRootFilesWhenFit(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      boolean useNoLimit,
      ContainerSize wholeSize) {
    long tmpSize = 0;
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof ManifestElement me) {
        if (!useNoLimit && (me.getSize() > DEFAULT_MAX_CONTAINERITEMSIZE)) {
          containerBuilder.addExternal(
              name, me.getData(), me.getMimeTypeOverride(), name.equals(defaultName));
        } else {
          containerBuilder.addItem(name, name, me, name.equals(defaultName));
        }
      } else {
        tmpSize += 512;
      }
    }
    tmpSize += useNoLimit ? wholeSize.getSizeFilesNoLimit() : wholeSize.getSizeFiles();
    return tmpSize;
  }

  private long fillSubdirsAfterRootFiles(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      long maxSize,
      long tmpSize)
      throws TooManyFilesInsertException {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof Map) {
        Map<String, Object> hm = Metadata.forceMap(o);
        if (tmpSize < maxSize - (512L * hm.size())) {
          containerBuilder.pushCurrentDir();
          containerBuilder.makeSubDirCD(name);
          tmpSize += makePutHandlers(containerBuilder, hm, defaultName, maxSize - tmpSize, name);
          containerBuilder.popCurrentDir();
        } else {
          ContainerBuilder subC = containerBuilder.makeSubContainer(name);
          makePutHandlers(subC, hm, defaultName, DEFAULT_MAX_CONTAINERSIZE, name);
        }
      }
    }
    return tmpSize;
  }

  private record RedirectStats(long tmpSizeDelta, int minUsageForFiles) {}

  private record SubdirContext(long maxSize, ContainerSize wholeSize, int minUsageForFiles) {}

  private RedirectStats extractRedirects(
      ContainerBuilder containerBuilder, Map<String, Object> manifestElements, String defaultName) {
    long tmpSizeDelta = 0;
    int minUsageForFiles = 0;
    Iterator<Map.Entry<String, Object>> iter = manifestElements.entrySet().iterator();
    while (iter.hasNext()) {
      Map.Entry<String, Object> entry = iter.next();
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof ManifestElement me) {
        if (me.getTargetURI() != null) {
          tmpSizeDelta += 512;
          containerBuilder.addItem(name, name, me, name.equals(defaultName));
          iter.remove();
        } else {
          minUsageForFiles += 512;
        }
      }
    }
    return new RedirectStats(tmpSizeDelta, minUsageForFiles);
  }

  private long handleSubdirs(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      SubdirContext subdirContext,
      long tmpSize)
      throws TooManyFilesInsertException {
    long maxSize = subdirContext.maxSize;
    ContainerSize wholeSize = subdirContext.wholeSize;
    int minUsageForFiles = subdirContext.minUsageForFiles;
    boolean subdirsFit =
        (wholeSize.getSizeSubTrees() + tmpSize + minUsageForFiles < maxSize)
            || (wholeSize.getSizeSubTreesNoLimit() + tmpSize + minUsageForFiles < maxSize);
    if (subdirsFit) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "PackStat2: the sub dirs fit into container with spare, so it need to grab files to"
                + " fill container up");
      boolean unlimited =
          (wholeSize.getSizeSubTreesNoLimit() + tmpSize + minUsageForFiles) < maxSize;
      tmpSize =
          processSubdirsFit(containerBuilder, manifestElements, defaultName, wholeSize, unlimited);
    } else {
      tmpSize =
          addEachSubdirInOwnContainer(containerBuilder, manifestElements, defaultName, tmpSize);
    }
    return tmpSize;
  }

  private record FillFilesResult(
      long tmpSize, int minUsageForFiles, HashMap<String, Object> itemsLeft) {}

  private FillFilesResult fillContainerWithFiles(
      ContainerBuilder containerBuilder,
      Map<String, Object> manifestElements,
      String defaultName,
      long maxSize,
      long tmpSize,
      int minUsageForFiles) {
    HashMap<String, Object> itemsLeft = new HashMap<>();
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof ManifestElement me) {
        long size = ContainerSizeEstimator.tarItemSize(me.getSize());
        if ((me.getSize() <= DEFAULT_MAX_CONTAINERITEMSIZE)
            && (size < (maxSize - (tmpSize + minUsageForFiles - 512 /* this one */)))) {
          containerBuilder.addItem(name, name, me, name.equals(defaultName));
          tmpSize += size;
          minUsageForFiles -= 512;
        } else {
          tmpSize += 512;
          minUsageForFiles -= 512;
          itemsLeft.put(name, me);
        }
      }
    }
    return new FillFilesResult(tmpSize, minUsageForFiles, itemsLeft);
  }

  private long groupRemainingIntoArchives(
      ContainerBuilder containerBuilder,
      Map<String, Object> itemsLeft,
      String defaultName,
      long tmpSize) {
    while (!itemsLeft.isEmpty()) {
      if (LOG.isDebugEnabled()) LOG.debug("ItemsLeft checker: {}", itemsLeft.size());

      if (itemsLeft.size() == 1) {
        handleSingleItemLeft(containerBuilder, itemsLeft, defaultName);
        itemsLeft.clear();
      } else {
        final long leftLimit = DEFAULT_MAX_CONTAINERSIZE - DEFAULT_CONTAINERSIZE_SPARE;
        ContainerSize leftSize =
            ContainerSizeEstimator.getSubTreeSize(
                itemsLeft, DEFAULT_MAX_CONTAINERITEMSIZE, leftLimit, 0);

        if (canFitIntoSingleArchive(leftSize)) {
          addAllToSingleArchive(containerBuilder, itemsLeft, defaultName);
          itemsLeft.clear();
        } else if (allTooBigOrRedirect(leftSize, itemsLeft.size())) {
          addAllAsExternalElements(containerBuilder, itemsLeft, defaultName);
          itemsLeft.clear();
        } else {
          tmpSize = fillPartialArchive(containerBuilder, itemsLeft, defaultName, tmpSize);
        }
      }
    }
    return tmpSize;
  }

  private void handleSingleItemLeft(
      ContainerBuilder containerBuilder, Map<String, Object> itemsLeft, String defaultName) {
    for (Map.Entry<String, Object> entry : itemsLeft.entrySet()) {
      String lname = entry.getKey();
      ManifestElement me = (ManifestElement) entry.getValue();
      containerBuilder.addElement(lname, me, lname.equals(defaultName));
    }
  }

  private boolean canFitIntoSingleArchive(ContainerSize leftSize) {
    return (leftSize.getSizeFiles() > 0)
        && (leftSize.getSizeFilesNoLimit()
            <= (DEFAULT_MAX_CONTAINERSIZE - DEFAULT_CONTAINERSIZE_SPARE));
  }

  private boolean allTooBigOrRedirect(ContainerSize leftSize, int itemsCount) {
    return ((leftSize.getSizeFiles() - (512L * itemsCount)) == 0)
        && (leftSize.getSizeFilesNoLimit() > 0);
  }

  private void addAllToSingleArchive(
      ContainerBuilder containerBuilder, Map<String, Object> itemsLeft, String defaultName) {
    ContainerBuilder archive = makeArchive();
    for (Map.Entry<String, Object> entry : itemsLeft.entrySet()) {
      String lname = entry.getKey();
      ManifestElement me = (ManifestElement) entry.getValue();
      containerBuilder.addArchiveItem(archive, lname, me, lname.equals(defaultName));
    }
  }

  private void addAllAsExternalElements(
      ContainerBuilder containerBuilder, Map<String, Object> itemsLeft, String defaultName) {
    for (Map.Entry<String, Object> entry : itemsLeft.entrySet()) {
      String lname = entry.getKey();
      ManifestElement me = (ManifestElement) entry.getValue();
      containerBuilder.addElement(lname, me, lname.equals(defaultName));
    }
  }

  private long fillPartialArchive(
      ContainerBuilder containerBuilder,
      Map<String, Object> itemsLeft,
      String defaultName,
      long tmpSize) {
    long archiveLimit = DEFAULT_CONTAINERSIZE_SPARE;
    ContainerBuilder archive = makeArchive();
    Iterator<Map.Entry<String, Object>> iter = itemsLeft.entrySet().iterator();
    while (iter.hasNext()) {
      Map.Entry<String, Object> entry = iter.next();
      String lname = entry.getKey();
      ManifestElement me = (ManifestElement) entry.getValue();
      if ((me.getSize() > -1)
          && (me.getSize() <= DEFAULT_MAX_CONTAINERITEMSIZE)
          && (me.getSize() < (DEFAULT_MAX_CONTAINERSIZE - archiveLimit))) {
        containerBuilder.addArchiveItem(archive, lname, me, lname.equals(defaultName));
        tmpSize += 512;
        archiveLimit += ContainerSizeEstimator.tarItemSize(me.getSize());
        iter.remove();
      }
    }
    return tmpSize;
  }

  /** Pack everything into a single container. */
  private void makeEveryThingUnlimitedPutHandlers(
      ContainerBuilder containerBuilder, Map<String, Object> manifestElements, String defaultName) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof ManifestElement element) {
        containerBuilder.addItem(name, name, element, name.equals(defaultName));
      } else {
        Map<String, Object> hm = Metadata.forceMap(o);
        containerBuilder.pushCurrentDir();
        containerBuilder.makeSubDirCD(name);
        makeEveryThingUnlimitedPutHandlers(containerBuilder, hm, defaultName);
        containerBuilder.popCurrentDir();
      }
    }
  }

  private void makeEveryThingPutHandlers(
      ContainerBuilder containerBuilder, Map<String, Object> manifestElements, String defaultName) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof ManifestElement element) {
        if (element.getSize() > DEFAULT_MAX_CONTAINERITEMSIZE)
          containerBuilder.addExternal(
              name, element.getData(), element.getMimeTypeOverride(), name.equals(defaultName));
        else containerBuilder.addItem(name, name, element, name.equals(defaultName));
      } else {
        Map<String, Object> hm = Metadata.forceMap(o);
        containerBuilder.pushCurrentDir();
        containerBuilder.makeSubDirCD(name);
        makeEveryThingPutHandlers(containerBuilder, hm, defaultName);
        containerBuilder.popCurrentDir();
      }
    }
  }

  @Override
  public void innerOnResume(ClientContext context) throws ResumeFailedException {
    super.innerOnResume(context);
    notifyClients(context);
  }
}
