package network.crypta.client.async;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.Metadata;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts a directory tree as a plain manifest in which every file entry is stored as an individual
 * redirect (no container archives are created).
 *
 * <p>This implementation operates in freeform mode: each leaf file is inserted independently and
 * the resulting top-level manifest contains redirects pointing to those file objects. This keeps
 * updates straightforward because files are not bundled together, at the cost of more distinct
 * objects when many files are present.
 *
 * <p>Typical usage is to construct an instance with a nested map describing the directory layout
 * (keys are names; values are either {@link java.util.Map} for subdirectories or {@link
 * network.crypta.support.api.ManifestElement} for files), choose a default document name, and then
 * start the insert via the {@link ManifestPutter} lifecycle. Coordination of asynchronous work,
 * progress reporting, and completion is handled by {@link BaseManifestPutter}.
 *
 * <ul>
 *   <li><strong>Structure:</strong> Any value that implements {@link java.util.Map} is treated as a
 *       subdirectory and normalized internally; map immutability is supported.
 *   <li><strong>Default document:</strong> The {@code defaultName} is compared to file names within
 *       each directory to mark that file as the default document for the directory.
 *   <li><strong>Concurrency:</strong> Network operations and callbacks are coordinated by the base
 *       class and the client context. This class expects the manifest structure to be immutable
 *       while inserts are running.
 * </ul>
 *
 * @see DefaultManifestPutter
 * @see BaseManifestPutter
 */
public class PlainManifestPutter extends BaseManifestPutter {
  private static final Logger LOG = LoggerFactory.getLogger(PlainManifestPutter.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Creates a putter that stores every file as an individual redirect and composes a simple
   * directory-like manifest referencing those redirects.
   *
   * <p>The supplied {@code manifestElements} describes the directory tree. Keys are entry names.
   * Values must be either another {@link java.util.Map} (subdirectory) or a {@link
   * network.crypta.support.api.ManifestElement} (file/redirect). Any {@link java.util.Map}
   * implementation is accepted, including immutable maps; the structure is normalized internally.
   * The {@code defaultName} is compared against file names within each directory to identify the
   * default document.
   *
   * <p>The constructor captures configuration only. Use the standard {@link ManifestPutter}
   * lifecycle (for example, {@code start(context)}) to begin the asynchronous insert. The callback
   * receives progress and completion signals.
   *
   * <pre>{@code
   * // Example: minimal tree with a subdirectory and a default document
   * Map<String, Object> sub = Map.of("index.html", elementIndex);
   * Map<String, Object> root = new HashMap<>();
   * root.put("dir", sub);
   * root.put("readme.txt", elementReadme);
   * var params = new ManifestPutterParams(cb, root, prio, target, "index.html", ctx, key, context);
   * var putter = new PlainManifestPutter(params);
   * }</pre>
   *
   * @param params shared manifest putter parameters including callback, manifest map, and context
   *     required by the base putter.
   * @throws TooManyFilesInsertException if the manifest contains more items than supported or
   *     exceeds structural limits during handler creation.
   */
  public PlainManifestPutter(ManifestPutterParams params) throws TooManyFilesInsertException {
    super(
        new InitParams()
            .withCb(params.clientCallback())
            .withManifestElements(params.manifestElements())
            .withPrioClass(params.prioClass())
            .withTarget(params.target())
            .withDefaultName(params.defaultName())
            .withCtx(params.ctx())
            .withRandomiseCryptoKeys(
                ClientPutter.randomiseSplitfileKeys(params.target(), params.ctx()))
            .withForceCryptoKey(params.forceCryptoKey())
            .withContext(params.context()));
  }

  /**
   * Builds freeform put handlers for the provided manifest tree and marks default documents.
   *
   * <p>This override arranges the root builder and delegates to the internal, map-aware recursive
   * helper. It treats any {@link java.util.Map} value as a subdirectory and casts leaf values to
   * {@link network.crypta.support.api.ManifestElement}. The tree is expected to contain only
   * supported value types.
   *
   * @param manifestElements normalized map of entry names to sub-maps or manifest elements; must
   *     not be {@code null}.
   * @param defaultName name considered the default document within each directory; matched by exact
   *     equality against child file entries.
   */
  @Override
  protected void makePutHandlers(HashMap<String, Object> manifestElements, String defaultName) {
    if (LOG.isTraceEnabled()) LOG.trace("Root map : {} elements", manifestElements.size());
    makePutHandlers(getRootBuilder(), manifestElements, defaultName);
  }

  /**
   * Recursively visits the manifest tree to create put handlers and directory structure.
   *
   * <p>Any {@link java.util.Map} value is treated as a subdirectory and normalized via {@link
   * network.crypta.client.Metadata#forceMap(Object)} before recursing. All other values are cast to
   * {@link network.crypta.support.api.ManifestElement} and added as files. The default document is
   * identified by comparing {@code defaultName} to the child file name.
   *
   * @param builder builder bound to the current directory; used to push/pop and add elements.
   * @param manifestElements current directory entries mapping names to sub-maps or manifest
   *     elements; never {@code null}.
   * @param defaultName name of the default document for the current directory; may be {@code null}
   *     when no default applies.
   */
  private void makePutHandlers(
      FreeFormBuilder builder, Map<String, Object> manifestElements, Object defaultName) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof Map) {
        Map<String, Object> subMap = Metadata.forceMap(o);
        builder.pushCurrentDir();
        builder.makeSubDirCD(name);
        makePutHandlers(builder, subMap, defaultName);
        builder.popCurrentDir();
        if (LOG.isTraceEnabled()) LOG.trace("Sub map for {} : {} elements", name, subMap.size());
      } else {
        ManifestElement element = (ManifestElement) o;
        builder.addElement(name, element, name.equals(defaultName));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void innerOnResume(ClientContext context) throws ResumeFailedException {
    super.innerOnResume(context);
    notifyClients(context);
  }
}
