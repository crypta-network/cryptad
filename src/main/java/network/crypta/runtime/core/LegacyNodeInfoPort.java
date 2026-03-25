package network.crypta.runtime.core;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.Version;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.NodeGreetingSnapshot;
import network.crypta.runtime.spi.NodeInfoPort;
import network.crypta.runtime.spi.NodeReferenceSnapshot;
import network.crypta.runtime.spi.NodeReferenceView;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.compress.Compressor;

/**
 * Adapts the daemon's legacy node-info exports to the runtime SPI's {@link NodeInfoPort}.
 *
 * <p>This bridge keeps knowledge of {@link Node}, {@link Version}, {@link NodeL10n}, {@link
 * Compressor}, and {@link SimpleFieldSet} inside the daemon root module while exposing only
 * SPI-local DTOs to management-facing code. It preserves the current export semantics by delegating
 * directly to the daemon's existing node-reference and greeting metadata sources.
 *
 * <p>The adapter is intentionally small and read-only. It does not make access-control decisions
 * and does not perform any FCP framing. Its job is limited to collecting the daemon state needed
 * for the current node-info slice and translating legacy {@link SimpleFieldSet} trees into the
 * immutable runtime-spi DTOs used by higher layers.
 */
final class LegacyNodeInfoPort implements NodeInfoPort {
  /** Subset name used when volatile export data is attached to the root reference tree. */
  private static final String VOLATILE_SUBSET = "volatile";

  /** Live daemon node that remains the source of greeting and node-reference exports. */
  private final Node node;

  /**
   * Creates a node-info adapter for one running daemon node.
   *
   * @param node live daemon node whose legacy exports back this adapter
   */
  LegacyNodeInfoPort(Node node) {
    this.node = Objects.requireNonNull(node);
  }

  @Override
  public NodeGreetingSnapshot greeting() {
    return new NodeGreetingSnapshot(
        Version.NODE_NAME,
        Version.getVersionString(),
        Version.currentBuildNumber(),
        Version.gitRevision(),
        Node.isTestnetEnabled(),
        Compressor.COMPRESSOR_TYPE.getHelloCompressorDescriptor(),
        NodeL10n.getBase().getSelectedLanguage().toString());
  }

  @Override
  public NodeReferenceSnapshot exportReference(NodeReferenceView view, boolean includeVolatile) {
    Objects.requireNonNull(view, "view");

    NodeFieldSet root = toNodeFieldSet(exportBaseReference(view));
    if (!includeVolatile) {
      return new NodeReferenceSnapshot(root);
    }

    NodeFieldSet volatileFieldSet = toNodeFieldSet(node.network().exportVolatileFieldSet());
    if (volatileFieldSet.isEmpty()) {
      return new NodeReferenceSnapshot(root);
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(root.directValues());
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>(root.directSubsets());
    directSubsets.put(VOLATILE_SUBSET, volatileFieldSet);
    return new NodeReferenceSnapshot(new NodeFieldSet(directValues, directSubsets));
  }

  /**
   * Selects the legacy daemon export that corresponds to one runtime-spi reference view.
   *
   * @param view requested node-reference view from the management-facing SPI
   * @return legacy field-set export that matches the requested reference visibility and network
   */
  private SimpleFieldSet exportBaseReference(NodeReferenceView view) {
    return switch (view) {
      case DARKNET_PUBLIC -> node.network().exportDarknetPublicFieldSet();
      case DARKNET_PRIVATE -> node.network().exportDarknetPrivateFieldSet();
      case OPENNET_PUBLIC -> node.network().exportOpennetPublicFieldSet();
      case OPENNET_PRIVATE -> node.network().exportOpennetPrivateFieldSet();
    };
  }

  /**
   * Converts one legacy field-set tree into the immutable runtime-spi node tree.
   *
   * <p>Only direct values and non-empty child subsets are retained at each level. That matches the
   * export shape expected by the current node-info slice while avoiding empty placeholder nodes in
   * the resulting snapshot.
   *
   * @param fieldSet legacy field-set tree to convert
   * @return immutable node tree representing the same exported structure
   */
  private static NodeFieldSet toNodeFieldSet(SimpleFieldSet fieldSet) {
    if (fieldSet.isEmpty()) {
      return NodeFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(fieldSet.directKeyValues());
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : fieldSet.directSubsets().entrySet()) {
      NodeFieldSet subset = toNodeFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new NodeFieldSet(directValues, directSubsets);
  }
}
