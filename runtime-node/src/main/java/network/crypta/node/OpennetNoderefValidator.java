package network.crypta.node;

import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses and validates opennet node references ("noderefs").
 *
 * <p>This utility owns the parsing/validation logic for compressed noderefs and updates the
 * session-level network size estimate when an identity is observed.
 */
public final class OpennetNoderefValidator {

  private static final Logger LOG = LoggerFactory.getLogger(OpennetNoderefValidator.class);

  private OpennetNoderefValidator() {}

  /**
   * Validate and parse a compressed noderef.
   *
   * <p>On success, this method also registers the noderef identity (when present) for the
   * session-level opennet size estimate.
   *
   * @param noderef compressed noderef bytes
   * @param from peer the noderef came from (for logging); may be {@code null}
   * @param forceOpennetEnabled if {@code true}, inject {@code opennet=true} into the parsed ref
   * @return parsed {@link SimpleFieldSet} when valid; {@code null} otherwise
   */
  public static SimpleFieldSet validateNoderef(
      byte[] noderef, PeerNode from, boolean forceOpennetEnabled) {
    SimpleFieldSet ref;
    try {
      ref = PeerNodeReferenceSupport.compressedNoderefToFieldSet(noderef, 0, noderef.length);
    } catch (FSParseException e) {
      LOG.error("Invalid noderef: {}", e, e);
      return null;
    }
    if (forceOpennetEnabled) ref.put("opennet", true);

    if (!OpennetPeerNode.validateRef(ref)) {
      LOG.error("Could not parse opennet noderef from {}", from);
      return null;
    }

    String identity = ref.get("identity");
    if (identity != null) { // N2N_MESSAGE_TYPE_DIFFNODEREF don't have identity
      OpennetManager.registerKnownIdentity(identity);
    }
    return ref;
  }
}
