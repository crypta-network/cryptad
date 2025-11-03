package network.crypta.node.useralerts;

/**
 * Base class for file-offer user alerts exchanged between nodes.
 *
 * <p>This abstract helper exists to make it convenient to create short-lived or anonymous
 * implementations of {@link NodeToNodeMessageUserAlert} that relate to offers or invitations to
 * transfer files between peers. It provides a stable type to extend so callers do not need to
 * implement multiple interfaces each time. Subclasses typically carry small amounts of immutable
 * metadata (for example, identifiers, human-readable titles, or sizes) and defer all behavior to
 * the surrounding system that dispatches and renders alerts to end users.
 *
 * <p>The class itself does not add state or behavior; it only narrows the intent of {@link
 * AbstractUserAlert}. Thread-safety and mutability are entirely determined by subclasses. In most
 * usages, instances are created, delivered to an alert bus or UI, and then allowed to be
 * garbage-collected once acknowledged or expired. Because the class is abstract, it cannot be
 * instantiated directly; extend it and supply any message details required by your application.
 *
 * <ul>
 *   <li>Scope: file-offer alerts exchanged across nodes.
 *   <li>Extensibility: designed for small, purpose-built subclasses.
 *   <li>Lifecycle: constructed, presented to the user, then discarded.
 * </ul>
 *
 * @see AbstractUserAlert
 * @see NodeToNodeMessageUserAlert
 */
public abstract class AbstractNodeToNodeFileOfferUserAlert extends AbstractUserAlert
    implements NodeToNodeMessageUserAlert {

  /**
   * Creates a new abstract file-offer user alert instance.
   *
   * <p>This constructor performs no initialization beyond the implicit invocation of the superclass
   * constructor. Subclasses are expected to capture any descriptive data (such as a file name, size
   * in bytes, or a peer reference) in their own fields and expose them via their public API.
   * Because this class is abstract, the constructor is primarily a convenience for subclasses and
   * cannot be invoked directly by application code.
   */
  protected AbstractNodeToNodeFileOfferUserAlert() {}
}
