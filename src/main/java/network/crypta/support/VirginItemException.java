package network.crypta.support;

import java.io.Serial;

/**
 * Signals that an intrusive list operation was attempted with an item that is not linked in a list
 * as required by the operation.
 *
 * <p>This unchecked exception is used by implementations of {@link DoublyLinkedList} when an
 * operation expects a specific anchor to already be part of a list (or to be positioned as head or
 * tail) but that precondition is not met. Typical cases include trying to stitch two {@link
 * DoublyLinkedList.Item} instances together when neither is currently a member of any list (a
 * "virgin" item), or when an anchor claims an impossible position relative to the list's recorded
 * head/tail invariants.
 *
 * <p>Thread-safety: list structures in this package are not thread-safe. Callers must use external
 * synchronization when accessing them concurrently.
 *
 * @see DoublyLinkedList
 * @see DoublyLinkedList.Item
 * @see PromiscuousItemException
 * @author tavin
 */
public class VirginItemException extends RuntimeException {
  // Stable serialization identifier for compatibility across versions.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception describing an item that is not linked as required.
   *
   * <p>The message is derived from {@code item.toString()} to aid diagnostics.
   *
   * @param item the problematic item; must not be {@code null}
   * @throws NullPointerException if {@code item} is {@code null}
   */
  VirginItemException(DoublyLinkedList.Item<?> item) {
    super(item.toString());
  }
}
