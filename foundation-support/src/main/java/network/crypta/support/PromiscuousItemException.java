package network.crypta.support;

import java.io.Serial;
import network.crypta.support.DoublyLinkedList.Item;

/**
 * Signals a violation of the intrusive list single-parent invariant.
 *
 * <p>This unchecked exception is thrown when code attempts to link a {@link DoublyLinkedList.Item}
 * into multiple {@link DoublyLinkedList} instances at the same time, or to link the same item more
 * than once into a single list. It may also be used when an operation targets an item that belongs
 * to a different list than the one performing the operation.
 *
 * <p>Rationale: {@code DoublyLinkedList.Item} is designed to be linked into exactly one parent list
 * at a time. Reusing an already-linked item would corrupt neighbor links or parent references and
 * is therefore rejected with this exception.
 *
 * <p>Thread-safety: list structures in this package are not thread-safe. Callers must provide
 * external synchronization if used concurrently.
 *
 * @author tavin
 */
public class PromiscuousItemException extends RuntimeException {

  // Stable serialization identifier for compatibility across versions.
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception describing an already-linked or otherwise invalid item.
   *
   * <p>The message is derived from {@code item.toString()} to aid diagnostics.
   *
   * @param item the problematic element; must not be {@code null}
   * @throws NullPointerException if {@code item} is {@code null}
   */
  PromiscuousItemException(DoublyLinkedList.Item<?> item) {
    super(item.toString());
  }

  /**
   * Creates an exception describing a conflict between an item and its (other) parent list.
   *
   * <p>The message includes the string forms of {@code item} and {@code parent} to make it easier
   * to spot mismatches in logs.
   *
   * @param item the element already linked elsewhere; must not be {@code null}
   * @param parent the list the element currently belongs to; may be {@code null} if unknown
   * @throws NullPointerException if {@code item} is {@code null}
   */
  public PromiscuousItemException(Item<?> item, DoublyLinkedList<?> parent) {
    super(item.toString() + ':' + parent);
  }
}
