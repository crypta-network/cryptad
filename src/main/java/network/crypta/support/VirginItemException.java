package network.crypta.support;

import java.io.Serial;

/**
 * Indicates an attempt to link two DoublyLinkedList.Item's, neither of which are a member of a
 * DoublyLinkedList.
 *
 * @author tavin
 */
public class VirginItemException extends RuntimeException {
  @Serial private static final long serialVersionUID = -1;

  VirginItemException(DoublyLinkedList.Item<?> item) {
    super(item.toString());
  }
}
