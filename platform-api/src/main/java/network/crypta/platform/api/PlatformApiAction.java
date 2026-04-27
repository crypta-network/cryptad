package network.crypta.platform.api;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/**
 * Capability-protected Platform API action selected from request method and route shape.
 *
 * <p>An action is the router-independent authorization description for one request shape. The
 * capability matrix creates these values before endpoint dispatch so app principals can be checked
 * consistently and audit events can use the same labels for allowed and denied decisions. The
 * endpoint family is intentionally coarse, while the label is specific enough to distinguish
 * mutations such as {@code queue.requests.remove} from read-only access.
 *
 * <p>Capabilities are normalized into sorted immutable order during construction. That keeps JSON
 * output, audit entries, and tests deterministic even when a route requires more than one
 * capability, such as a queue insert that needs both content-insert and queue-write authority.
 *
 * @param endpointFamily top-level endpoint family such as {@code queue}
 * @param label short deterministic route/action label for audit output
 * @param requiredCapabilities sorted capabilities required from an app principal
 */
public record PlatformApiAction(
    String endpointFamily, String label, List<String> requiredCapabilities) {
  /**
   * Creates an immutable route-action descriptor.
   *
   * <p>The constructor trims textual fields, rejects blank values, and copies the capability list
   * into sorted immutable order. At least one capability is required because app principals are
   * default-deny and every mapped action must name the manifest permission that grants access.
   *
   * @throws IllegalArgumentException if the endpoint, label, or capability set is blank or empty
   * @throws NullPointerException if any required value or capability element is {@code null}
   */
  public PlatformApiAction {
    endpointFamily = requireText(endpointFamily, "endpointFamily");
    label = requireText(label, "label");
    requiredCapabilities = sortedCapabilities(requiredCapabilities);
    if (requiredCapabilities.isEmpty()) {
      throw new IllegalArgumentException("requiredCapabilities must not be empty");
    }
  }

  /**
   * Creates one action descriptor.
   *
   * <p>This factory is used by the capability matrix to keep route declarations compact. It does
   * not bypass validation; the canonical record constructor still enforces non-blank labels and
   * immutable sorted capabilities.
   *
   * @param endpointFamily top-level endpoint family used for grouping audit entries
   * @param label deterministic audit label for the matched request shape
   * @param requiredCapabilities capabilities required from app principals
   * @return validated route-action descriptor for authorization and audit logging
   */
  static PlatformApiAction of(
      String endpointFamily, String label, Collection<String> requiredCapabilities) {
    return new PlatformApiAction(endpointFamily, label, List.copyOf(requiredCapabilities));
  }

  /**
   * Returns the immutable sorted capability list required by this action.
   *
   * <p>A defensive copy is returned even though the record stores an immutable list. That keeps the
   * accessor behavior explicit and prevents callers from depending on the concrete list instance
   * retained by the record.
   *
   * @return immutable sorted capabilities required from an app principal
   */
  @Override
  public List<String> requiredCapabilities() {
    return List.copyOf(this.requiredCapabilities);
  }

  private static List<String> sortedCapabilities(Collection<String> source) {
    Objects.requireNonNull(source, "requiredCapabilities");
    TreeSet<String> sorted = new TreeSet<>();
    for (String capability : source) {
      sorted.add(requireText(capability, "requiredCapabilities value"));
    }
    return List.copyOf(sorted);
  }

  private static String requireText(String value, String label) {
    String text = Objects.requireNonNull(value, label).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
    return text;
  }
}
