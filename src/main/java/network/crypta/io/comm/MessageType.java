package network.crypta.io.comm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import network.crypta.support.Serializer;
import network.crypta.support.ShortBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Describes the schema of an application message and maintains a registry of known types.
 *
 * <p>A MessageType records field names with their Java types and the order in which fields are
 * encoded. Instances are registered in a process-wide map keyed by {@code name.hashCode()} so they
 * can be resolved when decoding by identifier. The mapping is legacy behavior and may be subject to
 * hash collisions; callers should not rely on the numeric identifier being globally unique.
 */
public class MessageType {
  private static final Logger LOG = LoggerFactory.getLogger(MessageType.class);

  /** Source-control marker string retained for historical reference. Not used by runtime logic. */
  public static final String VERSION =
      "$Id: MessageType.java,v 1.6 2005/08/25 17:28:19 amphibian Exp $";

  private static final HashMap<Integer, MessageType> _specs = new HashMap<>();

  private final String name;
  private final List<String> orderedFields = new ArrayList<>();
  private final HashMap<String, Class<?>> fields = new HashMap<>();
  private final HashMap<String, Class<?>> linkedListTypes = new HashMap<>();
  private final boolean internalOnly;
  private final short priority;
  private final boolean isLossyPacketMessage;

  /**
   * Creates and registers a message type with the given name and default priority.
   *
   * @param name human-readable name; its {@link String#hashCode()} becomes the registry key
   * @param priority default priority used when enqueuing messages of this type
   * @throws DuplicateMessageTypeException if a type with the same hash identifier already exists
   */
  public MessageType(String name, short priority) {
    this(name, priority, false, false);
  }

  /**
   * Creates and registers a message type and configures optional transport flags.
   *
   * <p>The instance is inserted into the global registry keyed by {@code name.hashCode()}.
   *
   * @param name human-readable name; also used to derive the registry identifier
   * @param priority default priority used for outbound scheduling
   * @param internal whether messages of this type are internal-only (e.g., not accepted over UDP)
   * @param isLossyPacketMessage whether the type is eligible for lossy packet transport
   * @throws DuplicateMessageTypeException if a type with the same hash identifier already exists
   */
  public MessageType(String name, short priority, boolean internal, boolean isLossyPacketMessage) {
    this.name = name;
    this.priority = priority;
    this.isLossyPacketMessage = isLossyPacketMessage;
    internalOnly = internal;
    // XXX: Using name.hashCode() as an identifier risks collisions; this is legacy behavior.
    Integer id = name.hashCode();
    if (_specs.containsKey(id)) {
      throw new DuplicateMessageTypeException(
          "A message type by the name of " + name + " already exists!");
    }
    _specs.put(id, this);
  }

  /**
   * Removes this instance from the global registry.
   *
   * <p>After calling this method, {@link #getSpec(Integer, boolean)} with this type's identifier
   * returns {@code null}.
   */
  public void unregister() {
    _specs.remove(name.hashCode());
  }

  /**
   * Adds a field of type {@link LinkedList} and records the element type for that list field.
   *
   * <p>The field name is also appended to the ordered field list.
   *
   * @param name field name
   * @param parameter the list element type (e.g., {@code Integer.class})
   */
  public void addLinkedListField(String name, Class<?> parameter) {
    linkedListTypes.put(name, parameter);
    addField(name, LinkedList.class);
  }

  /**
   * Adds a field definition.
   *
   * <p>The field is stored by name with its declared Java type and its name is appended to the
   * ordered field list. If the same field name is added multiple times, the most recent type wins.
   *
   * @param name field name
   * @param type declared Java type for values assigned to this field
   */
  public void addField(String name, Class<?> type) {
    fields.put(name, type);
    orderedFields.add(name);
  }

  /**
   * Adds common routing-related fields used by node-to-node messages.
   *
   * <p>Fields are identified by constants in {@link DMT}: {@code UID} ({@link Long}), {@code
   * TARGET_LOCATION} ({@link Double}), {@code HTL} ({@link Short}), and {@code NODE_IDENTITY}
   * ({@link ShortBuffer}).
   */
  public void addRoutedToNodeMessageFields() {
    addField(DMT.UID, Long.class);
    addField(DMT.TARGET_LOCATION, Double.class);
    addField(DMT.HTL, Short.class);
    addField(DMT.NODE_IDENTITY, ShortBuffer.class);
  }

  /**
   * Verifies that a value is assignment-compatible with the declared type of field.
   *
   * @param fieldName the field to check
   * @param fieldValue the value to test; {@code null} returns {@code false}
   * @return {@code true} if {@code fieldValue.getClass()} is equal to, or a subclass/implementation
   *     of, the declared field type; {@code false} if the value is {@code null} or incompatible
   * @throws IllegalStateException if {@code fieldName} is not defined for this type
   */
  public boolean checkType(String fieldName, Object fieldValue) {
    if (fieldValue == null) {
      return false;
    }
    Class<?> defClass = fields.get(fieldName);
    if (defClass == null) {
      throw new IllegalStateException(
          "Cannot set field \""
              + fieldName
              + "\" which is not defined"
              + " in the message type \""
              + getName()
              + "\".");
    }
    Class<?> valueClass = fieldValue.getClass();
    if (defClass == valueClass) return true;
    return defClass.isAssignableFrom(valueClass);
  }

  /**
   * Returns the declared Java type for a field.
   *
   * @param field field name
   * @return the {@link Class} for the field, or {@code null} if the name is not defined
   */
  public Class<?> typeOf(String field) {
    return fields.get(field);
  }

  /**
   * Compares by {@code name} reference identity.
   *
   * <p>Equality relies on registration behavior that typically yields a single instance per logical
   * name.
   */
  @Override
  @SuppressWarnings("ReferenceEquality")
  public boolean equals(Object o) {
    if (!(o instanceof MessageType other)) {
      return false;
    }
    // Intentionally use reference equality for the name based on registration semantics.
    //noinspection StringEquality
    return other.name == name;
  }

  /**
   * Computes a hash code from the {@code name} string.
   *
   * @return {@code name.hashCode()}
   */
  @Override
  public int hashCode() {
    return name.hashCode();
  }

  /**
   * Resolves a registered message type by its hashed identifier.
   *
   * <p>When {@code dontLog} is {@code false}, unknown IDs are logged at INFO. Unknown types can
   * occur due to version skew or malformed traffic and are not necessarily fatal.
   *
   * @param specID identifier derived from {@code name.hashCode()}
   * @param dontLog if {@code true}, suppresses INFO logging when the ID is not present
   * @return the matching {@code MessageType}, or {@code null} if not registered
   */
  public static MessageType getSpec(Integer specID, boolean dontLog) {
    MessageType id = _specs.get(specID);
    if (id == null && !dontLog) LOG.info("Unrecognised message type received ({})", specID);

    return id;
  }

  /**
   * Returns the human-readable name for this type.
   *
   * @return the name used when the type was created
   */
  public String getName() {
    return name;
  }

  /**
   * Returns the mapping of field names to declared Java types.
   *
   * <p>The returned map is backed by this instance and is mutable; changes affect the message type.
   *
   * @return live map of field definitions
   */
  public Map<String, Class<?>> getFields() {
    return fields;
  }

  /**
   * Returns field names in their defined encoding order.
   *
   * <p>The returned list is backed by this instance and is mutable.
   *
   * @return live list of field names in order
   */
  public List<String> getOrderedFields() {
    return orderedFields;
  }

  /**
   * Returns element types for fields declared as {@link LinkedList}.
   *
   * <p>The map keys are field names; values are the corresponding element {@link Class} objects.
   * The returned map is backed by this instance and is mutable.
   *
   * @return live map of list field element types
   */
  public Map<String, Class<?>> getLinkedListTypes() {
    return linkedListTypes;
  }

  /**
   * Indicates whether this type is internal-only.
   *
   * <p>If {@code true}, incoming UDP messages with this spec are silently discarded.
   *
   * @return {@code true} if internal-only; {@code false} otherwise
   */
  public boolean isInternalOnly() {
    return internalOnly;
  }

  /**
   * Returns the default priority associated with this type.
   *
   * <p>Senders may raise the effective priority dynamically (e.g., for real-time traffic).
   *
   * @return default priority value
   */
  public short getDefaultPriority() {
    return priority;
  }

  /**
   * Estimates the maximum encoded size, in bytes, for simple messages.
   *
   * <p>This mirrors {@code Message.encodeToPacket}. It sums the fixed sizes for known field types
   * and uses {@code 4 + 2*maxStringLength} for strings. This method is not suitable for complex
   * structures such as nested collections beyond {@link LinkedList} placeholders.
   *
   * @param maxStringLength maximum number of characters assumed for string fields
   * @return upper bound on the encoded size in bytes
   * @throws IllegalArgumentException if any field type is unsupported by {@link Serializer#length}
   */
  public int getMaxSize(int maxStringLength) {
    // This method mirrors Message.encodeToPacket.
    int length = 0;
    length += 4; // _spec.getName().hashCode()
    for (Map.Entry<String, Class<?>> entry : fields.entrySet()) {
      length += Serializer.length(entry.getValue(), maxStringLength);
    }
    return length;
  }

  /**
   * Indicates whether this type is intended for lossy packet transport.
   *
   * @return {@code true} if lossy packet encoding is permitted
   */
  public boolean isLossyPacketMessage() {
    return isLossyPacketMessage;
  }
}
