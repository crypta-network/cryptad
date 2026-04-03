package network.crypta.platform.api.json;

import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.runtime.spi.ConfigFieldSet;
import network.crypta.runtime.spi.NodeFieldSet;
import network.crypta.runtime.spi.PeerFieldSet;

/**
 * Converts detached runtime field-set trees into nested JSON objects.
 *
 * <p>The Platform API exposes the existing runtime field-set trees as ordinary JSON objects. Direct
 * scalar values appear first in encounter order, followed by child subsets rendered recursively as
 * nested objects. This mirrors the logical shape already reconstructed for FCP field sets without
 * introducing wrapper noise at each tree level.
 */
public final class PlatformApiFieldSetJson {
  /** Prevents instantiation of this static helper type. */
  private PlatformApiFieldSetJson() {}

  /**
   * Converts one node-reference field-set tree into a nested JSON object.
   *
   * @param fieldSet detached runtime node-reference tree
   * @return encounter-order-preserving JSON object representation
   */
  public static Map<String, Object> toJson(NodeFieldSet fieldSet) {
    LinkedHashMap<String, Object> json =
        LinkedHashMap.newLinkedHashMap(
            fieldSet.directValues().size() + fieldSet.directSubsets().size());
    json.putAll(fieldSet.directValues());
    fieldSet.directSubsets().forEach((name, subset) -> json.put(name, toJson(subset)));
    return json;
  }

  /**
   * Converts one peer field-set tree into a nested JSON object.
   *
   * @param fieldSet detached runtime peer tree
   * @return encounter-order-preserving JSON object representation
   */
  public static Map<String, Object> toJson(PeerFieldSet fieldSet) {
    LinkedHashMap<String, Object> json =
        LinkedHashMap.newLinkedHashMap(
            fieldSet.directValues().size() + fieldSet.directSubsets().size());
    json.putAll(fieldSet.directValues());
    fieldSet.directSubsets().forEach((name, subset) -> json.put(name, toJson(subset)));
    return json;
  }

  /**
   * Converts one configuration field-set tree into a nested JSON object.
   *
   * @param fieldSet detached runtime configuration tree
   * @return encounter-order-preserving JSON object representation
   */
  public static Map<String, Object> toJson(ConfigFieldSet fieldSet) {
    LinkedHashMap<String, Object> json =
        LinkedHashMap.newLinkedHashMap(
            fieldSet.directValues().size() + fieldSet.directSubsets().size());
    json.putAll(fieldSet.directValues());
    fieldSet.directSubsets().forEach((name, subset) -> json.put(name, toJson(subset)));
    return json;
  }
}
