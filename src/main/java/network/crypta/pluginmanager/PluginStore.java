package network.crypta.pluginmanager;

import java.util.HashMap;
import java.util.Map;
import network.crypta.node.FSParseException;
import network.crypta.support.Base64;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;

/**
 * Holds plugin-owned primitive values and nested stores that can be serialized to a {@link
 * SimpleFieldSet}.
 *
 * <p>A {@code PluginStore} acts as a lightweight, hierarchical key/value container for plugins that
 * need to persist small pieces of state without introducing custom serialization formats. Each
 * supported primitive type (and its array form) has a dedicated map, and nested stores allow a tree
 * of data to be represented. Keys are stored as UTF-8 strings and are encoded when written to a
 * {@link SimpleFieldSet} to keep the external representation stable and safe for transport.
 *
 * <p>Typical usage is to populate the relevant maps, call {@link #exportStoreAsSFS()} to obtain a
 * {@link SimpleFieldSet}, and later reconstruct a store from that field set. The class performs no
 * validation beyond Base64 decoding and field-set parsing; callers are expected to treat the maps
 * as the single source of truth and manage key lifecycles themselves. This type is mutable and not
 * thread-safe; coordinate access if multiple threads can mutate a store concurrently.
 *
 * <p>Notable behaviors include:
 *
 * <ul>
 *   <li>Keys are encoded per-group when serializing and decoded on load.
 *   <li>Absent groups are treated as empty without raising errors.
 *   <li>Nested {@code PluginStore} instances are serialized recursively.
 * </ul>
 *
 * @author Artefact2
 * @see SimpleFieldSet
 */
public class PluginStore {

  /**
   * Holds nested stores indexed by logical key names.
   *
   * <p>Each entry represents a subtree of related values. The map is mutable and directly writable
   * by callers; a missing key implies no subtree. Keys are UTF-8 strings and are Base64-encoded
   * when written to a {@link SimpleFieldSet} through {@link #exportStoreAsSFS()}.
   */
  public final Map<String, PluginStore> subStores = new HashMap<>();

  /**
   * Holds {@code long} values indexed by logical key names.
   *
   * <p>Entries are mutable and may be replaced or removed by callers. Values are persisted as
   * scalar fields in the serialized representation. Keys are encoded on export and decoded when
   * reading from a {@link SimpleFieldSet}.
   */
  public final Map<String, Long> longs = new HashMap<>();

  /**
   * Holds {@code long[]} values indexed by logical key names.
   *
   * <p>Array contents are stored as-is and serialized via {@link SimpleFieldSet}. The map is
   * mutable and supports in-place replacement of values. Keys are encoded when exporting to ensure
   * that arbitrary UTF-8 names remain safe in the field-set format.
   */
  public final Map<String, long[]> longsArrays = new HashMap<>();

  /**
   * Holds {@code int} values indexed by logical key names.
   *
   * <p>The map is mutable and directly writable. Values are exported as scalar integer fields, and
   * keys are Base64-encoded during serialization. Missing keys imply no stored value for that name.
   */
  public final Map<String, Integer> integers = new HashMap<>();

  /**
   * Holds {@code int[]} values indexed by logical key names.
   *
   * <p>Array contents are stored without transformation and serialized using the field-set array
   * support. This map is mutable and not thread-safe; coordinate access if shared across threads.
   */
  public final Map<String, int[]> integersArrays = new HashMap<>();

  /**
   * Holds {@code short} values indexed by logical key names.
   *
   * <p>Values are serialized as scalar fields in the {@link SimpleFieldSet}. The map is mutable and
   * directly writable; keys are encoded on export and decoded on import.
   */
  public final Map<String, Short> shorts = new HashMap<>();

  /**
   * Holds {@code short[]} values indexed by logical key names.
   *
   * <p>Array contents are stored directly and serialized via {@link SimpleFieldSet}. Keys are
   * Base64-encoded during export to preserve arbitrary UTF-8 identifiers.
   */
  public final Map<String, short[]> shortsArrays = new HashMap<>();

  /**
   * Holds {@code boolean} values indexed by logical key names.
   *
   * <p>Entries are mutable and represent scalar flags in the serialized form. Keys are encoded on
   * export and decoded on import; absent keys are treated as missing values.
   */
  public final Map<String, Boolean> booleans = new HashMap<>();

  /**
   * Holds {@code boolean[]} values indexed by logical key names.
   *
   * <p>Array contents are stored as provided and serialized using the field-set array support. The
   * map is mutable and may be updated by callers as plugin state evolves.
   */
  public final Map<String, boolean[]> booleansArrays = new HashMap<>();

  /**
   * Holds {@code byte} values indexed by logical key names.
   *
   * <p>Values are serialized as scalar fields in the {@link SimpleFieldSet}. The map is mutable and
   * directly writable; keys are encoded in Base64 during serialization.
   */
  public final Map<String, Byte> bytes = new HashMap<>();

  /**
   * Holds {@code byte[]} values indexed by logical key names.
   *
   * <p>Array contents are stored directly and serialized using the field-set array support. Keys
   * are encoded on export to keep the external representation safe for transport and storage.
   */
  public final Map<String, byte[]> bytesArrays = new HashMap<>();

  /**
   * Holds {@link String} values indexed by logical key names.
   *
   * <p>Values are serialized as single fields using {@link SimpleFieldSet#putSingle(String,
   * String)}. The map is mutable and directly writable; keys are Base64-encoded on export and
   * decoded on import.
   */
  public final Map<String, String> strings = new HashMap<>();

  /**
   * Holds {@link String} array values indexed by logical key names.
   *
   * <p>Array contents are serialized with {@link SimpleFieldSet#putEncoded(String, String[])},
   * which preserves ordering. Keys are encoded on export, and the map is mutable for caller-managed
   * updates.
   */
  public final Map<String, String[]> stringsArrays = new HashMap<>();

  /**
   * Creates an empty {@code PluginStore} with no predefined keys or values.
   *
   * <p>This constructor initializes all maps to empty, mutable instances. It performs no I/O and is
   * side-effect free, so it is safe to call repeatedly. After construction, callers should populate
   * the maps directly before exporting or passing the store to other components.
   */
  public PluginStore() {
    // Default constructor. See below for constructor from SFS.
  }

  /**
   * Serializes the current store contents to a {@link SimpleFieldSet}.
   *
   * <p>The resulting field set contains one subgroup per primitive type plus recursive substore
   * groups. Keys are UTF-8 and Base64-encoded to ensure they are safe in the serialized format.
   * Empty maps are represented by omission of the corresponding subgroup. The returned value is a
   * new field set that is independent of this store; subsequent mutations to the store do not
   * affect the previously exported field set.
   *
   * <p>Example:
   *
   * <pre>{@code
   * PluginStore store = new PluginStore();
   * store.strings.put("name", "demo");
   * SimpleFieldSet fs = store.exportStoreAsSFS();
   * }</pre>
   *
   * @return a newly created {@link SimpleFieldSet} representing the current store contents
   */
  public SimpleFieldSet exportStoreAsSFS() {
    SimpleFieldSet fs = new SimpleFieldSet(true, true);
    for (Map.Entry<String, PluginStore> entry : subStores.entrySet()) {
      fs.put("substore." + encode(entry.getKey()), entry.getValue().exportStoreAsSFS());
    }
    for (Map.Entry<String, Long> entry : longs.entrySet()) {
      fs.put("long." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, long[]> entry : longsArrays.entrySet()) {
      fs.put("longs." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, Integer> entry : integers.entrySet()) {
      fs.put("integer." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, int[]> entry : integersArrays.entrySet()) {
      fs.put("integers." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, Short> entry : shorts.entrySet()) {
      fs.put("short." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, short[]> entry : shortsArrays.entrySet()) {
      fs.put("shorts." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, Byte> entry : bytes.entrySet()) {
      fs.put("byte." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, byte[]> entry : bytesArrays.entrySet()) {
      fs.put("bytes." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, Boolean> entry : booleans.entrySet()) {
      fs.put("boolean." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, boolean[]> entry : booleansArrays.entrySet()) {
      fs.put("booleans." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, String> entry : strings.entrySet()) {
      fs.putSingle("string." + encode(entry.getKey()), entry.getValue());
    }
    for (Map.Entry<String, String[]> entry : stringsArrays.entrySet()) {
      fs.putEncoded("strings." + encode(entry.getKey()), entry.getValue());
    }
    return fs;
  }

  /**
   * Constructs a {@code PluginStore} by reading a serialized {@link SimpleFieldSet}.
   *
   * <p>This constructor decodes each supported subgroup and populates the corresponding maps.
   * Missing subgroups are treated as empty, and nested stores are constructed recursively. The
   * provided field set is not modified. The resulting store is mutable and may be extended or
   * edited after construction.
   *
   * <p>Example:
   *
   * <pre>{@code
   * PluginStore store = new PluginStore(fieldSet);
   * String name = store.strings.get("name");
   * }</pre>
   *
   * @param sfs the field set to read, typically created by {@link #exportStoreAsSFS()}
   * @throws IllegalBase64Exception if any encoded key cannot be decoded as Base64 UTF-8
   * @throws FSParseException if a field cannot be parsed into the expected primitive type
   */
  public PluginStore(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readSubstores(sfs);
    readLongs(sfs);
    readLongArrays(sfs);
    readIntegers(sfs);
    readIntegerArrays(sfs);
    readShorts(sfs);
    readShortArrays(sfs);
    readBooleans(sfs);
    readBooleanArrays(sfs);
    readBytes(sfs);
    readByteArrays(sfs);
    readStrings(sfs);
    readStringArrays(sfs);
  }

  private static String encode(String s) {
    return Base64.encodeUTF8(s);
  }

  private static String decode(String s) throws IllegalBase64Exception {
    return Base64.decodeUTF8(s);
  }

  private void readSubstores(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    SimpleFieldSet group = sfs.subset("substore");
    if (group == null) {
      return;
    }
    for (Map.Entry<String, SimpleFieldSet> entry : group.directSubsets().entrySet()) {
      subStores.put(decode(entry.getKey()), new PluginStore(entry.getValue()));
    }
  }

  private void readLongs(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "long", longs, SimpleFieldSet::getLong);
  }

  private void readLongArrays(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "longs", longsArrays, SimpleFieldSet::getLongArray);
  }

  private void readIntegers(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "integer", integers, SimpleFieldSet::getInt);
  }

  private void readIntegerArrays(SimpleFieldSet sfs)
      throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "integers", integersArrays, SimpleFieldSet::getIntArray);
  }

  private void readShorts(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "short", shorts, SimpleFieldSet::getShort);
  }

  private void readShortArrays(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "shorts", shortsArrays, SimpleFieldSet::getShortArray);
  }

  private void readBooleans(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "boolean", booleans, SimpleFieldSet::getBoolean);
  }

  private void readBooleanArrays(SimpleFieldSet sfs)
      throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "booleans", booleansArrays, SimpleFieldSet::getBooleanArray);
  }

  private void readBytes(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "byte", bytes, SimpleFieldSet::getByte);
  }

  private void readByteArrays(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "bytes", bytesArrays, SimpleFieldSet::getByteArray);
  }

  private void readStrings(SimpleFieldSet sfs) throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "string", strings, SimpleFieldSet::get);
  }

  private void readStringArrays(SimpleFieldSet sfs)
      throws IllegalBase64Exception, FSParseException {
    readGroupValues(sfs, "strings", stringsArrays, SimpleFieldSet::getAllEncoded);
  }

  private <T> void readGroupValues(
      SimpleFieldSet sfs, String groupName, Map<String, T> target, ValueReader<T> reader)
      throws IllegalBase64Exception, FSParseException {
    SimpleFieldSet group = sfs.subset(groupName);
    if (group == null) {
      return;
    }
    for (String key : group.directKeys()) {
      target.put(decode(key), reader.read(group, key));
    }
  }

  @FunctionalInterface
  private interface ValueReader<T> {
    T read(SimpleFieldSet group, String key) throws IllegalBase64Exception, FSParseException;
  }
}
