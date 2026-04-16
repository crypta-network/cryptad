package network.crypta.clients.fcp;

import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ManifestTreeMapsTest {

  @Test
  void forceMap_whenHashMapProvided_returnsSameInstance() {
    Map<String, Object> manifest = new java.util.HashMap<>();
    manifest.put("file.txt", 1L);

    Map<String, Object> actual = ManifestTreeMaps.forceMap(manifest);

    assertSame(manifest, actual);
  }

  @Test
  void forceMap_whenGenericMapProvided_returnsMutableHashMapCopy() {
    Map<String, Object> manifest = new TreeMap<>();
    manifest.put("file.txt", 1L);

    Map<String, Object> actual = ManifestTreeMaps.forceMap(manifest);

    assertInstanceOf(java.util.HashMap.class, actual);
    assertNotSame(manifest, actual);
    assertEquals(manifest, actual);
  }

  @Test
  void forceMap_whenMapContainsNonStringKey_throwsClassCastException() {
    Map<Object, Object> manifest = new TreeMap<>();
    manifest.put(1, "value");

    assertThrows(ClassCastException.class, () -> ManifestTreeMaps.forceMap(manifest));
  }

  @Test
  void forceMap_whenValueIsNotMap_throwsClassCastException() {
    assertThrows(ClassCastException.class, () -> ManifestTreeMaps.forceMap("not-a-map"));
  }
}
