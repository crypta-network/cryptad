package network.crypta.clients.fcp;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ClientGetFetchConfigTest {

  @Test
  void setAllowedMimeTypes_whenSourceSetMutates_keepsDetachedStoredCopy() {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    Set<String> sourceMimeTypes = new HashSet<>(Set.of("text/plain"));

    fetchConfig.setAllowedMimeTypes(sourceMimeTypes);
    sourceMimeTypes.add("image/png");

    assertEquals(Set.of("text/plain"), fetchConfig.getAllowedMimeTypes());
  }

  @Test
  void getAllowedMimeTypes_whenReturnedSetMutates_keepsStoredSetUnchanged() {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setAllowedMimeTypes(new HashSet<>(Set.of("text/plain")));

    Set<String> returnedMimeTypes = fetchConfig.getAllowedMimeTypes();
    returnedMimeTypes.add("image/png");

    assertEquals(Set.of("text/plain"), fetchConfig.getAllowedMimeTypes());
  }

  @Test
  void copy_whenOriginalMutates_keepsIndependentState() {
    ClientGetFetchConfig original = new ClientGetFetchConfig();
    original.setAllowedMimeTypes(new HashSet<>(Set.of("text/plain")));
    original.setFilterData(true);
    original.setMaxOutputLength(4096L);

    ClientGetFetchConfig copy = original.copy();
    original.setAllowedMimeTypes(new HashSet<>(Set.of("image/png")));
    original.setFilterData(false);
    original.setMaxOutputLength(2048L);

    assertEquals(Set.of("text/plain"), copy.getAllowedMimeTypes());
    assertTrue(copy.getFilterData());
    assertEquals(4096L, copy.getMaxOutputLength());
    assertNotEquals(original, copy);
  }
}
