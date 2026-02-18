package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SimpleGetPubkeyTest {

  @Mock private PubkeyStore store;

  @InjectMocks private SimpleGetPubkey subject;

  @ParameterizedTest
  @CsvSource({"false,false", "true,false", "false,true", "true,true"})
  @DisplayName("getKey delegates to store.fetch with fixed flags and returns result")
  void getKey_whenVariousFlags_alwaysCallsStoreWithFixedArgs(
      boolean canReadClientCache, boolean forULPR) throws Exception {
    // Arrange
    byte[] hash = new byte[] {0x01, 0x02, 0x03};
    BlockMetadata meta = new BlockMetadata();
    DSAPublicKey key = org.mockito.Mockito.mock(DSAPublicKey.class);
    when(store.fetch(hash, false, false, meta)).thenReturn(key);

    // Act
    DSAPublicKey result = subject.getKey(hash, canReadClientCache, forULPR, meta);

    // Assert
    assertSame(key, result, "Should return the DSAPublicKey from store.fetch()");
    verify(store).fetch(same(hash), eq(false), eq(false), same(meta));
    verifyNoMoreInteractions(store);
  }

  @Test
  @DisplayName("getKey returns null when store.fetch throws IOException")
  void getKey_whenStoreThrowsIOException_returnsNull() throws Exception {
    // Arrange
    byte[] hash = new byte[] {0x0A, 0x0B};
    BlockMetadata meta = new BlockMetadata();
    when(store.fetch(hash, false, false, meta)).thenThrow(new IOException("disk error"));

    // Act
    DSAPublicKey result = subject.getKey(hash, false, false, meta);

    // Assert
    assertNull(result, "IOException must be swallowed and null returned");
    verify(store).fetch(same(hash), eq(false), eq(false), same(meta));
    verifyNoMoreInteractions(store);
  }

  @Test
  @DisplayName("getKey passes null metadata through to store.fetch")
  void getKey_whenMetaIsNull_passesNull() throws Exception {
    // Arrange
    byte[] hash = new byte[] {0x55};
    DSAPublicKey key = org.mockito.Mockito.mock(DSAPublicKey.class);
    when(store.fetch(hash, false, false, null)).thenReturn(key);

    // Act
    DSAPublicKey result = subject.getKey(hash, true, true, null);

    // Assert
    assertSame(key, result);
    verify(store).fetch(same(hash), eq(false), eq(false), eq(null));
    verifyNoMoreInteractions(store);
  }

  @ParameterizedTest(name = "deep={0}, client={1}, ds={2}, ulpr={3}, localDs={4}")
  @CsvSource({
    // baseline
    "false,false,false,false,false",
    // toggle each flag individually
    "true,false,false,false,false",
    "false,true,false,false,false",
    "false,false,true,false,false",
    "false,false,false,true,false",
    "false,false,false,false,true",
    // all true
    "true,true,true,true,true"
  })
  @DisplayName("cacheKey ignores flags and always writes with isOldBlock=false")
  void cacheKey_ignoresFlags_alwaysWritesWithIsOldFalse(
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      boolean writeLocalToDatastore)
      throws Exception {
    // Arrange
    byte[] hash = new byte[] {(byte) 0xA5};
    DSAPublicKey key = org.mockito.Mockito.mock(DSAPublicKey.class);

    // Act
    subject.cacheKey(
        hash, key, deep, canWriteClientCache, canWriteDatastore, forULPR, writeLocalToDatastore);

    // Assert
    verify(store).put(same(key), eq(false));
    verifyNoMoreInteractions(store);
  }

  @Test
  @DisplayName("cacheKey swallows IOException from store.put")
  void cacheKey_whenStoreThrowsIOException_swallowed() throws Exception {
    // Arrange
    byte[] hash = new byte[] {0x11, 0x22};
    DSAPublicKey key = org.mockito.Mockito.mock(DSAPublicKey.class);
    doThrow(new IOException("write failed")).when(store).put(key, false);

    // Act & Assert (no throw)
    subject.cacheKey(hash, key, false, false, false, false, false);
    verify(store).put(same(key), eq(false));
    verifyNoMoreInteractions(store);
  }
}
