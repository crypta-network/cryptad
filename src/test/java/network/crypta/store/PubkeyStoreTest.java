package network.crypta.store;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.keys.PubkeyVerifyException;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class PubkeyStoreTest {

  @Mock private FreenetStore<DSAPublicKey> mockStore;

  @Test
  void putAndFetch_whenUsingRamStore_roundTripsKeys() throws IOException {
    // Arrange
    final int keys = 10;
    PubkeyStore pk = new PubkeyStore();
    try (var _ = new RAMFreenetStore<>(pk, keys)) {
      DSAGroup group = Global.DSAgroupBigA;
      Random random = new MersenneTwister(1010101);
      HashMap<ByteArrayWrapper, DSAPublicKey> map = new HashMap<>();

      // Act
      for (int i = 0; i < keys; i++) {
        DSAPrivateKey privKey = new DSAPrivateKey(group, random);
        DSAPublicKey key = new DSAPublicKey(group, privKey);
        byte[] hash = key.asBytesHash();
        ByteArrayWrapper w = new ByteArrayWrapper(hash);
        map.put(w, key.cloneKey());
        pk.put(key, false);
        DSAPublicKey fetched = pk.fetch(hash, false, false, null);

        // Assert (per-key)
        assertEquals(key, fetched);
      }

      int count = 0;
      for (Map.Entry<ByteArrayWrapper, DSAPublicKey> entry : map.entrySet()) {
        count++;
        DSAPublicKey fetched = pk.fetch(entry.getKey().get(), false, false, null);
        assertEquals(entry.getValue(), fetched);
      }
      assertEquals(keys, count);
    }
  }

  @Test
  void construct_whenDataIsNull_throwPubkeyVerifyException() {
    // Arrange
    PubkeyStore sut = new PubkeyStore();

    // Act + Assert
    PubkeyVerifyException ex =
        assertThrows(
            PubkeyVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(null, null, null, null),
                    new StoreCallback.ConstructOptions(false, false, /*meta*/ null),
                    /*knownPubKey*/ null));
    assertEquals("Need data to construct pubkey", ex.getMessage());
  }

  @Test
  void construct_whenDataIsInvalid_throwPubkeyVerifyException() {
    // Arrange
    PubkeyStore sut = new PubkeyStore();
    byte[] invalid = new byte[] {0x00}; // Not a valid DSAGroup + MPI sequence

    // Act + Assert
    assertThrows(
        PubkeyVerifyException.class,
        () ->
            sut.construct(
                new StoreCallback.BlockPayload(invalid, null, null, null),
                new StoreCallback.ConstructOptions(false, false, /*meta*/ null),
                /*knownPubKey*/ null));
  }

  @Test
  void construct_whenDataIsValid_returnsParsedKey() throws Exception {
    // Arrange
    PubkeyStore sut = new PubkeyStore();
    DSAPublicKey original = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.TWO);
    byte[] bytes = original.asBytes();

    // Act
    DSAPublicKey parsed =
        sut.construct(
            new StoreCallback.BlockPayload(bytes, null, null, null),
            new StoreCallback.ConstructOptions(false, false, /*meta*/ null),
            /*knownPubKey*/ null);

    // Assert
    assertEquals(original, parsed);
  }

  @Test
  void fetch_whenDelegatesToStore_propagatesFlagsAndReturnsResult() throws Exception {
    // Arrange
    PubkeyStore sut = new PubkeyStore();
    sut.setStore(mockStore);
    byte[] hash = new byte[DSAPublicKey.HASH_LENGTH];
    BlockMetadata meta = new BlockMetadata();
    DSAPublicKey expected = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.TWO);
    when(mockStore.fetch(eq(hash), isNull(), eq(true), eq(false), eq(false), eq(true), same(meta)))
        .thenReturn(expected);

    // Act
    DSAPublicKey got = sut.fetch(hash, /*dontPromote*/ true, /*ignoreOldBlocks*/ true, meta);

    // Assert
    assertSame(expected, got);
    verify(mockStore, times(1))
        .fetch(eq(hash), isNull(), eq(true), eq(false), eq(false), eq(true), same(meta));
  }

  @Test
  void put_whenDelegatesToStore_writesPaddedBytesAndFlags() throws Exception {
    // Arrange
    PubkeyStore sut = new PubkeyStore();
    sut.setStore(mockStore);
    DSAPublicKey key = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(3));
    key.asBytesHash();
    byte[] expectedPadded = key.asPaddedBytes();

    // Act
    sut.put(key, /*isOldBlock*/ true);

    // Assert
    verify(mockStore, times(1))
        .put(
            same(key),
            argThat(arr -> arr != null && arr.length == expectedPadded.length),
            argThat(arr -> arr != null && arr.length == 0),
            eq(false),
            eq(true));
  }

  @Test
  void put_whenStoreThrowsKeyCollisionException_doesNotPropagate() throws Exception {
    // Arrange
    PubkeyStore sut = new PubkeyStore();
    sut.setStore(mockStore);
    DSAPublicKey key = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(5));
    key.asBytesHash();

    // Configure mock to throw on put
    org.mockito.Mockito.doThrow(new KeyCollisionException())
        .when(mockStore)
        .put(any(), any(), any(), eq(false), eq(false));

    // Act + Assert
    assertDoesNotThrow(() -> sut.put(key, /*isOldBlock*/ false));
    verify(mockStore, times(1)).put(any(), any(), any(), eq(false), eq(false));
  }

  @Test
  void sizesAndFlags_returnExpectedValues() {
    // Arrange
    PubkeyStore sut = new PubkeyStore();

    // Act + Assert
    assertEquals(DSAPublicKey.PADDED_SIZE, sut.dataLength());
    assertEquals(0, sut.headerLength());
    assertEquals(DSAPublicKey.HASH_LENGTH, sut.fullKeyLength());
    assertEquals(DSAPublicKey.HASH_LENGTH, sut.routingKeyLength());
    assertFalse(sut.storeFullKeys());
    assertFalse(sut.constructNeedsKey());
    assertFalse(sut.collisionPossible());
  }

  @Test
  void routingKeyFromFullKey_returnsSameInstance() {
    // Arrange
    PubkeyStore sut = new PubkeyStore();
    byte[] full = new byte[] {1, 2, 3};

    // Act
    byte[] routed = sut.routingKeyFromFullKey(full);

    // Assert
    assertSame(full, routed);
  }

  @Test
  void getTotalBlockSize_returnsSumOfSections() {
    // Arrange
    PubkeyStore sut = new PubkeyStore();

    // Act
    int total = sut.getTotalBlockSize();

    // Assert
    int expected = DSAPublicKey.PADDED_SIZE + DSAPublicKey.HASH_LENGTH + DSAPublicKey.HASH_LENGTH;
    assertEquals(expected, total);
  }
}
