package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class CompatibilityAnalyserTest {

  @Test
  void constructor_defaults_whenCreated_expectUnknownAndDontCompressTrue() {
    // Arrange & Act
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();

    // Assert
    assertAll(
        () -> assertEquals(CompatibilityMode.COMPAT_UNKNOWN, analyser.min()),
        () -> assertEquals(CompatibilityMode.COMPAT_UNKNOWN, analyser.max()),
        () -> assertTrue(analyser.dontCompress()),
        () -> assertFalse(analyser.definitive()),
        () -> assertNull(analyser.getCryptoKey()),
        () -> {
          var modes = analyser.getModes();
          assertNotNull(modes);
          assertEquals(2, modes.length);
          assertEquals(CompatibilityMode.COMPAT_UNKNOWN, modes[0]);
          assertEquals(CompatibilityMode.COMPAT_UNKNOWN, modes[1]);
        });
  }

  @Test
  void merge_updatesMinMaxDontCompressAndKey_whenNonDefinitive() {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 0xA5);

    // Act
    analyser.merge(
        CompatibilityMode.COMPAT_1250_EXACT,
        CompatibilityMode.COMPAT_1468,
        key,
        /* dontCompress */ false,
        /* definitive */ false);

    // Assert
    assertAll(
        () -> assertEquals(CompatibilityMode.COMPAT_1250_EXACT, analyser.min()),
        () -> assertEquals(CompatibilityMode.COMPAT_1468, analyser.max()),
        () -> assertFalse(analyser.dontCompress()),
        () -> assertArrayEquals(key, analyser.getCryptoKey()),
        () -> assertFalse(analyser.definitive()));
  }

  @Test
  void merge_transitionsMinUpAndMaxDown_acrossMultipleMerges() {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();

    // Act
    analyser.merge(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_1468,
        null,
        /* dontCompress */ true,
        /* definitive */ false);

    analyser.merge(
        CompatibilityMode.COMPAT_1416,
        CompatibilityMode.COMPAT_1251,
        null,
        /* dontCompress */ false,
        /* definitive */ false);

    // Assert
    assertAll(
        () -> assertEquals(CompatibilityMode.COMPAT_1416, analyser.min()),
        () -> assertEquals(CompatibilityMode.COMPAT_1251, analyser.max()),
        () -> assertFalse(analyser.dontCompress()));
  }

  @Test
  void merge_keepsKey_whenSameKeyProvided() {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) key[i] = (byte) i;

    // Act
    analyser.merge(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_1468,
        key,
        /* dontCompress */ true,
        /* definitive */ false);

    analyser.merge(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_1468,
        Arrays.copyOf(key, key.length),
        /* dontCompress */ true,
        /* definitive */ false);

    // Assert
    assertArrayEquals(key, analyser.getCryptoKey());
  }

  @Test
  void merge_nullsKey_whenDifferentKeysProvided() {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] key1 = new byte[32];
    byte[] key2 = new byte[32];
    Arrays.fill(key1, (byte) 0x11);
    Arrays.fill(key2, (byte) 0x22);

    // Act
    analyser.merge(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_1468,
        key1,
        /* dontCompress */ true,
        /* definitive */ false);

    analyser.merge(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_1468,
        key2,
        /* dontCompress */ true,
        /* definitive */ false);

    // Assert
    assertNull(analyser.getCryptoKey());
  }

  @Test
  void merge_ignored_whenDefinitiveAlreadySet() {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 0x01);

    analyser.merge(
        CompatibilityMode.COMPAT_1250,
        CompatibilityMode.COMPAT_1468,
        key,
        /* dontCompress */ false,
        /* definitive */ true);

    // Act (attempt to change everything after definitive)
    byte[] differentKey = new byte[32];
    Arrays.fill(differentKey, (byte) 0xFF);

    analyser.merge(
        CompatibilityMode.COMPAT_1416,
        CompatibilityMode.COMPAT_1251,
        differentKey,
        /* dontCompress */ true,
        /* definitive */ false);

    // Assert - unchanged
    assertAll(
        () -> assertEquals(CompatibilityMode.COMPAT_1250, analyser.min()),
        () -> assertEquals(CompatibilityMode.COMPAT_1468, analyser.max()),
        () -> assertFalse(analyser.dontCompress()),
        () -> assertTrue(analyser.definitive()),
        () -> assertArrayEquals(key, analyser.getCryptoKey()));
  }

  @Test
  void io_roundTrip_preservesAllFields_withKey() throws IOException, StorageFormatException {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 3);
    analyser.merge(
        CompatibilityMode.COMPAT_1255,
        CompatibilityMode.COMPAT_1416,
        key,
        /* dontCompress */ false,
        /* definitive */ true);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      analyser.writeTo(dos);
    }

    // Act
    CompatibilityAnalyser read;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      read = new CompatibilityAnalyser(dis);
    }

    // Assert
    assertAll(
        () -> assertEquals(CompatibilityMode.COMPAT_1255, read.min()),
        () -> assertEquals(CompatibilityMode.COMPAT_1416, read.max()),
        () -> assertFalse(read.dontCompress()),
        () -> assertTrue(read.definitive()),
        () -> assertArrayEquals(key, read.getCryptoKey()));
  }

  @Test
  void io_roundTrip_preservesAllFields_withoutKey() throws IOException, StorageFormatException {
    // Arrange
    CompatibilityAnalyser analyser = new CompatibilityAnalyser();
    analyser.merge(
        CompatibilityMode.COMPAT_1251,
        CompatibilityMode.COMPAT_1468,
        /* cryptoKey */ null,
        /* dontCompress */ true,
        /* definitive */ false);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      analyser.writeTo(dos);
    }

    // Act
    CompatibilityAnalyser read;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      read = new CompatibilityAnalyser(dis);
    }

    // Assert
    assertAll(
        () -> assertEquals(CompatibilityMode.COMPAT_1251, read.min()),
        () -> assertEquals(CompatibilityMode.COMPAT_1468, read.max()),
        () -> assertTrue(read.dontCompress()),
        () -> assertFalse(read.definitive()),
        () -> assertNull(read.getCryptoKey()));
  }

  @Test
  void read_throwsStorageFormatException_whenVersionUnknown() {
    // Arrange: write a bad version identifier
    byte[] bytes;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(999); // bad version
      // The rest of the stream is irrelevant because constructor fails after first read
      dos.flush();
      bytes = baos.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    // Act & Assert
    assertThrows(
        StorageFormatException.class,
        () -> new CompatibilityAnalyser(new DataInputStream(new ByteArrayInputStream(bytes))));
  }

  @Test
  void read_throwsStorageFormatException_whenMinCodeInvalid() throws IOException {
    // Arrange
    byte[] bytes;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(CompatibilityAnalyser.VERSION); // correct version
      dos.writeShort(Short.MAX_VALUE); // invalid min code
      dos.writeShort(CompatibilityMode.COMPAT_1468.code); // some max code (won't be read)
      // booleans and other fields are not needed because it will throw while reading min/max
      dos.flush();
      bytes = baos.toByteArray();
    }

    // Act & Assert
    assertThrows(
        StorageFormatException.class,
        () -> new CompatibilityAnalyser(new DataInputStream(new ByteArrayInputStream(bytes))));
  }
}
