package org.sevenzip;

import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("java:S100")
class CRCTest {

  @Test
  void getDigest_whenNoData_returnsCrcOfEmptyInput() {
    CRC crc = new CRC();
    crc.init();

    int digest = crc.getDigest();

    CRC32 reference = new CRC32();
    assertEquals((int) reference.getValue(), digest);
  }

  @Test
  void update_whenUsingArraySlice_matchesReference() {
    byte[] data = new byte[] {0, 1, 2, 3, 4, 5, 6};
    CRC crc = new CRC();
    crc.init();

    crc.update(data, 1, 4); // bytes 1..4

    CRC32 reference = new CRC32();
    reference.update(data, 1, 4);
    assertEquals((int) reference.getValue(), crc.getDigest());
  }

  @Test
  void updateByte_whenValueOutsideByteRange_usesLowerEightBits() {
    CRC crc = new CRC();
    crc.init();

    crc.updateByte(0x1AB); // lower 8 bits = 0xAB

    CRC32 reference = new CRC32();
    reference.update(new byte[] {(byte) 0xAB});
    assertEquals((int) reference.getValue(), crc.getDigest());
  }

  @Test
  void cumulativeUpdates_whenMixedMethods_matchesReference() {
    byte[] data = new byte[] {(byte) 0x00, (byte) 0xFF, 0x10, 0x20, 0x30};
    CRC crc = new CRC();
    crc.init();

    crc.updateByte(data[0]);
    crc.updateByte(data[1]);
    crc.update(data, 2, 3);

    CRC32 reference = new CRC32();
    reference.update(data, 0, data.length);
    assertEquals((int) reference.getValue(), crc.getDigest());
  }

  @Test
  void init_whenCalled_resetsStateToInitial() {
    CRC crc = new CRC();
    crc.init();
    byte[] first = new byte[] {1, 2, 3};
    crc.update(first);
    int firstDigest = crc.getDigest();

    crc.init();
    byte[] second = new byte[] {9, 8};
    crc.update(second);
    int secondDigest = crc.getDigest();

    CRC32 reference = new CRC32();
    reference.update(second, 0, second.length);

    assertNotEquals(firstDigest, secondDigest);
    assertEquals((int) reference.getValue(), secondDigest);
  }

  @Test
  void update_whenZeroLength_doesNotChangeDigest() {
    CRC crc = new CRC();
    crc.init();
    byte[] data = new byte[] {5, 6, 7};
    crc.update(data);
    int digestBefore = crc.getDigest();

    crc.update(data, 0, 0);

    assertEquals(digestBefore, crc.getDigest());
  }
}
