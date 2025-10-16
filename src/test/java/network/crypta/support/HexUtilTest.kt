package network.crypta.support

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.math.BigInteger
import java.util.BitSet
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

@Suppress("java:S100") // Allow expressive test method names
class HexUtilTest {

  // bytesToHex ---------------------------------------------------------------

  @Test
  fun bytesToHex_whenAllSingleBytes_expectTwoDigitLowercase() {
    // Arrange
    val one = ByteArray(1)

    // Act + Assert
    for (i in 0..255) {
      one[0] = i.toByte()
      val expected = Integer.toHexString(i).padStart(2, '0')
      assertEquals(expected, bytesToHex(one))
    }
  }

  @Test
  fun bytesToHex_whenZeroLength_expectEmpty() {
    assertEquals("", bytesToHex(ByteArray(0), 0, 0))
    assertEquals("", bytesToHex(ByteArray(2), 2, 0))
  }

  @Test
  fun bytesToHex_whenOffsetBeyondArray_expectIllegalArgumentException() {
    val arr = ByteArray(3)
    assertThrows(IllegalArgumentException::class.java) { bytesToHex(arr, 4, 1) }
  }

  @Test
  fun bytesToHex_whenReadingTooManyBytes_expectIllegalArgumentException() {
    val arr = ByteArray(3)
    assertThrows(IllegalArgumentException::class.java) { bytesToHex(arr, 0, 4) }
  }

  @Test
  fun bytesToHexAppend_whenAppendsToExistingBuilder_expectBuilderExtended() {
    val bytes = byteArrayOf(0x00, 0x7F, 0xFF.toByte())
    val sb = StringBuilder("prefix-")
    bytesToHexAppend(bytes, 0, bytes.size, sb)
    assertEquals("prefix-007fff", sb.toString())
  }

  // hexToBytes ---------------------------------------------------------------

  @Test
  fun hexToBytes_whenAllSingleBytes_expectDecodeMatches() {
    val expected = ByteArray(1)
    for (i in 0..255) {
      expected[0] = i.toByte()
      val hex = Integer.toHexString(i).padStart(2, '0')
      assertArrayEquals(expected, hexToBytes(hex))
      assertArrayEquals(expected, hexToBytes(hex, 0))

      val out = ByteArray(1)
      hexToBytes(hex, out, 0)
      assertArrayEquals(expected, out)
    }
  }

  @Test
  fun hexToBytes_whenUpperAndLowercase_expectEquivalent() {
    assertArrayEquals(byteArrayOf(0xAF.toByte()), hexToBytes("af"))
    assertArrayEquals(byteArrayOf(0xAF.toByte()), hexToBytes("AF"))
  }

  @Test
  fun hexToBytes_whenOddLength_expectPrefixedZeroNibble() {
    assertArrayEquals(byteArrayOf(0x0F), hexToBytes("f"))
    assertArrayEquals(hexToBytes("0f"), hexToBytes("f"))
  }

  @Test
  fun hexToBytes_withOffsetPrefix_expectLeadingZerosThenDecoded() {
    val out = hexToBytes("a1b2", 2)
    assertArrayEquals(byteArrayOf(0x00, 0x00, 0xA1.toByte(), 0xB2.toByte()), out)
  }

  @Test
  fun hexToBytes_intoProvidedArray_whenArrayTooSmallEvenLength_expectIndexOutOfBounds() {
    val out = ByteArray(1)
    assertThrows(IndexOutOfBoundsException::class.java) { hexToBytes("abcd", out, 0) }
  }

  @Test
  fun hexToBytes_intoProvidedArray_whenArrayTooSmallOddLength_expectIndexOutOfBounds() {
    // Odd-length input hits the implicit prefixing path; ensure bounds are still enforced.
    val out = ByteArray(1)
    assertThrows(IndexOutOfBoundsException::class.java) { hexToBytes("abc", out, 0) }
  }

  @Test
  fun hexToBytes_intoProvidedArray_whenOffsetEqualsLength_expectIndexOutOfBounds() {
    val out = ByteArray(1)
    assertThrows(IndexOutOfBoundsException::class.java) { hexToBytes("0", out, out.size) }
  }

  @Test
  fun hexToBytes_whenInvalidDigit_expectNumberFormatException() {
    val bad = "00%0"
    assertThrows(NumberFormatException::class.java) { hexToBytes(bad) }
    assertThrows(NumberFormatException::class.java) { hexToBytes(bad, 0) }
    assertThrows(NumberFormatException::class.java) { hexToBytes(bad, ByteArray(bad.length), 0) }
  }

  // BitSet/byte conversions --------------------------------------------------

  @Test
  fun bitsToBytes_whenEnumerateAll8BitValues_expectExactByte() {
    val bs = BitSet(8)
    for (i in 0..255) {
      val bytes = bitsToBytes(bs, 8)
      assertArrayEquals(byteArrayOf(i.toByte()), bytes)
      incrementBitSet(bs)
    }
  }

  @Test
  fun bitsToBytes_whenSizeSmallerThanSetBits_expectMasking() {
    val bs = BitSet(8)
    // 0x01
    bs.flip(0)
    assertFalse(bitsToBytes(bs, 0).contentEquals(byteArrayOf(1)))
    assertArrayEquals(byteArrayOf(1), bitsToBytes(bs, 1))

    // 0x89 (bits 0,3,7)
    bs.flip(7)
    bs.flip(3)
    assertFalse(bitsToBytes(bs, 3).contentEquals(byteArrayOf(0x89.toByte())))
    assertArrayEquals(byteArrayOf(0x89.toByte()), bitsToBytes(bs, 8))
  }

  @Test
  fun bytesToBits_thenBack_when8Bits_expectRoundTrip() {
    val bs = BitSet(8)
    val one = ByteArray(1)
    for (i in 0..254) {
      one[0] = i.toByte()
      bs.clear()
      bytesToBits(one, bs, 7)
      assertArrayEquals(one, bitsToBytes(bs, 8))
    }
  }

  @Test
  fun bitsToHexString_whenExamples_expectExpectedHex() {
    val bs = BitSet(8)
    assertEquals("00", bitsToHexString(bs, 8))
    bs.set(0, 7, true) // 0x7f
    assertEquals("7f", bitsToHexString(bs, 8))
    bs.set(0, 9, true) // 0xff when size=8
    assertEquals("ff", bitsToHexString(bs, 8))
  }

  @Test
  fun hexToBits_whenExamples_expectExpectedBitSets() {
    var bs = BitSet(8)
    hexToBits("00", bs, bs.size())
    assertEquals(0, bs.cardinality())

    bs = BitSet(8)
    hexToBits("7f", bs, bs.size())
    val expected7f = BitSet(8).apply { set(0, 7, true) }
    assertTrue(bs.intersects(expected7f))

    bs = BitSet(8)
    hexToBits("ff", bs, bs.size())
    val expectedff = BitSet(8).apply { set(0, 9, true) }
    assertTrue(bs.intersects(expectedff))
  }

  // Count bytes for bits -----------------------------------------------------

  @ParameterizedTest
  @CsvSource(value = ["0,0", "1,1", "7,1", "8,1", "9,2", "15,2", "16,2", "17,3"])
  fun countBytesForBits_whenVariousSizes_expectCeilDivBy8(bits: Int, expectedBytes: Int) {
    assertEquals(expectedBytes, countBytesForBits(bits))
  }

  // BigInteger I/O -----------------------------------------------------------

  @Test
  fun writeBigInteger_and_readBigInteger_whenRoundTrip_expectSameValue() {
    val value = BigInteger("999999999999999")
    val bos = ByteArrayOutputStream()
    DataOutputStream(bos).use { dos -> writeBigInteger(value, dos) }
    val bytes = bos.toByteArray()
    val read = DataInputStream(ByteArrayInputStream(bytes)).use { dis -> readBigInteger(dis) }
    assertEquals(0, value.compareTo(read))
  }

  @Test
  fun writeBigInteger_whenNegative_expectIllegalArgumentException() {
    val neg = BigInteger.valueOf(-1)
    val bos = ByteArrayOutputStream()
    val dos = DataOutputStream(bos)
    assertThrows(IllegalArgumentException::class.java) { writeBigInteger(neg, dos) }
  }

  @Test
  fun writeBigInteger_whenTooLong_expectIllegalStateException() {
    // Construct a positive BigInteger whose two's-complement byte array exceeds Short.MAX_VALUE
    val magnitude = ByteArray(Short.MAX_VALUE.toInt() + 1) { 0x7F.toByte() }
    val big = BigInteger(1, magnitude)
    val dos = DataOutputStream(ByteArrayOutputStream())
    assertThrows(IllegalStateException::class.java) { writeBigInteger(big, dos) }
  }

  @Test
  fun readBigInteger_whenNegativeLengthHeader_expectIOException() {
    val bos = ByteArrayOutputStream()
    DataOutputStream(bos).use { it.writeShort(-1) }
    val dis = DataInputStream(ByteArrayInputStream(bos.toByteArray()))
    assertThrows(IOException::class.java) { readBigInteger(dis) }
  }

  @Test
  fun readBigInteger_whenUnexpectedEOF_expectIOException() {
    val bos = ByteArrayOutputStream()
    DataOutputStream(bos).use {
      it.writeShort(4) // claims 4 bytes follow
      it.write(byteArrayOf(1, 2, 3)) // only 3 bytes provided
    }
    val dis = DataInputStream(ByteArrayInputStream(bos.toByteArray()))
    val ex = assertThrows(IOException::class.java) { readBigInteger(dis) }
    // DataInputStream.readFully throws EOFException specifically
    assertTrue(ex is EOFException)
  }

  // BigInteger → hex ---------------------------------------------------------

  @Test
  fun biToHex_and_toHexString_whenKnownValues_expectExpectedHex() {
    var bi = BigInteger("999999999999999")
    assertEquals("038d7ea4c67fff", biToHex(bi))
    assertEquals(biToHex(bi), toHexString(bi))

    bi = BigInteger.ZERO
    assertEquals("00", biToHex(bi))
    assertEquals(biToHex(bi), toHexString(bi))

    bi = BigInteger("72057594037927935")
    assertEquals("00ffffffffffffff", biToHex(bi))
    assertEquals(biToHex(bi), toHexString(bi))
  }

  // Helpers ------------------------------------------------------------------

  private fun incrementBitSet(bs: BitSet) {
    var idx = 0
    while (bs[idx]) {
      bs.flip(idx)
      idx++
    }
    bs.flip(idx)
  }
}
