@file:JvmName("HexUtil")

/**
 * Hex/binary conversion helpers for Crypta.
 *
 * This file provides small, allocation‑friendly utilities to convert between hexadecimal strings,
 * byte arrays, [BitSet]s and [BigInteger]s, plus simple I/O routines for reading/writing
 * `BigInteger` values with a length prefix.
 *
 * General conventions
 * - Hex strings use lowercase digits `0-9a-f` when produced by this utility. Decoding accepts both
 *   lowercase and uppercase digits.
 * - For bit/byte packing, bit index `j` inside a byte corresponds to mask `1 shl j` (LSB first).
 * - Methods strive to avoid intermediate allocations when a destination buffer is supplied.
 */
package network.crypta.support

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.math.BigInteger
import java.util.*
import org.slf4j.LoggerFactory

private val LOG = LoggerFactory.getLogger("network.crypta.support.HexUtil")
private val logDEBUG: Boolean
  get() = LOG.isDebugEnabled

/**
 * Returns a lowercase hexadecimal representation of a slice of a byte array.
 *
 * The output uses two characters per byte and digits `0-9a-f`.
 *
 * @param bs source array.
 * @param off starting offset in `bs` (0-based).
 * @param length number of bytes to encode.
 * @return hex string of the requested slice.
 * @throws IllegalArgumentException if `off + length` exceeds `bs.size`.
 */
fun bytesToHex(bs: ByteArray, off: Int, length: Int): String {
  require(bs.size >= off + length) { "Total length: ${bs.size}, offset: $off, length: $length" }
  val sb = StringBuilder(length * 2)
  bytesToHexAppend(bs, off, length, sb)
  return sb.toString()
}

/**
 * Appends the lowercase hexadecimal encoding of a slice of a byte array to a `StringBuilder`.
 *
 * This method does not allocate intermediate strings and ensures the builder has enough capacity
 * before writing.
 *
 * @param bs source array.
 * @param off starting offset in `bs` (0-based).
 * @param length number of bytes to encode.
 * @param sb destination builder to append to.
 * @throws IllegalArgumentException if `off + length` exceeds `bs.size`.
 */
fun bytesToHexAppend(bs: ByteArray, off: Int, length: Int, sb: StringBuilder) {
  require(bs.size >= off + length)
  sb.ensureCapacity(sb.length + length * 2)
  for (i in off until off + length) {
    val b = bs[i].toInt()
    sb.append(Character.forDigit((b ushr 4) and 0xf, 16))
    sb.append(Character.forDigit(b and 0xf, 16))
  }
}

/**
 * Encodes an entire array into a lowercase hexadecimal string.
 *
 * @param bs source array to encode.
 * @return hex string with two characters per byte.
 */
fun bytesToHex(bs: ByteArray): String = bytesToHex(bs, 0, bs.size)

/**
 * Decodes a hexadecimal string into a new byte array.
 *
 * Accepts both lowercase and uppercase digits. For odd-length input, a leading `0` is assumed.
 *
 * @param s hex string to decode.
 * @return newly allocated array with decoded bytes.
 * @see hexToBytes
 */
fun hexToBytes(s: String): ByteArray = hexToBytes(s, 0)

/**
 * Decodes a hex string into a new array and prefixes `off` zero-bytes before the decoded bytes.
 *
 * The returned array length is `off + ceil(s.length / 2)`. For odd-length input, a leading `0` is
 * assumed when decoding.
 *
 * @param s hex string to decode.
 * @param off number of zero-bytes to prefix.
 * @return newly allocated array with `off` leading zeros followed by the decoded bytes.
 */
fun hexToBytes(s: String, off: Int): ByteArray {
  val bs = ByteArray(off + (1 + s.length) / 2)
  hexToBytes(s, bs, off)
  return bs
}

/**
 * Decodes a hex string into a provided output buffer starting at `off`.
 *
 * Accepts both lowercase and uppercase digits. For odd-length input, a leading `0` is assumed. The
 * caller must provide a large enough `out` buffer to hold the decoded bytes starting at the
 * requested offset.
 *
 * @param s hex string to decode.
 * @param out destination array to receive bytes.
 * @param off starting offset in `out` (0-based).
 * @throws NumberFormatException if `s` contains a non-hexadecimal character.
 * @throws IndexOutOfBoundsException if `out.size < off + decodedLength`.
 */
@Throws(NumberFormatException::class, IndexOutOfBoundsException::class)
fun hexToBytes(s: String, out: ByteArray, off: Int) {
  var str = s
  val slen = str.length
  if (slen % 2 != 0) {
    str = "0$str"
  }
  if (out.size < off + slen / 2) {
    throw IndexOutOfBoundsException(
      "Output buffer too small for input (${out.size}<${off + slen / 2})"
    )
  }
  var i = 0
  while (i < slen) {
    val b1 = Character.digit(str[i], 16).toByte()
    val b2 = Character.digit(str[i + 1], 16).toByte()
    if (b1.toInt() < 0 || b2.toInt() < 0) {
      throw NumberFormatException()
    }
    out[off + i / 2] = ((b1.toInt() shl 4) or b2.toInt()).toByte()
    i += 2
  }
}

/**
 * Packs the first `size` bits of a [BitSet] into a little‑endian byte array.
 *
 * Bit index `j` maps to mask `1 shl j` within a byte (LSB first). The output length is
 * `countBytesForBits(size)`.
 *
 * @param ba source bits.
 * @param size number of bits to read from `ba`.
 * @return new byte array containing the packed bits.
 */
fun bitsToBytes(ba: BitSet, size: Int): ByteArray {
  val bytesAlloc = countBytesForBits(size)
  val b = ByteArray(bytesAlloc)
  val debugBuilder: StringBuilder? = if (logDEBUG) StringBuilder(8 * bytesAlloc) else null
  for (i in 0 until bytesAlloc) {
    val startBit = i * 8
    val s = computeByteFromBits(ba, startBit, size, debugBuilder)
    b[i] = s.toByte()
  }
  if (logDEBUG) {
    LOG.debug(
      "bytes: {} returned from bitsToBytes({},{}): {} for {}",
      bytesAlloc,
      ba,
      size,
      bytesToHex(b),
      debugBuilder.toString(),
    )
  }
  return b
}

private fun computeByteFromBits(
  ba: BitSet,
  startBit: Int,
  size: Int,
  debugBuilder: StringBuilder?,
): Int {
  var s = 0
  for (j in 0 until 8) {
    val idx = startBit + j
    val value = (idx <= size - 1) && ba[idx]
    if (value) s = s or (1 shl j)
    debugBuilder?.append(if (value) '1' else '0')
  }
  check(s <= 255) { "WTF? s = $s" }
  return s
}

/**
 * Converts the first `size` bits of a [BitSet] into a lowercase hexadecimal string.
 *
 * @param ba source bits.
 * @param size number of bits to read from `ba`.
 * @return hex string produced by `bytesToHex(bitsToBytes(ba, size))`.
 */
fun bitsToHexString(ba: BitSet, size: Int): String = bytesToHex(bitsToBytes(ba, size))

/**
 * Returns the two's‑complement hexadecimal representation of a [BigInteger].
 *
 * This is equivalent to `bytesToHex(i.toByteArray())` and thus may include a leading sign byte.
 *
 * @param i integer to encode.
 * @return lowercase hex representation of `i`.
 * @see biToHex
 */
fun toHexString(i: BigInteger): String = bytesToHex(i.toByteArray())

/**
 * Returns the number of bytes required to store `size` bits.
 *
 * This performs a ceiling division by 8: `(size + 7) / 8`.
 *
 * @param size number of bits.
 * @return minimum byte count to hold `size` bits.
 */
fun countBytesForBits(size: Int): Int = (size + 7) / 8

/**
 * Expands a byte array into a [BitSet].
 *
 * Bits are unpacked with LSB‑first semantics (mask `1 shl j`). Up to and including bit index
 * `maxSize` is written; i.e., pass `7` to copy exactly 8 bits.
 *
 * @param b source bytes.
 * @param ba destination bit set to populate.
 * @param maxSize highest bit index (inclusive) to write.
 */
fun bytesToBits(b: ByteArray, ba: BitSet, maxSize: Int) {
  if (logDEBUG) LOG.debug("bytesToBits({},ba,{} )", bytesToHex(b), maxSize)
  var x = 0
  for (bi in b) {
    for (j in 0 until 8) {
      if (x > maxSize) break
      val mask = 1 shl j
      val value = (mask and bi.toInt()) != 0
      ba[x] = value
      x++
    }
  }
}

/**
 * Decodes a hex string and writes its bits into a [BitSet].
 *
 * The same LSB‑first mapping as in [bytesToBits] applies.
 *
 * @param s hex string to decode.
 * @param ba destination bit set to populate.
 * @param length highest bit index (inclusive) to write.
 */
fun hexToBits(s: String, ba: BitSet, length: Int) {
  val b = hexToBytes(s)
  bytesToBits(b, ba, length)
}

/**
 * Writes a non‑negative [BigInteger] to a [DataOutputStream].
 *
 * The format is a signed 16‑bit length (number of bytes of `toByteArray()`), followed by the raw
 * two's‑complement bytes. Negative values are rejected. Extremely large values are rejected when
 * the encoded length would exceed `Short.MAX_VALUE`.
 *
 * @param integer non‑negative value to write.
 * @param out destination stream.
 * @throws IOException on I/O error while writing.
 * @throws IllegalArgumentException if `integer` is negative.
 * @throws IllegalStateException if the encoded byte array length exceeds `Short.MAX_VALUE`.
 */
@Throws(IOException::class)
fun writeBigInteger(integer: BigInteger, out: DataOutputStream) {
  require(integer.signum() != -1) { "Negative BigInteger!" }
  val buf = integer.toByteArray()
  check(buf.size <= Short.MAX_VALUE.toInt()) { "Too long: ${buf.size}" }
  out.writeShort(buf.size)
  out.write(buf)
}

/**
 * Reads a [BigInteger] value written by [writeBigInteger].
 *
 * The method reads a signed 16‑bit length; negative values are rejected. It then reads exactly that
 * many bytes and constructs a positive `BigInteger` with `BigInteger(1, bytes)`.
 *
 * @param dis source data stream.
 * @return decoded non‑negative integer.
 * @throws IOException if the length is negative, if the stream ends prematurely, or an I/O error
 *   occurs while reading.
 */
@Throws(IOException::class)
fun readBigInteger(dis: DataInputStream): BigInteger {
  val i = dis.readShort()
  if (i.toInt() < 0) throw IOException("Invalid BigInteger length: $i")
  val buf = ByteArray(i.toInt())
  dis.readFully(buf)
  return BigInteger(1, buf)
}

/**
 * Convenience alias of [toHexString] for a [BigInteger].
 *
 * @param bi integer to encode.
 * @return lowercase hex representation of `bi` using two's‑complement bytes.
 * @see toHexString
 */
fun biToHex(bi: BigInteger): String = bytesToHex(bi.toByteArray())
