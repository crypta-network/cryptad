@file:JvmName("HexUtil")

/**
 * Provides utility methods for conversions between hexadecimal strings, byte arrays,
 * BitSets, and BigIntegers. Also includes I/O operations for BigIntegers.
 */

package freenet.support

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.math.BigInteger
import java.util.*

private val fileClass: Class<*> = object {}.javaClass.enclosingClass

private val logDEBUG: Boolean = Logger.shouldLog(Logger.LogLevel.DEBUG, fileClass)

/**
 * Converts a subsection of a byte array into a hexadecimal string.
 *
 * @param bs The source byte array.
 * @param off The starting offset within the byte array.
 * @param length The number of bytes to convert.
 * @return The hexadecimal string representation of the specified subsection.
 * @throws IllegalArgumentException if the offset and length are out of bounds for the array.
 */
fun bytesToHex(bs: ByteArray, off: Int, length: Int): String {
    require(bs.size >= off + length) { "Total length: ${bs.size}, offset: $off, length: $length" }
    val sb = StringBuilder(length * 2)
    bytesToHexAppend(bs, off, length, sb)
    return sb.toString()
}

/**
 * Converts a subsection of a byte array into hexadecimal characters and appends them to a StringBuilder.
 *
 * @param bs The source byte array.
 * @param off The starting offset within the byte array.
 * @param length The number of bytes to convert.
 * @param sb The StringBuilder to which the hexadecimal string will be appended.
 * @throws IllegalArgumentException if the offset and length are out of bounds for the array.
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
 * Converts an entire byte array into a hexadecimal string.
 *
 * @param bs The byte array to convert.
 * @return The hexadecimal string representation of the byte array.
 */
fun bytesToHex(bs: ByteArray): String = bytesToHex(bs, 0, bs.size)

/**
 * Converts a hexadecimal string into a new byte array.
 *
 * @param s The hexadecimal string to convert.
 * @return A new byte array containing the decoded bytes.
 * @see hexToBytes
 */
fun hexToBytes(s: String): ByteArray = hexToBytes(s, 0)

/**
 * Converts a hexadecimal string into a new byte array with a specified leading offset.
 * The resulting array will be prefixed with `off` zero-bytes.
 *
 * @param s The hexadecimal string to convert.
 * @param off The number of zero-bytes to prefix to the output array.
 * @return A new byte array containing `off` zero-bytes followed by the decoded bytes from the string.
 */
fun hexToBytes(s: String, off: Int): ByteArray {
    val bs = ByteArray(off + (1 + s.length) / 2)
    hexToBytes(s, bs, off)
    return bs
}

/**
 * Decodes a hexadecimal string into a provided byte array at a given offset.
 * If the string has an odd length, it is implicitly prefixed with a '0'.
 *
 * @param s The hexadecimal string to convert.
 * @param out The destination byte array.
 * @param off The starting offset in the destination array `out`.
 * @throws NumberFormatException if the string `s` contains non-hexadecimal characters.
 * @throws IndexOutOfBoundsException if the output buffer `out` is too small to hold the decoded bytes.
 */
@Throws(NumberFormatException::class, IndexOutOfBoundsException::class)
fun hexToBytes(s: String, out: ByteArray, off: Int) {
    var str = s
    val slen = str.length
    if (slen % 2 != 0) {
        str = "0$str"
    }
    if (out.size < off + slen / 2) {
        throw IndexOutOfBoundsException("Output buffer too small for input (${out.size}<${off + slen / 2})")
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
 * Converts the first `size` bits of a BitSet into a byte array.
 *
 * @param ba The BitSet to convert.
 * @param size The number of bits from the BitSet to convert.
 * @return A new byte array representing the specified bits.
 */
fun bitsToBytes(ba: BitSet, size: Int): ByteArray {
    val bytesAlloc = countBytesForBits(size)
    val b = ByteArray(bytesAlloc)
    val debugBuilder: StringBuilder? = if (logDEBUG) StringBuilder(8 * bytesAlloc) else null
    for (i in b.indices) {
        var s: Int = 0
        for (j in 0 until 8) {
            val idx = i * 8 + j
            val value = (idx <= size - 1) && ba[idx]
            if (value) s = s or (1 shl j)
            if (logDEBUG) debugBuilder!!.append(if (value) '1' else '0')
        }
        check(s <= 255) { "WTF? s = $s" }
        b[i] = s.toByte()
    }
    if (logDEBUG) Logger.debug(
        fileClass,
        "bytes: $bytesAlloc returned from bitsToBytes($ba,$size): ${bytesToHex(b)} for ${debugBuilder.toString()}"
    )
    return b
}

/**
 * Converts the first `size` bits of a BitSet into a hexadecimal string.
 *
 * @param ba The BitSet to convert.
 * @param size The number of bits to use from the BitSet.
 * @return The resulting hexadecimal string.
 */
fun bitsToHexString(ba: BitSet, size: Int): String = bytesToHex(bitsToBytes(ba, size))

/**
 * Converts a BigInteger to its hexadecimal string representation using two's complement.
 *
 * @param i The BigInteger to convert.
 * @return The hexadecimal string of the BigInteger.
 * @see biToHex
 */
fun toHexString(i: BigInteger): String = bytesToHex(i.toByteArray())

/**
 * Calculates the number of bytes required to store a given number of bits.
 *
 * @param size The number of bits.
 * @return The minimum number of bytes needed to store the bits.
 */
fun countBytesForBits(size: Int): Int = (size + 7) / 8

/**
 * Converts a byte array into a BitSet.
 *
 * @param b The source byte array.
 * @param ba The destination BitSet to populate. It will be cleared before population.
 * @param maxSize The maximum number of bits to read from the byte array and set in the BitSet.
 */
fun bytesToBits(b: ByteArray, ba: BitSet, maxSize: Int) {
    if (logDEBUG) Logger.debug(fileClass, "bytesToBits(${bytesToHex(b)},ba,$maxSize)")
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
 * Converts a hexadecimal string into a BitSet.
 *
 * @param s The source hexadecimal string.
 * @param ba The destination BitSet to populate.
 * @param length The maximum number of bits to write to the BitSet.
 */
fun hexToBits(s: String, ba: BitSet, length: Int) {
    val b = hexToBytes(s)
    bytesToBits(b, ba, length)
}

/**
 * Writes a non-negative BigInteger to a DataOutputStream.
 * The BigInteger is written as a short representing the length, followed by the byte array of the BigInteger.
 *
 * @param integer The non-negative BigInteger to write.
 * @param out The DataOutputStream to write to.
 * @throws IOException on an I/O error.
 * @throws IllegalArgumentException if the BigInteger is negative.
 * @throws IllegalStateException if the BigInteger's byte array is too long (exceeds Short.MAX_VALUE).
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
 * Reads a BigInteger from a DataInputStream that was previously written by [writeBigInteger].
 *
 * @param dis The DataInputStream to read from.
 * @return The BigInteger read from the stream.
 * @throws IOException if the length prefix is invalid, an I/O error occurs,
 * or the end of the stream is reached unexpectedly.
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
 * Converts a BigInteger to its hexadecimal string representation.
 * This is a convenience alias for [toHexString].
 *
 * @param bi The BigInteger to convert.
 * @return The hexadecimal string of the BigInteger.
 * @see toHexString
 */
fun biToHex(bi: BigInteger): String = bytesToHex(bi.toByteArray())
