package freenet.support

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.math.BigInteger
import java.util.*

object HexUtil {
    private val logDEBUG: Boolean = Logger.shouldLog(Logger.LogLevel.DEBUG, HexUtil::class.java)

    @JvmStatic
    fun bytesToHex(bs: ByteArray, off: Int, length: Int): String {
        if (bs.size < off + length)
            throw IllegalArgumentException("Total length: ${bs.size}, offset: $off, length: $length")
        val sb = StringBuilder(length * 2)
        bytesToHexAppend(bs, off, length, sb)
        return sb.toString()
    }

    @JvmStatic
    fun bytesToHexAppend(bs: ByteArray, off: Int, length: Int, sb: StringBuilder) {
        if (bs.size < off + length)
            throw IllegalArgumentException()
        sb.ensureCapacity(sb.length + length * 2)
        for (i in off until off + length) {
            val b = bs[i].toInt()
            sb.append(Character.forDigit((b ushr 4) and 0xf, 16))
            sb.append(Character.forDigit(b and 0xf, 16))
        }
    }

    @JvmStatic
    fun bytesToHex(bs: ByteArray): String = bytesToHex(bs, 0, bs.size)

    @JvmStatic
    fun hexToBytes(s: String): ByteArray = hexToBytes(s, 0)

    @JvmStatic
    fun hexToBytes(s: String, off: Int): ByteArray {
        val bs = ByteArray(off + (1 + s.length) / 2)
        hexToBytes(s, bs, off)
        return bs
    }

    @JvmStatic
    @Throws(NumberFormatException::class, IndexOutOfBoundsException::class)
    fun hexToBytes(s: String, out: ByteArray, off: Int) {
        var str = s
        val slen = str.length
        if (slen % 2 != 0) {
            str = "0" + str
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

    @JvmStatic
    fun bitsToBytes(ba: BitSet, size: Int): ByteArray {
        val bytesAlloc = countBytesForBits(size)
        val b = ByteArray(bytesAlloc)
        val debugBuilder: StringBuilder? = if (logDEBUG) StringBuilder(8 * bytesAlloc) else null
        for (i in b.indices) {
            var s: Int = 0
            for (j in 0 until 8) {
                val idx = i * 8 + j
                val value = if (idx > size - 1) false else ba.get(idx)
                if (value) s = s or (1 shl j)
                if (logDEBUG) debugBuilder!!.append(if (value) '1' else '0')
            }
            if (s > 255) throw IllegalStateException("WTF? s = $s")
            b[i] = s.toByte()
        }
        if (logDEBUG) Logger.debug(
            HexUtil::class.java,
            "bytes: $bytesAlloc returned from bitsToBytes($ba,$size): ${bytesToHex(b)} for ${debugBuilder.toString()}"
        )
        return b
    }

    @JvmStatic
    fun bitsToHexString(ba: BitSet, size: Int): String = bytesToHex(bitsToBytes(ba, size))

    @JvmStatic
    fun toHexString(i: BigInteger): String = bytesToHex(i.toByteArray())

    @JvmStatic
    fun countBytesForBits(size: Int): Int = (size + 7) / 8

    @JvmStatic
    fun bytesToBits(b: ByteArray, ba: BitSet, maxSize: Int) {
        if (logDEBUG) Logger.debug(HexUtil::class.java, "bytesToBits(${bytesToHex(b)},ba,$maxSize)")
        var x = 0
        for (bi in b) {
            for (j in 0 until 8) {
                if (x > maxSize) break
                val mask = 1 shl j
                val value = (mask and bi.toInt()) != 0
                ba.set(x, value)
                x++
            }
        }
    }

    @JvmStatic
    fun hexToBits(s: String, ba: BitSet, length: Int) {
        val b = hexToBytes(s)
        bytesToBits(b, ba, length)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeBigInteger(integer: BigInteger, out: DataOutputStream) {
        if (integer.signum() == -1) {
            throw IllegalStateException("Negative BigInteger!")
        }
        val buf = integer.toByteArray()
        if (buf.size > Short.MAX_VALUE.toInt())
            throw IllegalStateException("Too long: ${buf.size}")
        out.writeShort(buf.size)
        out.write(buf)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readBigInteger(dis: DataInputStream): BigInteger {
        val i = dis.readShort()
        if (i.toInt() < 0) throw IOException("Invalid BigInteger length: $i")
        val buf = ByteArray(i.toInt())
        dis.readFully(buf)
        return BigInteger(1, buf)
    }

    @JvmStatic
    fun biToHex(bi: BigInteger): String = bytesToHex(bi.toByteArray())
}
