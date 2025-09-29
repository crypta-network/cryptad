@file:JvmName("TestRandomData")

package network.crypta.testsupport

import java.io.IOException
import java.io.OutputStream
import java.util.Random
import network.crypta.support.api.Bucket
import network.crypta.support.api.LockableRandomAccessBuffer

private const val DEFAULT_BUFFER_SIZE = 64 * 1024

@JvmOverloads
@Throws(IOException::class)
fun fillRandomAccessBuffer(
  buffer: LockableRandomAccessBuffer,
  random: Random,
  offset: Long,
  length: Long,
  chunkSize: Int = DEFAULT_BUFFER_SIZE,
) {
  require(chunkSize > 0) { "chunkSize must be positive" }
  if (length <= 0) return
  var remaining = length
  var position = offset
  val chunk = ByteArray(minOf(chunkSize.toLong(), remaining).toInt())
  while (remaining > 0) {
    val toWrite = minOf(chunk.size.toLong(), remaining).toInt()
    random.nextBytes(chunk)
    buffer.pwrite(position, chunk, 0, toWrite)
    position += toWrite
    remaining -= toWrite
  }
}

@JvmOverloads
@Throws(IOException::class)
fun fillBucketWithRandom(
  bucket: Bucket,
  random: Random,
  length: Long,
  useUnbufferedStream: Boolean = false,
  chunkSize: Int = DEFAULT_BUFFER_SIZE,
) {
  require(chunkSize > 0) { "chunkSize must be positive" }
  if (length <= 0) {
    val closer: () -> OutputStream =
      if (useUnbufferedStream) bucket::getOutputStreamUnbuffered else bucket::getOutputStream
    closer().use {}
    return
  }
  val chunk = ByteArray(minOf(chunkSize.toLong(), length).toInt())
  var remaining = length
  val outputSupplier: () -> OutputStream =
    if (useUnbufferedStream) bucket::getOutputStreamUnbuffered else bucket::getOutputStream
  outputSupplier().use { out ->
    while (remaining > 0) {
      val toWrite = minOf(chunk.size.toLong(), remaining).toInt()
      random.nextBytes(chunk)
      out.write(chunk, 0, toWrite)
      remaining -= toWrite
    }
  }
}
