package cryptad

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal object StableSupplyChainJson {
  fun encode(value: Any?): ByteArray =
    (buildString { appendValue(value) } + "\n").toByteArray(StandardCharsets.UTF_8)

  fun canonicalBytes(value: Any?): ByteArray =
    buildString { appendValue(value) }.toByteArray(StandardCharsets.UTF_8)

  fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

  private fun StringBuilder.appendValue(value: Any?) {
    when (value) {
      null -> append("null")
      is Boolean -> append(if (value) "true" else "false")
      is Number -> append(value.toString())
      is String -> appendString(value)
      is Map<*, *> -> {
        append('{')
        value.entries
          .map { entry ->
            val key = entry.key as? String ?: error("Canonical JSON object keys must be strings")
            key to entry.value
          }
          .sortedBy { it.first }
          .forEachIndexed { index, (key, child) ->
            if (index > 0) append(',')
            appendString(key)
            append(':')
            appendValue(child)
          }
        append('}')
      }
      is Iterable<*> -> {
        append('[')
        value.forEachIndexed { index, child ->
          if (index > 0) append(',')
          appendValue(child)
        }
        append(']')
      }
      else -> error("Unsupported canonical JSON value type: ${value::class.qualifiedName}")
    }
  }

  private fun StringBuilder.appendString(value: String) {
    append('"')
    value.forEach { character ->
      when (character) {
        '"' -> append("\\\"")
        '\\' -> append("\\\\")
        '\b' -> append("\\b")
        '\u000c' -> append("\\f")
        '\n' -> append("\\n")
        '\r' -> append("\\r")
        '\t' -> append("\\t")
        else ->
          if (character.code < 0x20) {
            append("\\u")
            append(character.code.toString(16).padStart(4, '0'))
          } else {
            append(character)
          }
      }
    }
    append('"')
  }

  private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }
}
