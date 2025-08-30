package network.crypta.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Minimal CLI entry that launches the Crypta wrapper similarly to LauncherController.start().
 *
 * Run with the assembled jar:
 *   java -cp cryptad.jar network.crypta.launcher.LauncherStartCliKt [args]
 *
 * Respects CRYPTAD_PATH for resolving the wrapper script. Prints the effective command and cwd,
 * streams combined stdout+stderr, and exits when the process terminates.
 */
fun main(args: Array<String>) {
  val cwd = Paths.get(System.getProperty("user.dir"))
  val cryptad = resolveCryptadPathWithEnv(cwd, System.getenv())
  if (!Files.isRegularFile(cryptad) || !Files.isExecutable(cryptad)) {
    println(tsCli() + " ERROR: Cannot find executable 'cryptad' at $cryptad")
    return
  }

  // Best-effort: enable wrapper console flush if wrapper.conf is available
  tryEnableConsoleFlushCli(cryptad)

  val cmd = buildCryptadCommand(cryptad)
  println(tsCli() + " exec: " + formatCommandForLog(cmd) + " (cwd=" + cwd.toAbsolutePath() + ")")

  val pb = ProcessBuilder(cmd)
  pb.redirectErrorStream(true)
  pb.directory(cwd.toFile())

  val p = pb.start()

  // Stream combined stdout+stderr until exit
  p.inputStream.bufferedReader(StandardCharsets.UTF_8).use { br ->
    var line: String?
    while (br.readLine().also { line = it } != null) {
      println(line)
    }
  }
  val code = p.waitFor()
  println(tsCli() + " cryptad exited with code $code")
}

private fun tryEnableConsoleFlushCli(cryptadPath: Path) {
  try {
    val conf = guessWrapperConfPathForCryptadScript(cryptadPath) ?: return
    if (!Files.isRegularFile(conf)) return
    val lines = Files.readAllLines(conf, StandardCharsets.UTF_8)
    val props = parseWrapperProperties(lines)
    if (props["wrapper.console.flush"]?.equals("TRUE", ignoreCase = true) == true) return
    val updated = upsertWrapperProperty(lines, "wrapper.console.flush", "TRUE")
    Files.write(conf, updated, StandardCharsets.UTF_8)
  } catch (_: Throwable) {
    // best-effort only
  }
}

private fun formatCommandForLog(cmd: List<String>): String {
  val isWindows = System.getProperty("os.name").lowercase().contains("win")
  return cmd.joinToString(" ") { arg ->
    if (isWindows) {
      if (arg.any { it.isWhitespace() || it == '"' }) "\"" + arg.replace("\"", "\\\"") + "\""
      else arg
    } else {
      if (arg.any { it.isWhitespace() || it == '\'' || it == '"' || it == '\\' }) shellQuote(arg)
      else arg
    }
  }
}

private fun tsCli(): String =
  java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME)
