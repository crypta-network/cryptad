package network.crypta.tools

import network.crypta.fs.AppDirs
import network.crypta.fs.AppEnv
import network.crypta.fs.Resolved
import network.crypta.fs.ServiceDirs

fun main() {
  val appEnv = AppEnv(System.getenv())
  println("cryptad.service.mode=${System.getProperty("cryptad.service.mode")}")
  if (appEnv.isServiceMode()) {
    val r = ServiceDirs().resolve()
    println("mode=service")
    printDirs(r)
  } else {
    val r = AppDirs().resolve()
    println("mode=user")
    printDirs(r)
  }
}

private fun printDirs(resolved: Resolved) {
  println("configDir=${resolved.configDir}")
  println("dataDir=${resolved.dataDir}")
  println("cacheDir=${resolved.cacheDir}")
  println("runDir=${resolved.runDir}")
  println("logsDir=${resolved.logsDir}")
}
