package network.crypta.tools

import network.crypta.fs.AppDirs
import network.crypta.fs.AppEnv
import network.crypta.fs.ServiceDirs

fun main() {
    val env = System.getenv()
    val appEnv = AppEnv(env)
    val service = appEnv.isServiceMode()
    val sys = System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() }
    println("cryptad.service.mode=${System.getProperty("cryptad.service.mode")}")
    if (service) {
        val r = ServiceDirs(env, appEnv).resolve()
        println("mode=service")
        println("configDir=${r.configDir}")
        println("dataDir=${r.dataDir}")
        println("cacheDir=${r.cacheDir}")
        println("runDir=${r.runDir}")
        println("logsDir=${r.logsDir}")
    } else {
        val r = AppDirs(env, sys, emptyMap(), appEnv).resolve()
        println("mode=user")
        println("configDir=${r.configDir}")
        println("dataDir=${r.dataDir}")
        println("cacheDir=${r.cacheDir}")
        println("runDir=${r.runDir}")
        println("logsDir=${r.logsDir}")
    }
}
