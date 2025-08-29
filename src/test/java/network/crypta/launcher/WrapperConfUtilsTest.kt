package network.crypta.launcher

import java.nio.file.Paths
import org.junit.Assert.assertEquals
import org.junit.Test

class WrapperConfUtilsTest {
  @Test
  fun upsertsProperty() {
    val lines = listOf("# Comment", "wrapper.name=cryptad", "wrapper.console.loglevel=INFO")
    val updated = upsertWrapperProperty(lines, "wrapper.console.flush", "TRUE")
    val props = parseWrapperProperties(updated)
    assertEquals("TRUE", props["wrapper.console.flush"])
    // Existing untouched
    assertEquals("cryptad", props["wrapper.name"])
  }

  @Test
  fun replacesExistingProperty() {
    val lines = listOf("wrapper.console.flush=FALSE", "wrapper.name=cryptad")
    val updated = upsertWrapperProperty(lines, "wrapper.console.flush", "TRUE")
    val props = parseWrapperProperties(updated)
    assertEquals("TRUE", props["wrapper.console.flush"])
  }

  @Test
  fun computesLogPathRelative() {
    val conf = Paths.get("/opt/crypta/conf/wrapper.conf")
    val log = computeWrapperLogPath(conf, "../logs/wrapper.log").normalize()
    assertEquals(Paths.get("/opt/crypta/logs/wrapper.log").normalize(), log)
  }

  @Test
  fun computesLogPathAbsolute() {
    val conf = Paths.get("/opt/crypta/conf/wrapper.conf")
    val log = computeWrapperLogPath(conf, "/var/log/crypta/wrapper.log")
    assertEquals(Paths.get("/var/log/crypta/wrapper.log"), log)
  }
}
