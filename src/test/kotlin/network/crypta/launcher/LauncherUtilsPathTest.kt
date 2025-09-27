package network.crypta.launcher

import java.nio.file.Paths
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class LauncherUtilsPathTest {
  @Test
  fun computeWrapperFilePath_resolves_relative_to_working_dir() {
    val conf = Paths.get("/opt/cryptad/conf/wrapper.conf")
    val p = computeWrapperFilePath(conf, "Cryptad.anchor", "..")
    assertEquals(p, Paths.get("/opt/cryptad/Cryptad.anchor"))
  }

  @Test
  fun computeWrapperFilePath_falls_back_to_conf_dir_when_no_working_dir() {
    val conf = Paths.get("/opt/cryptad/conf/wrapper.conf")
    val p = computeWrapperFilePath(conf, "../logs/wrapper.log", null)
    assertEquals(p, Paths.get("/opt/cryptad/logs/wrapper.log"))
  }

  @Test
  fun computeWrapperFilePath_returns_null_on_blank_spec() {
    val conf = Paths.get("/opt/cryptad/conf/wrapper.conf")
    val p = computeWrapperFilePath(conf, "  ", "..")
    assertNull(p)
  }
}
