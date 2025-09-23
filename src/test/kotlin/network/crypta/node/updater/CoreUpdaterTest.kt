package network.crypta.node.updater

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class CoreUpdaterTest {
  @Test
  fun parseJson_minimal() {
    val json =
      """
          {
            "version": "1.2.3+build123",
            "release_page_url": "https://example.com/r/1.2.3",
            "packages": {
              "amd64.deb": { "chk": "CHK@abc", "size": 10 },
              "arm64.dmg": { "chk": "CHK@def" }
            },
            "changelog_chk": "CHK@chg",
            "fullchangelog_chk": "CHK@full"
          }
      """
        .trimIndent()
    val info = CoreJson.parse(json)
    assertEquals("1.2.3+build123", info.version)
    assertEquals("https://example.com/r/1.2.3", info.releasePageUrl)
    assertEquals("CHK@abc", info.packages["amd64.deb"]?.chk)
    assertEquals(10L, info.packages["amd64.deb"]?.size)
    assertEquals("CHK@chg", info.changelogChk)
    assertEquals("CHK@full", info.fullChangelogChk)
  }

  @Test
  fun json_missing_optional_fields() {
    val json = """{ "version":"2", "packages": {"amd64.exe": {"chk":"CHK@x"}} }"""
    val info = CoreJson.parse(json)
    assertEquals("2", info.version)
    assertNotNull(info.packages["amd64.exe"])
    assertNull(info.releasePageUrl)
  }
}
