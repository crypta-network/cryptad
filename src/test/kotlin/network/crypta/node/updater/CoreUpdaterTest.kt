package network.crypta.node.updater

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

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
    assertEquals(info.version, "1.2.3+build123")
    assertEquals(info.releasePageUrl, "https://example.com/r/1.2.3")
    assertEquals(info.packages["amd64.deb"]?.chk, "CHK@abc")
    assertEquals(10L, info.packages["amd64.deb"]?.size)
    assertEquals(info.changelogChk, "CHK@chg")
    assertEquals(info.fullChangelogChk, "CHK@full")
  }

  @Test
  fun json_missing_optional_fields() {
    val json = """{ "version":"2", "packages": {"amd64.exe": {"chk":"CHK@x"}} }"""
    val info = CoreJson.parse(json)
    assertEquals(info.version, "2")
    assertNotNull(info.packages["amd64.exe"])
    assertNull(info.releasePageUrl)
  }
}
