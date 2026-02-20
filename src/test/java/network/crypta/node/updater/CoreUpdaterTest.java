package network.crypta.node.updater;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class CoreUpdaterTest {
  @Test
  void parseJson_minimal() {
    String json =
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
        """;

    CoreInfo info = CoreJson.parse(json);

    assertEquals("1.2.3+build123", info.version());
    assertEquals("https://example.com/r/1.2.3", info.releasePageUrl());
    assertEquals("CHK@abc", info.packages().get("amd64.deb").chk());
    assertEquals(10L, info.packages().get("amd64.deb").size());
    assertEquals("CHK@chg", info.changelogChk());
    assertEquals("CHK@full", info.fullChangelogChk());
  }

  @Test
  void json_missingOptionalFields() {
    String json = "{ \"version\":\"2\", \"packages\": {\"amd64.exe\": {\"chk\":\"CHK@x\"}} }";

    CoreInfo info = CoreJson.parse(json);

    assertEquals("2", info.version());
    assertNotNull(info.packages().get("amd64.exe"));
    assertNull(info.releasePageUrl());
  }
}
