package network.crypta.runtime.admin;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.node.Node;
import network.crypta.runtime.spi.WelcomePageSnapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyWelcomePagePortTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void snapshot_whenFetchKeyBoxConfiguredAboveBookmarks_returnsDetachedSnapshot() {
    when(node.getConfig().get("fproxy").getBoolean("fetchKeyBoxAboveBookmarks")).thenReturn(true);

    WelcomePageSnapshot snapshot = new LegacyWelcomePagePort(node).snapshot();

    assertEquals(new WelcomePageSnapshot(true), snapshot);
  }

  @Test
  void latestNodeLogTail_whenCryptaLogExists_prefersCryptaLatestLog(@TempDir Path tmp)
      throws Exception {
    Files.writeString(tmp.resolve("crypta-latest.log"), "crypta-tail\n", StandardCharsets.UTF_8);
    Files.writeString(tmp.resolve("freenet-latest.log"), "freenet-tail\n", StandardCharsets.UTF_8);

    String text = newPort(tmp).latestNodeLogTail();

    assertEquals("crypta-tail\n", text);
  }

  @Test
  void latestNodeLogTail_whenCryptaLogMissing_fallsBackToFreenetLatestLog(@TempDir Path tmp)
      throws Exception {
    Files.writeString(tmp.resolve("freenet-latest.log"), "freenet-tail\n", StandardCharsets.UTF_8);

    String text = newPort(tmp).latestNodeLogTail();

    assertEquals("freenet-tail\n", text);
  }

  @Test
  void latestNodeLogTail_whenLogExceedsLimit_returnsTailFromNextFullLine(@TempDir Path tmp)
      throws Exception {
    String content = "x".repeat(100001) + "\nfull-tail-line\n";
    Files.writeString(tmp.resolve("crypta-latest.log"), content, StandardCharsets.UTF_8);

    String text = newPort(tmp).latestNodeLogTail();

    assertEquals("full-tail-line\n", text);
  }

  private LegacyWelcomePagePort newPort(Path logDir) {
    when(node.getConfig().get("logger").getString("dirname")).thenReturn(logDir.toString());
    return new LegacyWelcomePagePort(node);
  }
}
