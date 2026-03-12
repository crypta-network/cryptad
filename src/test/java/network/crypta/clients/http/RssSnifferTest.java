package network.crypta.clients.http;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RssSnifferTest {

  @ParameterizedTest(name = "recognizes feed prefix: {0}")
  @MethodSource("recognizedFeeds")
  void isSniffedAsFeed_whenTopLevelFeedLikeTags_returnsTrue(String data) {
    // Arrange
    byte[] prefix = data.getBytes(UTF_8);

    // Act
    boolean sniffed = RssSniffer.isSniffedAsFeed(prefix);

    // Assert
    assertTrue(sniffed);
  }

  @ParameterizedTest(name = "does not mis-detect: {0}")
  @MethodSource("nonFeedPrefixes")
  void isSniffedAsFeed_whenTagIsNotEligible_returnsFalse(String data) {
    // Arrange
    byte[] prefix = data.getBytes(UTF_8);

    // Act
    boolean sniffed = RssSniffer.isSniffedAsFeed(prefix);

    // Assert
    assertFalse(sniffed);
  }

  @Test
  void isSniffedAsFeed_whenFirstTagIncomplete_returnsFalse() {
    // Arrange
    String incompleteDoctype = "<!DOCTYPE html"; // missing closing '>'
    byte[] prefix = incompleteDoctype.getBytes(UTF_8);

    // Act
    boolean sniffed = RssSniffer.isSniffedAsFeed(prefix);

    // Assert
    assertFalse(sniffed);
  }

  @Test
  void isSniffedAsFeed_whenDataShorterThanKey_returnsFalse() {
    // Arrange
    byte[] prefix = "<rs".getBytes(UTF_8);

    // Act
    boolean sniffed = RssSniffer.isSniffedAsFeed(prefix);

    // Assert
    assertFalse(sniffed);
  }

  private static Stream<String> recognizedFeeds() {
    return Stream.of(
        "<rss version=\"2.0\">",
        "<?xml version=\"1.0\"?><rss>",
        "<!-- leading comment --><feed>",
        "<!DOCTYPE html><rss>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!----><rdf:RDF attr=\"v\">",
        "   <rss>");
  }

  private static Stream<String> nonFeedPrefixes() {
    return Stream.of(
        "",
        "plain text only",
        "<!rss", // comment without terminator
        "<html><rss>", // first top-level tag is not a feed indicator
        "<!--<rss>-->",
        "<!DOCTYPE html><bogus><rss",
        "<bogus><rdf:RDF>");
  }
}
