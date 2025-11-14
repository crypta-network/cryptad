package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.NullBucket;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class BookmarkFeedTest {

  private static final String HEADER = "Bookmark header";
  private static final String SHORT_TEXT = "Short summary";
  private static final String BODY_TEXT = "Long body of the bookmark notification";
  private static final short PRIORITY_CLASS = 3;
  private static final long UPDATED_TIME = 42L;
  private static final String SOURCE_NODE_NAME = "RemoteNode";
  private static final long COMPOSED = 100L;
  private static final long SENT = 200L;
  private static final long RECEIVED = 300L;
  private static final String BOOKMARK_NAME = "Favorite link";

  @Test
  void getFieldSet_whenBookmarkHasMetadata_exportsNameUriAndFlags() throws Exception {
    FreenetURI uri = sampleUri();
    BookmarkFeed feed =
        new BookmarkFeed(
            HEADER,
            SHORT_TEXT,
            BODY_TEXT,
            PRIORITY_CLASS,
            UPDATED_TIME,
            SOURCE_NODE_NAME,
            COMPOSED,
            SENT,
            RECEIVED,
            BOOKMARK_NAME,
            uri,
            "A bookmark description",
            true);

    SimpleFieldSet fieldSet = feed.getFieldSet();

    assertEquals(HEADER, fieldSet.getString("Header"));
    assertEquals(SHORT_TEXT, fieldSet.getString("ShortText"));
    assertEquals(PRIORITY_CLASS, fieldSet.getLong("PriorityClass"));
    assertEquals(UPDATED_TIME, fieldSet.getLong("UpdatedTime"));
    assertEquals(SOURCE_NODE_NAME, fieldSet.getString("SourceNodeName"));
    assertEquals(COMPOSED, fieldSet.getLong("TimeComposed"));
    assertEquals(SENT, fieldSet.getLong("TimeSent"));
    assertEquals(RECEIVED, fieldSet.getLong("TimeReceived"));
    assertEquals(BOOKMARK_NAME, fieldSet.getString("Name"));
    assertEquals(uri.toString(), fieldSet.getString("URI"));
    assertEquals("true", fieldSet.getString("HasAnActivelink"));
  }

  @Test
  void constructor_whenDescriptionProvided_storesDescriptionAsArrayBucket() throws Exception {
    String description = "UTF-8: café";
    BookmarkFeed feed = createFeedWithDescription(description);

    Bucket descriptionBucket = feed.buckets.get("Description");

    assertNotNull(descriptionBucket);
    assertInstanceOf(ArrayBucket.class, descriptionBucket);
    assertEquals(description, bucketToString(descriptionBucket));
  }

  @Test
  void constructor_whenDescriptionMissing_usesNullBucketPlaceholder() {
    BookmarkFeed feed = createFeedWithDescription(null);

    Bucket descriptionBucket = feed.buckets.get("Description");

    assertNotNull(descriptionBucket);
    assertInstanceOf(NullBucket.class, descriptionBucket);
    assertEquals(0, descriptionBucket.size());
  }

  @Test
  void getName_alwaysReturnsBookmarkFeedConstant() {
    BookmarkFeed feed = createFeedWithDescription("desc");

    assertEquals(BookmarkFeed.NAME, feed.getName());
  }

  private static BookmarkFeed createFeedWithDescription(String description) {
    return new BookmarkFeed(
        HEADER,
        SHORT_TEXT,
        BODY_TEXT,
        PRIORITY_CLASS,
        UPDATED_TIME,
        SOURCE_NODE_NAME,
        COMPOSED,
        SENT,
        RECEIVED,
        BOOKMARK_NAME,
        sampleUri(),
        description,
        false);
  }

  private static FreenetURI sampleUri() {
    return new FreenetURI("KSK", "bookmark");
  }

  private static String bucketToString(Bucket bucket) throws IOException {
    try (InputStream inputStream = bucket.getInputStream()) {
      return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    }
  }
}
