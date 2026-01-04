package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import network.crypta.client.async.BlockSet;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.FoundURICallback;
import network.crypta.node.RequestScheduler;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FetchContextTest {

  // Valid defaults for constructor parameters
  private static final long VALID_MAX_OUTPUT = 1024L;
  private static final long VALID_MAX_TEMP = 2048L;
  private static final int VALID_MAX_METADATA = 512;
  private static final int VALID_MAX_RECURSION = 2;
  private static final int VALID_MAX_ARCHIVE_RESTARTS = 1;
  private static final int VALID_MAX_ARCHIVE_LEVELS = 3;
  private static final boolean VALID_DONT_ENTER_IMPLICIT = false;
  private static final int VALID_SPLIT_BLOCK_RETRIES = 0;
  private static final int VALID_NON_SPLIT_RETRIES = 0;
  private static final int VALID_USK_RETRIES = 0;
  private static final boolean VALID_ALLOW_SPLIT = true;
  private static final boolean VALID_FOLLOW_REDIRECTS = true;
  private static final boolean VALID_LOCAL_ONLY = false;
  private static final boolean VALID_FILTER_DATA = true;
  private static final int VALID_MAX_DATABLOCKS = 10;
  private static final int VALID_MAX_CHECKBLOCKS = 10;
  private static final boolean VALID_IGNORE_TOO_MANY = false;
  private static final boolean VALID_CAN_WRITE_CLIENT_CACHE = true;
  private static final String VALID_CHARSET = "UTF-8";
  private static final String VALID_OVERRIDE_MIME = "text/plain";
  private static final String VALID_SCHEME = "https://localhost:1234";

  @Mock private ClientEventProducer producerMock;

  @Test
  void writeToAndReadBack_whenDefaultContext_roundTripsEqual()
      throws IOException, StorageFormatException {
    FetchContext context =
        HighLevelSimpleClientImpl.makeDefaultFetchContext(
            Long.MAX_VALUE, Long.MAX_VALUE, new SimpleEventProducer());
    byte[] bytes;
    try (var baos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(baos)) {
      context.writeTo(dos);
      dos.flush();
      bytes = baos.toByteArray();
    }
    assertNotEquals(0, bytes.length);
    FetchContext ctx;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      ctx = new FetchContext(dis);
    }
    assertEquals(ctx, context);
  }

  @Test
  void constructor_whenValidValues_setsFieldsAndDefaults() {
    FetchContext ctx = createValidContext();
    assertEquals(VALID_MAX_OUTPUT, ctx.getMaxOutputLength());
    assertEquals(VALID_MAX_TEMP, ctx.getMaxTempLength());
    assertEquals(VALID_MAX_RECURSION, ctx.getMaxRecursionLevel());
    assertEquals(VALID_MAX_ARCHIVE_RESTARTS, ctx.getMaxArchiveRestarts());
    assertEquals(VALID_MAX_ARCHIVE_LEVELS, ctx.getMaxArchiveLevels());
    assertTrue(ctx.getAllowSplitfiles());
    assertTrue(ctx.getFollowRedirects());
    assertFalse(ctx.getLocalRequestOnly());
    assertTrue(ctx.getFilterData());
    assertEquals(VALID_MAX_DATABLOCKS, ctx.getMaxDataBlocksPerSegment());
    assertEquals(VALID_MAX_CHECKBLOCKS, ctx.getMaxCheckBlocksPerSegment());
    assertEquals(RequestScheduler.COOLDOWN_RETRIES, ctx.getCooldownRetries());
    assertEquals(RequestScheduler.COOLDOWN_PERIOD, ctx.getCooldownTime());
    assertEquals(VALID_SCHEME, ctx.getSchemeHostAndPort());
  }

  @Test
  void constructor_whenNegativeMaxOutputLength_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                -1L,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenNegativeMaxTempLength_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                -2L,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenNegativeMaxMetadata_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                -1,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenSplitRetriesLessThanMinusOne_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                -2,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenNonSplitRetriesLessThanMinusOne_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                -5,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenUSKRetriesLessThanMinusOne_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                -2,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenDataBlocksOutOfRange_expectIllegalArgumentException() {
    // Negative
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                -1,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
    // Greater than allowed
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT + 1,
                VALID_MAX_CHECKBLOCKS,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void constructor_whenCheckBlocksOutOfRange_expectIllegalArgumentException() {
    // Negative
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                -1,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
    // Greater than allowed
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new FetchContext(
                VALID_MAX_OUTPUT,
                VALID_MAX_TEMP,
                VALID_MAX_METADATA,
                VALID_MAX_RECURSION,
                VALID_MAX_ARCHIVE_RESTARTS,
                VALID_MAX_ARCHIVE_LEVELS,
                VALID_DONT_ENTER_IMPLICIT,
                VALID_SPLIT_BLOCK_RETRIES,
                VALID_NON_SPLIT_RETRIES,
                VALID_USK_RETRIES,
                VALID_ALLOW_SPLIT,
                VALID_FOLLOW_REDIRECTS,
                VALID_LOCAL_ONLY,
                VALID_FILTER_DATA,
                VALID_MAX_DATABLOCKS,
                FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT + 1,
                producerMock,
                VALID_IGNORE_TOO_MANY,
                VALID_CAN_WRITE_CLIENT_CACHE,
                VALID_CHARSET,
                VALID_OVERRIDE_MIME,
                VALID_SCHEME));
  }

  @Test
  void copyConstructor_whenIdenticalMask_expectEqualExceptProducer() {
    FetchContext base = createValidContext();
    FetchContext copy = new FetchContext(base, FetchContext.IDENTICAL_MASK);

    // Event producer should be a new SimpleEventProducer, not the same mock
    assertNotSame(base.getEventProducer(), copy.getEventProducer());
    assertInstanceOf(SimpleEventProducer.class, copy.getEventProducer());

    // Configuration should be equal
    assertEquals(base, copy);
    assertEquals(base.hashCode(), copy.hashCode());
  }

  @Test
  void copyConstructor_whenKeepProducerTrue_preservesProducerInstance() {
    FetchContext base = createValidContext();
    FetchContext copy = new FetchContext(base, FetchContext.IDENTICAL_MASK, true, /*blocks*/ null);
    assertSame(base.getEventProducer(), copy.getEventProducer());
  }

  @Test
  void copyConstructor_whenBlocksProvided_setsBlocksAndAffectsEquality() {
    FetchContext base = createValidContext();
    BlockSet bs =
        new BlockSet() {
          @Override
          public network.crypta.keys.KeyBlock get(network.crypta.keys.Key key) {
            return null;
          }

          @Override
          public void add(network.crypta.keys.KeyBlock block) {
            // Intentional no-op: stub implementation for equality/serialization tests; not used.
          }

          @Override
          public Set<network.crypta.keys.Key> keys() {
            return Set.of();
          }

          @Override
          public network.crypta.keys.ClientKeyBlock get(network.crypta.keys.ClientKey key) {
            return null;
          }
        };
    FetchContext withBlocks = new FetchContext(base, FetchContext.IDENTICAL_MASK, false, bs);
    assertSame(bs, withBlocks.blocks);
    assertNotEquals(base, withBlocks); // blocks participates in equals()
  }

  @Test
  void copyConstructor_whenSplitfileDefaultBlockMask_appliesRestrictions() {
    FetchContext base = createValidContext();
    // Ensure base has different values so mask effects are observable
    base.setMaxRecursionLevel(5);
    base.setMaxArchiveRestarts(2);
    base.setDontEnterImplicitArchives(false);
    base.setAllowSplitfiles(true);
    base.setFollowRedirects(true);
    base.setMaxDataBlocksPerSegment(7);
    base.setMaxCheckBlocksPerSegment(8);
    base.setReturnZIPManifests(true);

    FetchContext masked = new FetchContext(base, FetchContext.SPLITFILE_DEFAULT_BLOCK_MASK);

    assertEquals(1, masked.getMaxRecursionLevel());
    assertEquals(0, masked.getMaxArchiveRestarts());
    assertTrue(masked.getDontEnterImplicitArchives());
    assertFalse(masked.getAllowSplitfiles());
    assertFalse(masked.getFollowRedirects());
    assertEquals(0, masked.getMaxDataBlocksPerSegment());
    assertEquals(0, masked.getMaxCheckBlocksPerSegment());
    assertFalse(masked.getReturnZIPManifests());
  }

  @Test
  void copyConstructor_whenSetReturnArchivesMask_setsReturnZIPManifestsTrue() {
    FetchContext base = createValidContext();
    base.setReturnZIPManifests(false);
    FetchContext masked = new FetchContext(base, FetchContext.SET_RETURN_ARCHIVES);
    assertTrue(masked.getReturnZIPManifests());
  }

  @Test
  void copyConstructor_whenUnknownMask_expectIllegalArgumentException() {
    FetchContext base = createValidContext();
    assertThrows(IllegalArgumentException.class, () -> new FetchContext(base, 999));
  }

  @Test
  void cooldownRetries_whenSetWithinBounds_updatesValue() {
    FetchContext ctx = createValidContext();
    int newVal = Math.max(0, RequestScheduler.COOLDOWN_RETRIES - 1);
    ctx.setCooldownRetries(newVal);
    assertEquals(newVal, ctx.getCooldownRetries());
  }

  @Test
  void cooldownRetries_whenNegativeOrTooLarge_expectIllegalArgumentException() {
    FetchContext ctx = createValidContext();
    assertThrows(IllegalArgumentException.class, () -> ctx.setCooldownRetries(-1));
    assertThrows(
        IllegalArgumentException.class,
        () -> ctx.setCooldownRetries(RequestScheduler.COOLDOWN_RETRIES + 1));
  }

  @Test
  void cooldownTime_whenNegativeOrTooSmall_expectIllegalArgumentException() {
    FetchContext ctx = createValidContext();
    assertThrows(IllegalArgumentException.class, () -> ctx.setCooldownTime(-1));
    long tooSmall = Math.max(0, RequestScheduler.COOLDOWN_PERIOD - 1);
    assertThrows(IllegalArgumentException.class, () -> ctx.setCooldownTime(tooSmall));
  }

  @Test
  void cooldownTime_whenForcedAllowsSmallerThanDefault_setsValue() {
    FetchContext ctx = createValidContext();
    long smaller = Math.max(0, RequestScheduler.COOLDOWN_PERIOD - 1);
    ctx.setCooldownTime(smaller, true);
    assertEquals(smaller, ctx.getCooldownTime());
  }

  @Test
  void writeTo_whenBlocksPresent_expectUnsupportedOperationException() throws IOException {
    FetchContext base = createValidContext();
    BlockSet bs =
        new BlockSet() {
          @Override
          public network.crypta.keys.KeyBlock get(network.crypta.keys.Key key) {
            return null;
          }

          @Override
          public void add(network.crypta.keys.KeyBlock block) {
            // Intentional no-op: stub implementation for writeTo() error-path test; not used.
          }

          @Override
          public Set<network.crypta.keys.Key> keys() {
            return Set.of();
          }

          @Override
          public network.crypta.keys.ClientKeyBlock get(network.crypta.keys.ClientKey key) {
            return null;
          }
        };
    FetchContext withBlocks = new FetchContext(base, FetchContext.IDENTICAL_MASK, false, bs);

    try (var baos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(baos)) {
      assertThrows(UnsupportedOperationException.class, () -> withBlocks.writeTo(dos));
    }
  }

  @Test
  void writeTo_whenPrefetchHookPresent_expectUnsupportedOperationException() throws IOException {
    FetchContext ctx = createValidContext();
    ctx.setPrefetchHook(
        new FoundURICallback() {
          @Override
          public void foundURI(network.crypta.keys.FreenetURI uri) {
            // Intentional no-op: this callback is only present to trigger
            // UnsupportedOperationException in writeTo().
          }

          @Override
          public void foundURI(network.crypta.keys.FreenetURI uri, boolean inline) {
            // Intentional no-op: this callback is only present to trigger
            // UnsupportedOperationException in writeTo().
          }

          @Override
          public void onText(String text, String type, java.net.URI baseURI) {
            // Intentional no-op: this callback is only present to trigger
            // UnsupportedOperationException in writeTo().
          }

          @Override
          public void onFinishedPage() {
            // Intentional no-op: this callback is only present to trigger
            // UnsupportedOperationException in writeTo().
          }
        });
    try (var baos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(baos)) {
      assertThrows(UnsupportedOperationException.class, () -> ctx.writeTo(dos));
    }
  }

  @Test
  void writeTo_whenTagReplacerPresent_expectUnsupportedOperationException() throws IOException {
    FetchContext ctx = createValidContext();
    ctx.setTagReplacer((pt, uriProcessor) -> null);
    try (var baos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(baos)) {
      assertThrows(UnsupportedOperationException.class, () -> ctx.writeTo(dos));
    }
  }

  @Test
  void writeToAndReadBack_whenNonNullFields_setRoundTripEqual() throws Exception {
    FetchContext ctx = createValidContext();
    // enrich fields to test serialization of sets and toggles
    ctx.setAllowedMIMETypes(new HashSet<>(Set.of("text/html", "application/json")));
    ctx.setCanWriteClientCache(true);
    ctx.setOverrideMIME("text/html");
    ctx.setIgnoreUSKDatehints(true);
    ctx.setCharset("UTF-8");

    byte[] bytes;
    try (var baos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(baos)) {
      ctx.writeTo(dos);
      dos.flush();
      bytes = baos.toByteArray();
    }

    FetchContext read;
    try (var dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      read = new FetchContext(dis);
    }
    assertEquals(ctx, read);
    assertEquals(ctx.hashCode(), read.hashCode());
    assertEquals(VALID_SCHEME, read.getSchemeHostAndPort());
  }

  @Test
  void readFrom_whenStreamOmitsSchemeHostAndPort_setsNull() throws Exception {
    // Manually serialize the "old" format without the final schemeHostAndPort UTF string.
    FetchContext ctx = createValidContext();
    ctx.setAllowedMIMETypes(new HashSet<>(Set.of("text/plain")));
    ctx.setCharset(null);
    ctx.setCanWriteClientCache(false);
    ctx.setOverrideMIME(null);
    ctx.setIgnoreUSKDatehints(false);

    byte[] bytes;
    try (var baos = new ByteArrayOutputStream();
        var dos = new DataOutputStream(baos)) {
      dos.writeLong(0x5ae53b0ce18dd821L); // magic
      dos.writeInt(1); // version
      dos.writeLong(ctx.getMaxOutputLength());
      dos.writeLong(ctx.getMaxTempLength());
      dos.writeInt(ctx.getMaxRecursionLevel());
      dos.writeInt(ctx.getMaxArchiveRestarts());
      dos.writeInt(ctx.getMaxArchiveLevels());
      dos.writeBoolean(ctx.getDontEnterImplicitArchives());
      dos.writeInt(ctx.getMaxSplitfileBlockRetries());
      dos.writeInt(ctx.getMaxNonSplitfileRetries());
      dos.writeInt(ctx.maxUSKRetries);
      dos.writeBoolean(ctx.getAllowSplitfiles());
      dos.writeBoolean(ctx.getFollowRedirects());
      dos.writeBoolean(ctx.getLocalRequestOnly());
      dos.writeBoolean(ctx.getIgnoreStore());
      dos.writeInt(ctx.getMaxMetadataSize());
      dos.writeInt(ctx.getMaxDataBlocksPerSegment());
      dos.writeInt(ctx.getMaxCheckBlocksPerSegment());
      dos.writeBoolean(ctx.getReturnZIPManifests());
      dos.writeBoolean(ctx.getFilterData());
      dos.writeBoolean(ctx.ignoreTooManyPathComponents);
      // allowedMIMETypes (non-null and non-empty)
      dos.writeInt(1);
      for (String s : ctx.getAllowedMIMETypes()) {
        dos.writeUTF(s);
      }
      // charset empty -> null
      dos.writeUTF("");
      dos.writeBoolean(ctx.getCanWriteClientCache());
      // override MIME empty -> null
      dos.writeUTF("");
      dos.writeInt(ctx.getCooldownRetries());
      dos.writeLong(ctx.getCooldownTime());
      dos.writeBoolean(ctx.getIgnoreUSKDatehints());
      // Intentionally stop here to simulate EOF before schemeHostAndPort
      dos.flush();
      bytes = baos.toByteArray();
    }

    // Verify that reading handles EOF for the trailing field and sets it to null.
    FetchContext read;
    try (var dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      read = new FetchContext(dis);
    }
    assertNull(read.getSchemeHostAndPort());
  }

  @Test
  void equalsAndHashCode_whenDifferInField_notEqual() {
    FetchContext a = createValidContext();
    FetchContext b = createValidContext();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());

    b.setFollowRedirects(!a.getFollowRedirects());
    assertNotEquals(a, b);
  }

  private FetchContext createValidContext() {
    return new FetchContext(
        VALID_MAX_OUTPUT,
        VALID_MAX_TEMP,
        VALID_MAX_METADATA,
        VALID_MAX_RECURSION,
        VALID_MAX_ARCHIVE_RESTARTS,
        VALID_MAX_ARCHIVE_LEVELS,
        VALID_DONT_ENTER_IMPLICIT,
        VALID_SPLIT_BLOCK_RETRIES,
        VALID_NON_SPLIT_RETRIES,
        VALID_USK_RETRIES,
        VALID_ALLOW_SPLIT,
        VALID_FOLLOW_REDIRECTS,
        VALID_LOCAL_ONLY,
        VALID_FILTER_DATA,
        VALID_MAX_DATABLOCKS,
        VALID_MAX_CHECKBLOCKS,
        producerMock,
        VALID_IGNORE_TOO_MANY,
        VALID_CAN_WRITE_CLIENT_CACHE,
        VALID_CHARSET,
        VALID_OVERRIDE_MIME,
        VALID_SCHEME);
  }
}
