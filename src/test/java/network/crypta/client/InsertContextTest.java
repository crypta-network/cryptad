package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.client.events.SimpleEventProducer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class InsertContextTest {

  @Mock private ClientEventProducer mockProducer;

  private static InsertContext newContextWithDefaults(CompatibilityMode mode) {
    return new InsertContext(
        3, // maxRetries
        2, // rnfsToSuccess
        128, // splitfileSegmentDataBlocks
        96, // splitfileSegmentCheckBlocks
        new SimpleEventProducer(), // eventProducer
        true, // canWriteClientCache
        true, // forkOnCacheable
        false, // localRequestOnly
        "GZIP", // compressorDescriptor
        1, // extraInsertsSingleBlock
        2, // extraInsertsSplitfileHeaderBlock
        mode // compatibilityMode
        );
  }

  @Test
  void constructor_whenGivenValues_setsAllExpectedFields() {
    // Arrange
    int maxRetries = 7;
    int rnfsToSuccess = 4;
    int dataBlocks = 120;
    int checkBlocks = 80;
    boolean canWriteClientCache = true;
    boolean forkOnCacheable = false;
    boolean localRequestOnly = true;
    String descriptor = "LZMA,GZIP";
    int extraSingle = 3;
    int extraHeader = 5;
    CompatibilityMode mode = CompatibilityMode.COMPAT_1255;

    // Act
    InsertContext ctx =
        new InsertContext(
            maxRetries,
            rnfsToSuccess,
            dataBlocks,
            checkBlocks,
            mockProducer,
            canWriteClientCache,
            forkOnCacheable,
            localRequestOnly,
            descriptor,
            extraSingle,
            extraHeader,
            mode);

    // Assert
    assertFalse(ctx.dontCompress);
    assertEquals(maxRetries, ctx.maxInsertRetries);
    assertEquals(rnfsToSuccess, ctx.consecutiveRNFsCountAsSuccess);
    assertEquals(dataBlocks, ctx.splitfileSegmentDataBlocks);
    assertEquals(checkBlocks, ctx.splitfileSegmentCheckBlocks);
    assertEquals(canWriteClientCache, ctx.canWriteClientCache);
    assertEquals(forkOnCacheable, ctx.forkOnCacheable);
    assertEquals(localRequestOnly, ctx.localRequestOnly);
    assertEquals(descriptor, ctx.compressorDescriptor);
    assertEquals(extraSingle, ctx.extraInsertsSingleBlock);
    assertEquals(extraHeader, ctx.extraInsertsSplitfileHeaderBlock);

    assertEquals(SplitfileAlgorithm.ONION_STANDARD, ctx.getSplitfileAlgorithm());
    assertFalse(ctx.ignoreUSKDatehints);
    assertNotNull(ctx.eventProducer);

    assertEquals(mode, ctx.getCompatibilityMode());
    assertEquals(mode.ordinal(), ctx.getCompatibilityCode());
  }

  @Test
  void setCompatibilityMode_whenCurrent_internsToLatest() {
    // Arrange
    InsertContext ctx = newContextWithDefaults(CompatibilityMode.COMPAT_1250);
    CompatibilityMode latest = CompatibilityMode.latest();

    // Act
    ctx.setCompatibilityMode(CompatibilityMode.COMPAT_CURRENT);

    // Assert
    assertEquals(latest, ctx.getCompatibilityMode());
    assertEquals(latest.ordinal(), ctx.getCompatibilityCode());
  }

  @Test
  void copyConstructor_whenCopied_preservesEqualityAndHashCode() {
    // Arrange
    InsertContext original = newContextWithDefaults(CompatibilityMode.COMPAT_1255);

    // Act
    InsertContext copy = new InsertContext(original);

    // Assert
    assertEquals(original, copy);
    assertEquals(original.hashCode(), copy.hashCode());
  }

  @Test
  void copyOf_whenCalled_returnsEqualButDistinctInstance() {
    // Arrange
    InsertContext original = newContextWithDefaults(CompatibilityMode.COMPAT_1468);

    // Act
    InsertContext copy = InsertContext.copyOf(original);

    // Assert
    assertEquals(original, copy);
    // eventProducer is intentionally the same reference in the copy constructor, verify identity
    assertSame(original.eventProducer, copy.eventProducer);
  }

  @Test
  void copyWithProducer_whenDifferentProducer_equalsIgnoresProducer() {
    // Arrange
    InsertContext base = newContextWithDefaults(CompatibilityMode.COMPAT_1251);
    // The specialized constructor does not copy canWriteClientCache; keep semantics equal.
    base.canWriteClientCache = false;
    SimpleEventProducer otherProducer = new SimpleEventProducer();

    // Act
    InsertContext withOtherProducer = new InsertContext(base, otherProducer);

    // Assert
    // equals() ignores eventProducer
    assertEquals(base, withOtherProducer);
    // but producers actually differ
    assertNotEquals(base.eventProducer, withOtherProducer.eventProducer);
  }

  @Test
  void equals_and_hashCode_canDifferWhenOnlyCompatModeRealFieldChanges() {
    // Arrange
    InsertContext a = newContextWithDefaults(CompatibilityMode.COMPAT_1255);
    InsertContext b = new InsertContext(a);

    // Sanity: equal and same hash initially
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());

    // Act: change only the real compatibility field on one instance
    b.setCompatibilityMode(CompatibilityMode.COMPAT_1468);

    // Assert: equals still true (compatibilityMode migration field not compared),
    // but hashCode differs (computed from realCompatMode ordinal).
    assertEquals(a, b);
    assertNotEquals(a.hashCode(), b.hashCode());
  }

  // ----- CompatibilityMode enum tests -----

  static Stream<CompatibilityMode> allModes() {
    return Arrays.stream(CompatibilityMode.class.getEnumConstants());
  }

  @ParameterizedTest
  @MethodSource("allModes")
  void byCode_whenKnownCode_returnsSameMode(CompatibilityMode m) {
    assertEquals(m, CompatibilityMode.byCode(m.code));
    assertTrue(CompatibilityMode.hasCode(m.code));
    assertFalse(CompatibilityMode.maybeFutureCode(m.code));
  }

  @Test
  void byCode_whenUnknown_throwsIllegalArgumentException() {
    short unknown = (short) (CompatibilityMode.latest().code + 10);
    assertThrows(IllegalArgumentException.class, () -> CompatibilityMode.byCode(unknown));
    assertTrue(CompatibilityMode.maybeFutureCode(unknown));
    assertFalse(CompatibilityMode.hasCode(unknown));
  }

  @Test
  void intern_whenCurrent_returnsLatest_otherwiseReturnsSelf() {
    CompatibilityMode latest = CompatibilityMode.latest();
    assertEquals(latest, CompatibilityMode.COMPAT_CURRENT.intern());
    assertSame(CompatibilityMode.COMPAT_1250_EXACT, CompatibilityMode.COMPAT_1250_EXACT.intern());
  }

  @Test
  void latest_returnsLastDeclaredEnumConstant() {
    CompatibilityMode[] values = CompatibilityMode.class.getEnumConstants();
    assertSame(values[values.length - 1], CompatibilityMode.latest());
  }
}
