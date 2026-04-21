package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.SimpleEventProducer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
class DefaultFcpInsertContextHandleTest {

  @Test
  void constructor_whenOptionsAndLimitsProvided_expectInitialStateFromParameters() {
    // Arrange
    SimpleEventProducer eventProducer = new SimpleEventProducer();
    FcpInsertContextLimits limits = new FcpInsertContextLimits(4, 10, 11);
    FcpInsertOptions options =
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(true, true, true, 9, null, true, false, true),
            new FcpInsertTuningOptions(
                true, true, "GZIP", 2, 3, FcpCompatibilityMode.COMPAT_CURRENT),
            null);

    // Act
    DefaultFcpInsertContextHandle handle =
        new DefaultFcpInsertContextHandle(eventProducer, limits, options);

    // Assert
    assertSame(eventProducer, handle.eventProducer());
    assertTrue(handle.getCHKOnly());
    assertTrue(handle.isDontCompress());
    assertEquals(9, handle.getMaxInsertRetries());
    assertEquals(4, limits.consecutiveRnfsCountAsSuccess());
    assertEquals(4, handle.getConsecutiveRnfsCountAsSuccess());
    assertEquals(10, limits.splitfileSegmentDataBlocks());
    assertEquals(10, handle.getSplitfileSegmentDataBlocks());
    assertEquals(11, limits.splitfileSegmentCheckBlocks());
    assertEquals(11, handle.getSplitfileSegmentCheckBlocks());
    assertTrue(handle.canWriteClientCache());
    assertEquals("GZIP", handle.getCompressorDescriptor());
    assertTrue(handle.forkOnCacheable());
    assertEquals(2, handle.getExtraInsertsSingleBlock());
    assertEquals(3, handle.getExtraInsertsSplitfileHeaderBlock());
    assertSame(FcpCompatibilityMode.latest(), handle.getCompatibilityMode());
    assertTrue(handle.localRequestOnly());
    assertTrue(handle.earlyEncode());
    assertTrue(handle.ignoreUSKDatehints());
  }

  @Test
  void constructor_whenEventProducerOmitted_expectFreshSimpleEventProducer() {
    // Arrange
    FcpInsertContextLimits limits = new FcpInsertContextLimits(0, 1, 2);
    FcpInsertOptions options =
        new FcpInsertOptions(
            new FcpInsertBehaviorOptions(false, false, false, 1, null, false, false, false),
            new FcpInsertTuningOptions(false, false, null, 0, 0, FcpCompatibilityMode.COMPAT_1255),
            null);

    // Act
    DefaultFcpInsertContextHandle handle = new DefaultFcpInsertContextHandle(limits, options);

    // Assert
    assertNotNull(handle.eventProducer());
    assertInstanceOf(SimpleEventProducer.class, handle.eventProducer());
    assertSame(FcpCompatibilityMode.COMPAT_1255, handle.getCompatibilityMode());
  }

  @Test
  void mutators_whenValuesChange_expectUpdatedStateAndInternedCompatibility() {
    // Arrange
    DefaultFcpInsertContextHandle handle =
        newHandle(
            new FcpInsertContextLimits(1, 2, 3),
            new FcpInsertOptions(
                new FcpInsertBehaviorOptions(false, false, false, 0, null, false, false, false),
                new FcpInsertTuningOptions(
                    false, false, null, 0, 0, FcpCompatibilityMode.COMPAT_1251),
                null));

    // Act
    handle.setGetCHKOnly(true);
    handle.setDontCompress(true);
    handle.setMaxInsertRetries(12);
    handle.setConsecutiveRnfsCountAsSuccess(0);
    handle.setCanWriteClientCache(true);
    handle.setCompressorDescriptor("BZ2");
    handle.setForkOnCacheable(true);
    handle.setExtraInsertsSingleBlock(5);
    handle.setExtraInsertsSplitfileHeaderBlock(6);
    handle.setCompatibilityMode(FcpCompatibilityMode.COMPAT_CURRENT);
    handle.setLocalRequestOnly(true);
    handle.setEarlyEncode(true);
    handle.setIgnoreUSKDatehints(true);

    // Assert
    assertTrue(handle.getCHKOnly());
    assertTrue(handle.isDontCompress());
    assertEquals(12, handle.getMaxInsertRetries());
    assertEquals(0, handle.getConsecutiveRnfsCountAsSuccess());
    assertTrue(handle.canWriteClientCache());
    assertEquals("BZ2", handle.getCompressorDescriptor());
    assertTrue(handle.forkOnCacheable());
    assertEquals(5, handle.getExtraInsertsSingleBlock());
    assertEquals(6, handle.getExtraInsertsSplitfileHeaderBlock());
    assertSame(FcpCompatibilityMode.latest(), handle.getCompatibilityMode());
    assertTrue(handle.localRequestOnly());
    assertTrue(handle.earlyEncode());
    assertTrue(handle.ignoreUSKDatehints());
  }

  @Test
  void eventListener_whenAddedAndRemoved_expectProducerTracksListener() {
    // Arrange
    DefaultFcpInsertContextHandle handle =
        newHandle(
            new FcpInsertContextLimits(1, 2, 3),
            new FcpInsertOptions(
                new FcpInsertBehaviorOptions(false, false, false, 0, null, false, false, false),
                new FcpInsertTuningOptions(
                    false, false, null, 0, 0, FcpCompatibilityMode.COMPAT_1251),
                null));
    ClientEventListener listener = mock(ClientEventListener.class);

    // Act
    handle.addEventListener(listener);
    boolean removed = handle.removeEventListener(listener);
    boolean removedAgain = handle.removeEventListener(listener);

    // Assert
    assertTrue(removed);
    assertFalse(removedAgain);
  }

  @Test
  void serialization_whenRoundTripped_expectStatePreserved() throws Exception {
    // Arrange
    DefaultFcpInsertContextHandle handle =
        newHandle(
            new FcpInsertContextLimits(4, 10, 11),
            new FcpInsertOptions(
                new FcpInsertBehaviorOptions(true, true, true, 9, null, true, false, true),
                new FcpInsertTuningOptions(
                    true, true, "GZIP", 2, 3, FcpCompatibilityMode.COMPAT_1468),
                null));

    // Act
    DefaultFcpInsertContextHandle restored = roundTrip(handle);

    // Assert
    assertTrue(restored.getCHKOnly());
    assertTrue(restored.isDontCompress());
    assertEquals(9, restored.getMaxInsertRetries());
    assertEquals(4, restored.getConsecutiveRnfsCountAsSuccess());
    assertEquals(10, restored.getSplitfileSegmentDataBlocks());
    assertEquals(11, restored.getSplitfileSegmentCheckBlocks());
    assertTrue(restored.canWriteClientCache());
    assertEquals("GZIP", restored.getCompressorDescriptor());
    assertTrue(restored.forkOnCacheable());
    assertEquals(2, restored.getExtraInsertsSingleBlock());
    assertEquals(3, restored.getExtraInsertsSplitfileHeaderBlock());
    assertSame(FcpCompatibilityMode.COMPAT_1468, restored.getCompatibilityMode());
    assertTrue(restored.localRequestOnly());
    assertTrue(restored.earlyEncode());
    assertTrue(restored.ignoreUSKDatehints());
    assertInstanceOf(SimpleEventProducer.class, restored.eventProducer());
  }

  private static DefaultFcpInsertContextHandle roundTrip(DefaultFcpInsertContextHandle value)
      throws Exception {
    byte[] serialized;
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
      objectOutput.writeObject(value);
      objectOutput.flush();
      serialized = output.toByteArray();
    }
    try (ObjectInputStream objectInput =
        new ObjectInputStream(new ByteArrayInputStream(serialized))) {
      return (DefaultFcpInsertContextHandle) objectInput.readObject();
    }
  }

  private static DefaultFcpInsertContextHandle newHandle(
      FcpInsertContextLimits limits, FcpInsertOptions options) {
    return new DefaultFcpInsertContextHandle(new SimpleEventProducer(), limits, options);
  }
}
