package network.crypta.clients.fcp;

import java.io.InvalidObjectException;
import network.crypta.client.InsertContext;
import network.crypta.client.events.ClientEventProducer;
import network.crypta.clients.fcp.bridge.CoreFcpServerDependenciesFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class LegacyInsertExecutionBridgeLoaderTest {

  @Test
  void load_whenBridgeAvailable_expectFactorySingleton() throws Exception {
    // Act
    FcpLegacyInsertExecutionBridge bridge = LegacyInsertExecutionBridgeLoader.load();

    // Assert
    assertSame(CoreFcpServerDependenciesFactory.legacyInsertExecutionBridge(), bridge);
  }

  @Test
  void load_whenWrappingLegacyInsertContext_expectDetachedHandleWithEquivalentValues()
      throws Exception {
    // Arrange
    InsertContext legacyInsertContext = mock(InsertContext.class);
    ClientEventProducer eventProducer = mock(ClientEventProducer.class);
    when(legacyInsertContext.getEventProducer()).thenReturn(eventProducer);
    when(legacyInsertContext.isGetCHKOnly()).thenReturn(true);
    when(legacyInsertContext.isDontCompress()).thenReturn(true);
    when(legacyInsertContext.getMaxInsertRetries()).thenReturn(8);
    when(legacyInsertContext.getConsecutiveRNFsCountAsSuccess()).thenReturn(4);
    when(legacyInsertContext.getSplitfileSegmentDataBlocks()).thenReturn(10);
    when(legacyInsertContext.getSplitfileSegmentCheckBlocks()).thenReturn(11);
    when(legacyInsertContext.isCanWriteClientCache()).thenReturn(true);
    when(legacyInsertContext.getCompressorDescriptor()).thenReturn("GZIP");
    when(legacyInsertContext.isForkOnCacheable()).thenReturn(true);
    when(legacyInsertContext.getExtraInsertsSingleBlock()).thenReturn(2);
    when(legacyInsertContext.getExtraInsertsSplitfileHeaderBlock()).thenReturn(3);
    when(legacyInsertContext.getCompatibilityMode())
        .thenReturn(InsertContext.CompatibilityMode.COMPAT_1468);
    when(legacyInsertContext.isLocalRequestOnly()).thenReturn(true);
    when(legacyInsertContext.isEarlyEncode()).thenReturn(true);
    when(legacyInsertContext.isIgnoreUSKDatehints()).thenReturn(true);

    // Act
    FcpInsertContextHandle handle =
        LegacyInsertExecutionBridgeLoader.load().wrapLegacyInsertContext(legacyInsertContext);

    // Assert
    assertSame(eventProducer, handle.eventProducer());
    assertTrue(handle.getCHKOnly());
    assertTrue(handle.isDontCompress());
    assertEquals(8, handle.getMaxInsertRetries());
    assertEquals(4, handle.getConsecutiveRnfsCountAsSuccess());
    assertEquals(10, handle.getSplitfileSegmentDataBlocks());
    assertEquals(11, handle.getSplitfileSegmentCheckBlocks());
    assertTrue(handle.canWriteClientCache());
    assertEquals("GZIP", handle.getCompressorDescriptor());
    assertTrue(handle.forkOnCacheable());
    assertEquals(2, handle.getExtraInsertsSingleBlock());
    assertEquals(3, handle.getExtraInsertsSplitfileHeaderBlock());
    assertSame(FcpCompatibilityMode.COMPAT_1468, handle.getCompatibilityMode());
    assertTrue(handle.localRequestOnly());
    assertTrue(handle.earlyEncode());
    assertTrue(handle.ignoreUSKDatehints());
  }

  @Test
  void load_whenWrappingUnsupportedLegacyObject_expectInvalidObjectException()
      throws InvalidObjectException {
    // Arrange
    FcpLegacyInsertExecutionBridge bridge = LegacyInsertExecutionBridgeLoader.load();

    // Act & Assert
    assertThrows(InvalidObjectException.class, () -> bridge.wrapLegacyInsertContext(new Object()));
  }
}
