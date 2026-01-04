package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ArchiveHandlerImplTest {

  private FreenetURI key;
  private ARCHIVE_TYPE archiveType;
  private COMPRESSOR_TYPE compressorType;

  private static final String FILE_TXT = "file.txt";
  private static final String MISSING_BIN = "missing.bin";
  private static final String AFTER_TXT = "after.txt";
  private static final String BOOM = "boom";

  @Mock private ArchiveManager manager;
  @Mock private ArchiveContext archiveContext;
  @Mock private ArchiveExtractCallback callback;
  @Mock private ClientContext clientContext;
  @Mock private ArchiveStoreContext storeContext;
  @Mock private Bucket bucket;

  @BeforeEach
  void setUp() {
    key = new FreenetURI("CHK", null);
    archiveType = ARCHIVE_TYPE.TAR;
    compressorType = COMPRESSOR_TYPE.GZIP;
  }

  @Test
  @DisplayName("get: when forceRefetch=true, returns null and skips manager")
  void get_whenForceRefetchTrue_returnsNullAndSkipsManager() throws Exception {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, true);

    Bucket result = handler.get(FILE_TXT, archiveContext, manager);

    assertNull(result);
    verifyNoInteractions(manager);
  }

  @Test
  @DisplayName("get: when cached present, returns bucket and calls manager.getCached")
  void get_whenCachedPresent_returnsBucket() throws Exception {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, false);
    Bucket expected = bucket;
    when(manager.getCached(key, FILE_TXT)).thenReturn(expected);

    Bucket result = handler.get(FILE_TXT, archiveContext, manager);

    assertSame(expected, result);
    verify(manager).getCached(key, FILE_TXT);
  }

  @Test
  @DisplayName("get: when cached missing, returns null and calls manager.getCached")
  void get_whenCachedMissing_returnsNull() throws Exception {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, false);
    when(manager.getCached(key, MISSING_BIN)).thenReturn(null);

    Bucket result = handler.get(MISSING_BIN, archiveContext, manager);

    assertNull(result);
    verify(manager).getCached(key, MISSING_BIN);
  }

  @Test
  @DisplayName("get: propagates ArchiveFailureException from manager.getCached")
  void get_whenManagerThrows_propagatesException() throws Exception {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, false);
    when(manager.getCached(key, BOOM)).thenThrow(new ArchiveFailureException("fail"));

    assertThrows(ArchiveFailureException.class, () -> handler.get(BOOM, archiveContext, manager));
    verify(manager).getCached(key, BOOM);
  }

  @Test
  @DisplayName("getMetadata: delegates to get with .metadata")
  void getMetadata_whenCalled_usesDotMetadataName() throws Exception {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, false);
    when(manager.getCached(key, ".metadata")).thenReturn(bucket);

    Bucket result = handler.getMetadata(archiveContext, manager);

    assertSame(bucket, result);
    verify(manager).getCached(key, ".metadata");
  }

  @Test
  @DisplayName("extractToCache: resets forceRefetch and delegates to manager with context")
  void extractToCache_whenCalled_resetsFlagAndDelegates() throws Exception {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, true);
    when(manager.makeContext(key, archiveType, compressorType, false)).thenReturn(storeContext);

    handler.extractToCache(bucket, archiveContext, "element.txt", callback, manager, clientContext);

    verify(manager).makeContext(key, archiveType, compressorType, false);
    ArgumentCaptor<ArchiveExtractionInput> inputCaptor =
        ArgumentCaptor.forClass(ArchiveExtractionInput.class);
    ArgumentCaptor<ArchiveElementRequest> elementCaptor =
        ArgumentCaptor.forClass(ArchiveElementRequest.class);
    verify(manager).extractToCache(inputCaptor.capture(), elementCaptor.capture());
    ArchiveExtractionInput input = inputCaptor.getValue();
    ArchiveElementRequest elementRequest = elementCaptor.getValue();
    assertEquals(key, input.key);
    assertEquals(archiveType, input.archiveType);
    assertEquals(compressorType, input.compressorType);
    assertSame(bucket, input.data);
    assertSame(archiveContext, input.archiveContext);
    assertSame(storeContext, input.storeContext);
    assertEquals("element.txt", elementRequest.element);
    assertSame(callback, elementRequest.callback);
    assertSame(clientContext, elementRequest.clientContext);

    // Now forceRefetch should be cleared; a subsequent get should consult the manager
    when(manager.getCached(key, AFTER_TXT)).thenReturn(null);
    Bucket after = handler.get(AFTER_TXT, archiveContext, manager);
    assertNull(after);
    verify(manager).getCached(key, AFTER_TXT);
  }

  @Test
  @DisplayName("accessors: return constructor values")
  void accessors_whenQueried_returnValues() {
    ArchiveHandlerImpl handler = new ArchiveHandlerImpl(key, archiveType, compressorType, false);

    assertEquals(archiveType, handler.getArchiveType());
    assertEquals(compressorType, handler.getCompressorType());
    assertEquals(key, handler.getKey());
  }

  @Test
  @DisplayName("cloneHandler: preserves fields and has independent forceRefetch state")
  void cloneHandler_whenCloned_preservesFieldsAndIndependence() throws Exception {
    ArchiveHandlerImpl original = new ArchiveHandlerImpl(key, archiveType, compressorType, true);
    ArchiveHandler cloned = original.cloneHandler();

    // Cloned handler has same public fields
    assertEquals(key, cloned.getKey());
    assertEquals(archiveType, cloned.getArchiveType());
    // Downcast only to test compressor type (public method)
    assertEquals(compressorType, ((ArchiveHandlerImpl) cloned).getCompressorType());

    // Original: clear forceRefetch via extractToCache
    when(manager.makeContext(key, archiveType, compressorType, false)).thenReturn(storeContext);
    original.extractToCache(bucket, archiveContext, "el", callback, manager, clientContext);

    // Cloned: still has forceRefetch=true captured at clone time; should not consult manager
    Bucket res = cloned.get("anything", archiveContext, manager);
    assertNull(res);
    verify(manager, never()).getCached(any(FreenetURI.class), any(String.class));
  }
}
