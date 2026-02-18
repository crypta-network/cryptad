package network.crypta.client.async;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class USKCompletionHandlerTest {

  @Test
  void decodeBlockIfNeeded_whenDecodeFalse_returnsNull() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    ClientContext context = mock(ClientContext.class);
    ClientRequester parent = mock(ClientRequester.class);

    //noinspection ConstantValue
    Bucket result = handler.decodeBlockIfNeeded(false, block, context, parent);

    //noinspection ConstantValue
    assertNull(result);
    verifyNoInteractions(block, context, parent);
  }

  @Test
  void decodeBlockIfNeeded_whenBlockNull_returnsNull() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientContext context = mock(ClientContext.class);
    ClientRequester parent = mock(ClientRequester.class);

    //noinspection ConstantValue
    Bucket result = handler.decodeBlockIfNeeded(true, null, context, parent);

    //noinspection ConstantValue
    assertNull(result);
    verifyNoInteractions(context, parent);
  }

  @Test
  @SuppressWarnings("resource")
  void decodeBlockIfNeeded_whenDecodeTrue_returnsBucket() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    ClientContext context = mock(ClientContext.class);
    ClientRequester parent = mock(ClientRequester.class);
    Bucket bucket = mock(Bucket.class);
    when(parent.persistent()).thenReturn(true);
    when(context.getBucketFactory(true)).thenReturn(bucketFactory);
    when(block.decode(bucketFactory, 1025, true)).thenReturn(bucket);

    Bucket result = handler.decodeBlockIfNeeded(true, block, context, parent);

    assertSame(bucket, result);
    verify(context).getBucketFactory(true);
    verify(block).decode(bucketFactory, 1025, true);
  }

  @Test
  void decodeBlockIfNeeded_whenDecodeThrowsKeyDecodeException_returnsNull() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    ClientContext context = mock(ClientContext.class);
    ClientRequester parent = mock(ClientRequester.class);
    when(parent.persistent()).thenReturn(false);
    when(context.getBucketFactory(false)).thenReturn(bucketFactory);
    when(block.decode(bucketFactory, 1025, true)).thenThrow(new KeyDecodeException("bad"));

    Bucket result = handler.decodeBlockIfNeeded(true, block, context, parent);

    assertNull(result);
  }

  @Test
  void decodeBlockIfNeeded_whenDecodeThrowsIOException_returnsNull() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    ClientContext context = mock(ClientContext.class);
    ClientRequester parent = mock(ClientRequester.class);
    when(parent.persistent()).thenReturn(true);
    when(context.getBucketFactory(true)).thenReturn(bucketFactory);
    when(block.decode(bucketFactory, 1025, true)).thenThrow(new IOException("io"));

    Bucket result = handler.decodeBlockIfNeeded(true, block, context, parent);

    assertNull(result);
  }

  @Test
  void applyDecodedData_whenDecodeFalse_doesNotChangeState() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    Bucket data = mock(Bucket.class);

    handler.applyDecodedData(false, block, data);

    assertEquals(0, handler.lastCompressionCodec());
    assertFalse(handler.lastWasMetadata());
    assertFalse(handler.hasLastRequestData());
    verifyNoInteractions(block, data);
  }

  @Test
  void applyDecodedData_whenKeepLastDataTrue_replacesPreviousBucket() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    Bucket first = mock(Bucket.class);
    Bucket second = mock(Bucket.class);
    when(block.getCompressionCodec()).thenReturn((short) 5);
    when(block.isMetadata()).thenReturn(true);

    handler.applyDecodedData(true, block, first);
    handler.applyDecodedData(true, block, second);

    assertTrue(handler.hasLastRequestData());
    assertEquals((short) 5, handler.lastCompressionCodec());
    assertTrue(handler.lastWasMetadata());
    verify(first).free();
    verify(second, never()).free();
  }

  @Test
  void applyDecodedData_whenKeepLastDataFalse_freesProvidedBucket() {
    USKCompletionHandler handler = new USKCompletionHandler(false);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    Bucket data = mock(Bucket.class);
    when(block.getCompressionCodec()).thenReturn((short) 2);
    when(block.isMetadata()).thenReturn(false);

    handler.applyDecodedData(true, block, data);

    verify(data).free();
    assertFalse(handler.hasLastRequestData());
    assertEquals((short) 2, handler.lastCompressionCodec());
    assertFalse(handler.lastWasMetadata());
  }

  @Test
  void applyDecodedData_whenBlockNull_resetsCodecAndMetadata() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientSSKBlock block = mock(ClientSSKBlock.class);
    Bucket data = mock(Bucket.class);
    when(block.getCompressionCodec()).thenReturn((short) 9);
    when(block.isMetadata()).thenReturn(true);

    handler.applyDecodedData(true, block, data);
    handler.applyDecodedData(true, null, null);

    assertEquals((short) -1, handler.lastCompressionCodec());
    assertFalse(handler.lastWasMetadata());
    assertFalse(handler.hasLastRequestData());
  }

  @Test
  void applyFoundDecodedData_whenDecodeFalse_doesNothing() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ClientContext context = mock(ClientContext.class);

    handler.applyFoundDecodedData(false, true, (short) 3, new byte[] {1}, context);

    assertEquals(0, handler.lastCompressionCodec());
    assertFalse(handler.lastWasMetadata());
    assertFalse(handler.hasLastRequestData());
  }

  @Test
  void applyFoundDecodedData_whenKeepLastDataTrue_storesBucketAndReleasesBytes() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.makeBucket(anyLong())).thenAnswer(_ -> new ArrayBucket());
    ClientContext context = mock(ClientContext.class);
    setField(context, "tempBucketFactory", tempBucketFactory);
    byte[] data = new byte[] {1, 2, 3};

    handler.applyFoundDecodedData(true, true, (short) 4, data, context);

    assertTrue(handler.hasLastRequestData());
    assertEquals((short) 4, handler.lastCompressionCodec());
    assertTrue(handler.lastWasMetadata());
    assertArrayEquals(data, handler.releaseLastDataBytes());
    assertFalse(handler.hasLastRequestData());
  }

  @Test
  void applyFoundDecodedData_whenBucketCreationFails_keepsNoDataButUpdatesFlags() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.makeBucket(anyLong())).thenThrow(new IOException("nope"));
    ClientContext context = mock(ClientContext.class);
    setField(context, "tempBucketFactory", tempBucketFactory);

    handler.applyFoundDecodedData(true, false, (short) 7, new byte[] {9}, context);

    assertEquals((short) 7, handler.lastCompressionCodec());
    assertFalse(handler.lastWasMetadata());
    assertFalse(handler.hasLastRequestData());
  }

  @Test
  void releaseLastDataBytes_whenNoData_returnsNull() {
    USKCompletionHandler handler = new USKCompletionHandler(true);

    assertNull(handler.releaseLastDataBytes());
  }

  @Test
  void releaseLastDataBytes_whenBucketReadFails_returnsNullAndFrees() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    Bucket bucket = mock(Bucket.class);
    when(bucket.size()).thenReturn(2L);
    when(bucket.getInputStreamUnbuffered()).thenThrow(new IOException("boom"));
    setField(handler, "lastRequestData", bucket);

    assertNull(handler.releaseLastDataBytes());

    verify(bucket).free();
    assertFalse(handler.hasLastRequestData());
  }

  @Test
  void clearLastRequestData_whenBucketExists_freesAndClears() {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    Bucket bucket = mock(Bucket.class);
    setField(handler, "lastRequestData", bucket);

    handler.clearLastRequestData();

    verify(bucket).free();
    assertFalse(handler.hasLastRequestData());
  }

  @Test
  void releaseLastDataBytes_whenBucketPresent_returnsBytesAndClears() throws Exception {
    USKCompletionHandler handler = new USKCompletionHandler(true);
    ArrayBucket bucket = new ArrayBucket();
    byte[] data = new byte[] {4, 5};
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(data);
    }
    setField(handler, "lastRequestData", bucket);

    assertArrayEquals(data, handler.releaseLastDataBytes());

    assertFalse(handler.hasLastRequestData());
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (NoSuchFieldException _) {
      try {
        Field field = target.getClass().getSuperclass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
      } catch (ReflectiveOperationException ex) {
        throw new LinkageError(ex.getMessage(), ex);
      }
    } catch (ReflectiveOperationException e) {
      throw new LinkageError(e.getMessage(), e);
    }
  }
}
