package network.crypta.node.simulator;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LongTermManySingleBlocksTestTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private InsertBlock block1;
  @Mock private InsertBlock block2;

  @Test
  void waitUntilFinished_whenNoInserts_returnsImmediately() {
    // Arrange
    LongTermManySingleBlocksTest.InsertBatch batch =
        new LongTermManySingleBlocksTest.InsertBatch(client);

    // Act + Assert
    assertTimeoutPreemptively(Duration.ofMillis(200), batch::waitUntilFinished);
    verifyNoInteractions(client);
  }

  @Test
  void startInsert_whenInsertSucceeds_recordsUriAndTime_andNoError() throws Exception {
    // Arrange
    LongTermManySingleBlocksTest.InsertBatch batch =
        new LongTermManySingleBlocksTest.InsertBatch(client);
    FreenetURI expectedUri = FreenetURI.EMPTY_CHK_URI;
    when(client.insert(eq(block1), eq(false), isNull())).thenReturn(expectedUri);

    // Act
    batch.startInsert(block1);
    assertTimeoutPreemptively(Duration.ofSeconds(5), batch::waitUntilFinished);

    // Assert
    FreenetURI[] uris = batch.getURIs();
    long[] times = batch.getTimes();
    InsertException[] errors = batch.getErrors();

    assertArrayEquals(new FreenetURI[] {expectedUri}, uris);
    assertEquals(1, times.length);
    assertTrue(times[0] >= 0);
    assertEquals(1, errors.length);
    assertNull(errors[0]);
    verify(client, times(1)).insert(eq(block1), eq(false), isNull());
  }

  @Test
  void startInsert_whenInsertThrows_recordsError_andNullUriAndTime() throws Exception {
    // Arrange
    LongTermManySingleBlocksTest.InsertBatch batch =
        new LongTermManySingleBlocksTest.InsertBatch(client);
    InsertException failure = new InsertException(InsertExceptionMode.CANCELLED);
    when(client.insert(eq(block1), eq(false), isNull())).thenThrow(failure);

    // Act
    batch.startInsert(block1);
    assertTimeoutPreemptively(Duration.ofSeconds(5), batch::waitUntilFinished);

    // Assert
    FreenetURI[] uris = batch.getURIs();
    long[] times = batch.getTimes();
    InsertException[] errors = batch.getErrors();

    assertArrayEquals(new FreenetURI[] {null}, uris);
    assertArrayEquals(new long[] {0L}, times);
    assertEquals(1, errors.length);
    assertNotNull(errors[0]);
    assertEquals(failure, errors[0]);
    verify(client, times(1)).insert(eq(block1), eq(false), isNull());
  }

  @Test
  void startInsert_whenInsertReturnsNull_recordsNullUriAndTime_andNoErrorRecorded()
      throws Exception {
    // Arrange
    LongTermManySingleBlocksTest.InsertBatch batch =
        new LongTermManySingleBlocksTest.InsertBatch(client);
    when(client.insert(eq(block1), eq(false), isNull())).thenReturn(null);

    // Act
    batch.startInsert(block1);
    assertTimeoutPreemptively(Duration.ofSeconds(5), batch::waitUntilFinished);

    // Assert
    // Note: The production code allocates a fallback InsertException when insert() returns null,
    // but does not assign it to the BatchInsert's 'failed' field.
    FreenetURI[] uris = batch.getURIs();
    long[] times = batch.getTimes();
    InsertException[] errors = batch.getErrors();

    assertArrayEquals(new FreenetURI[] {null}, uris);
    assertArrayEquals(new long[] {0L}, times);
    assertEquals(1, errors.length);
    assertNull(errors[0]);
    verify(client, times(1)).insert(eq(block1), eq(false), isNull());
  }

  @Test
  void getURIsAndTimesAndErrors_whenMultipleInserts_returnsArraysInInsertOrder() throws Exception {
    // Arrange
    LongTermManySingleBlocksTest.InsertBatch batch =
        new LongTermManySingleBlocksTest.InsertBatch(client);
    FreenetURI uri1 = new FreenetURI("KSK", "doc1");
    FreenetURI uri2 = new FreenetURI("KSK", "doc2");
    when(client.insert(eq(block1), eq(false), isNull())).thenReturn(uri1);
    when(client.insert(eq(block2), eq(false), isNull())).thenReturn(uri2);

    // Act: serialize completion to avoid scheduling-dependent ordering.
    batch.startInsert(block1);
    assertTimeoutPreemptively(Duration.ofSeconds(5), batch::waitUntilFinished);
    batch.startInsert(block2);
    assertTimeoutPreemptively(Duration.ofSeconds(5), batch::waitUntilFinished);

    // Assert
    FreenetURI[] uris = batch.getURIs();
    long[] times = batch.getTimes();
    InsertException[] errors = batch.getErrors();

    assertArrayEquals(new FreenetURI[] {uri1, uri2}, uris);
    assertEquals(2, times.length);
    assertTrue(times[0] >= 0);
    assertTrue(times[1] >= 0);
    assertArrayEquals(new InsertException[] {null, null}, errors);
    verify(client, times(1)).insert(eq(block1), eq(false), isNull());
    verify(client, times(1)).insert(eq(block2), eq(false), isNull());
  }

  @Test
  void waitUntilFinished_whenInsertInProgress_blocksUntilCompletion() throws Exception {
    // Arrange
    LongTermManySingleBlocksTest.InsertBatch batch =
        new LongTermManySingleBlocksTest.InsertBatch(client);
    FreenetURI expectedUri = new FreenetURI("KSK", "doc");

    CountDownLatch insertEntered = new CountDownLatch(1);
    CountDownLatch allowReturn = new CountDownLatch(1);
    when(client.insert(eq(block1), eq(false), isNull()))
        .thenAnswer(
            invocation -> {
              insertEntered.countDown();
              boolean released = allowReturn.await(5, TimeUnit.SECONDS);
              assertTrue(released);
              return expectedUri;
            });

    // Act
    batch.startInsert(block1);
    assertTrue(insertEntered.await(5, TimeUnit.SECONDS));

    try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
      var waitFuture = executor.submit(batch::waitUntilFinished);

      // Assert: it should not finish while insert() is blocked.
      assertThrows(TimeoutException.class, () -> waitFuture.get(200, TimeUnit.MILLISECONDS));

      // Act: now allow insert to complete.
      allowReturn.countDown();
      waitFuture.get(5, TimeUnit.SECONDS);
    } finally {
      // Ensure we never leave the insert thread blocked if the assertions above fail.
      allowReturn.countDown();
    }

    // Assert
    assertArrayEquals(new FreenetURI[] {expectedUri}, batch.getURIs());
  }
}
