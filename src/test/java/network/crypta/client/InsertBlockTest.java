package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class InsertBlockTest {

  @Mock private RandomAccessBucket bucket;

  @Test
  @DisplayName("constructor_whenDataNull_expectNullPointerException")
  void constructor_whenDataNull_expectNullPointerException() {
    assertThrows(
        NullPointerException.class, () -> new InsertBlock(null, null, FreenetURI.EMPTY_CHK_URI));
  }

  @Test
  @DisplayName("constructor_whenMetadataNull_expectDefaultClientMetadata")
  void constructor_whenMetadataNull_expectDefaultClientMetadata() {
    InsertBlock block = new InsertBlock(bucket, null, FreenetURI.EMPTY_CHK_URI);
    assertNotNull(block.clientMetadata, "Default metadata should be created when null is passed");
    // Newly constructed ClientMetadata has no explicit MIME and is therefore trivial.
    // This verifies that we didn't just keep a null reference.
    assertNotNull(block.clientMetadata.getMIMEType(), "Effective MIME should never be null");
  }

  @Test
  @DisplayName("constructor_whenProvidedArgs_expectFieldsAssigned")
  void constructor_whenProvidedArgs_expectFieldsAssigned() {
    ClientMetadata meta = new ClientMetadata("text/plain");
    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;

    InsertBlock block = new InsertBlock(bucket, meta, uri);

    // getData() should return the same instance before free()
    assertSame(bucket, block.getData(), "getData should return the original bucket before free()");
    // Metadata and URI references should be preserved
    assertSame(meta, block.clientMetadata, "clientMetadata should be the same instance passed in");
    assertSame(uri, block.desiredURI, "desiredURI should be the same instance passed in");
  }

  @Test
  @DisplayName("getData_afterFree_returnsNull")
  void getData_afterFree_returnsNull() {
    InsertBlock block = new InsertBlock(bucket, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);

    block.free();

    assertNull(block.getData(), "getData should return null after free()");
  }

  @Test
  @DisplayName("free_whenDataPresent_callsBucketFreeOnce_evenIfCalledTwice")
  void free_whenDataPresent_callsBucketFreeOnce_evenIfCalledTwice() {
    InsertBlock block = new InsertBlock(bucket, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);

    // Act: free twice
    block.free();
    block.free();

    // Assert: bucket.free() invoked exactly once (idempotent free)
    verify(bucket, times(1)).free();
  }

  @Test
  @DisplayName("free_whenDataNull_doesNotCallBucketFree")
  void free_whenDataNull_doesNotCallBucketFree() {
    InsertBlock block = new InsertBlock(bucket, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
    // Make data somebody else's problem
    block.nullData();

    block.free();

    // Since data was nulled, InsertBlock must not call free() on the bucket
    verifyNoInteractions(bucket);
  }

  @Test
  @DisplayName("nullURI_setsDesiredURINull")
  void nullURI_setsDesiredURINull() {
    InsertBlock block = new InsertBlock(bucket, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
    block.nullURI();
    assertNull(block.desiredURI, "desiredURI should be null after nullURI()");
  }

  @Test
  @DisplayName("nullMetadata_setsClientMetadataNull")
  void nullMetadata_setsClientMetadataNull() {
    InsertBlock block =
        new InsertBlock(bucket, new ClientMetadata("text/plain"), FreenetURI.EMPTY_CHK_URI);
    block.nullMetadata();
    assertNull(block.clientMetadata, "clientMetadata should be null after nullMetadata()");
  }
}
