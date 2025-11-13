package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming convention: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class ErrorArchiveStoreItemTest {

  private FreenetURI key;
  private String filename;

  @Mock private ArchiveStoreContext context;

  @BeforeEach
  void setup() {
    // Simple KSK variant avoids needing routing/crypto keys
    key = new FreenetURI("KSK", "doc");
    filename = "file.txt";
  }

  @Test
  @DisplayName("getDataOrThrow: always throws ArchiveFailureException with provided message")
  void getDataOrThrow_whenCalled_expectThrowsWithMessage() {
    String error = "File too big";
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, error, true);

    ArchiveFailureException ex = assertThrows(ArchiveFailureException.class, item::getDataOrThrow);
    assertEquals(error, ex.getMessage());
  }

  @Test
  @DisplayName("getDataOrThrow: null message is preserved on exception")
  void getDataOrThrow_whenNullError_expectExceptionWithNullMessage() {
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, null, false);

    ArchiveFailureException ex = assertThrows(ArchiveFailureException.class, item::getDataOrThrow);
    assertNull(ex.getMessage());
  }

  @Test
  @DisplayName("spaceUsed: returns zero for placeholder error item")
  void spaceUsed_whenCalled_expectZero() {
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, "err", false);

    assertEquals(0L, item.spaceUsed());
  }

  @Test
  @DisplayName("getReaderBucket: tooBig==true -> returns null (no exception)")
  void getReaderBucket_whenTooBigTrue_expectNull() throws Exception {
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, "err", true);

    Bucket b = item.getReaderBucket();
    assertNull(b);
  }

  @Test
  @DisplayName("getReaderBucket: tooBig==false -> throws ArchiveFailureException with message")
  void getReaderBucket_whenTooBigFalse_expectThrowsWithMessage() {
    String error = "extraction failed";
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, error, false);

    ArchiveFailureException ex = assertThrows(ArchiveFailureException.class, item::getReaderBucket);
    assertEquals(error, ex.getMessage());
  }

  @Test
  @DisplayName("tooBig(): reflects constructor flag")
  void tooBig_whenSetInConstructor_expectReflectedByAccessor() {
    assertTrue(new ErrorArchiveStoreItem(context, key, filename, "err", true).tooBig());
  }

  @Test
  @DisplayName("addToContext: registers item in context via addItem(this)")
  void addToContext_whenCalled_expectContextAddItemInvoked() {
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, "err", false);

    // Protected in base class; accessible within same package
    item.addToContext();

    verify(context).addItem(item);
  }

  @Test
  @DisplayName("close: delegates to context.removeItem(this)")
  void close_whenCalled_expectContextRemoveItemInvoked() {
    ErrorArchiveStoreItem item = new ErrorArchiveStoreItem(context, key, filename, "err", false);

    item.close(); // package-private in base; accessible from same package

    verify(context).removeItem(item);
  }
}
