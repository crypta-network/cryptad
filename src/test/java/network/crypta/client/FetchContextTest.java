package network.crypta.client;

import static org.junit.Assert.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.StorageFormatException;
import org.junit.Test;

public class FetchContextTest {

  @Test
  public void testPersistence() throws IOException, StorageFormatException {
    FetchContext context =
        HighLevelSimpleClientImpl.makeDefaultFetchContext(
            Long.MAX_VALUE, Long.MAX_VALUE, new ArrayBucketFactory(), new SimpleEventProducer());
    ArrayBucket bucket = new ArrayBucket();
    try {
      try (DataOutputStream dos = new DataOutputStream(bucket.getOutputStream())) {
        context.writeTo(dos);
      }
      assertNotEquals(0, bucket.size());
      FetchContext ctx;
      try (DataInputStream dis = new DataInputStream(bucket.getInputStream())) {
        ctx = new FetchContext(dis);
      }
      assertEquals(ctx, context);
    } finally {
      bucket.free();
    }
  }
}
