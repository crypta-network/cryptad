package network.crypta.runtime.peers.reference;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PeerReferenceTextLoaderTest {

  @Mock private HighLevelSimpleClient client;

  @Test
  void readFromUrl_whenFileHasTwoLines_readsBothLinesWithTrailingNewlines(@TempDir Path tempDir)
      throws IOException {
    Path file = tempDir.resolve("peer-ref.txt");
    Files.writeString(file, "line1\nline2\n", StandardCharsets.UTF_8);

    URL url = file.toUri().toURL();

    StringBuilder result = PeerReferenceTextLoader.readFromUrl(url);

    assertEquals("line1\nline2\n", result.toString());
  }

  @Test
  void readFromFreenetUri_whenClientReturnsBucket_readsBucketContent() throws Exception {
    Bucket bucket = new ArrayBucket();
    try (OutputStream out = bucket.getOutputStream()) {
      out.write("ref-line-1\nref-line-2\n".getBytes(StandardCharsets.UTF_8));
    }

    FetchResult fetchResult = FetchResult.create(new ClientMetadata("text/plain"), bucket);
    when(client.fetch(any(FreenetURI.class), eq(31000L))).thenReturn(fetchResult);

    FreenetURI uri = mock(FreenetURI.class);

    StringBuilder result = PeerReferenceTextLoader.readFromFreenetUri(uri, client);

    assertEquals("ref-line-1\nref-line-2\n", result.toString());
  }
}
