package network.crypta.node;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Path;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.subsystem.NodeBootstrap;
import network.crypta.support.Base64;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TextModeClientInterfaceTest {

  @Mock Node node;
  @Mock NodeBootstrap bootstrap;
  @Mock NodeClientCore core;
  @Mock HighLevelSimpleClient client;
  @Mock ClientEndpoints endpoints;

  @Captor ArgumentCaptor<Boolean> getChkOnlyCaptor;

  @TempDir Path tmpDir;

  @org.junit.jupiter.api.BeforeEach
  void setUp() {
    when(core.getEndpoints()).thenReturn(endpoints);
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.random())
        .thenReturn(org.mockito.Mockito.mock(network.crypta.crypt.RandomSource.class));
  }

  private String runWithInput(String input) throws Exception {
    // Arrange IO
    InputStream in = new ByteArrayInputStream(input.getBytes(UTF_8));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Minimal stubbing used by header/QUIT path
    when(endpoints.getDirectTMCI()).thenReturn(null); // enable QUIT on header and command

    // Construct SUT
    TextModeClientInterface tmci =
        new TextModeClientInterface(node, core, client, tmpDir.toFile(), in, out);

    // Act
    tmci.realRun();
    return out.toString(UTF_8);
  }

  @Test
  void quit_whenInvoked_expectConnectionClosedMessage() throws Exception {
    String output = runWithInput("QUIT\n");

    assertTrue(output.contains("Trivial Text Mode Client Interface"));
    assertTrue(output.contains("TMCI> "));
    assertTrue(output.contains("Closing connection."));
  }

  @Test
  void help_whenInvoked_expectHeaderPrintedAgain() throws Exception {
    String output = runWithInput("HELP\nQUIT\n");

    int idx = output.indexOf("Trivial Text Mode Client Interface");
    assertTrue(idx >= 0, "Header not found once");
    int idx2 = output.indexOf("Trivial Text Mode Client Interface", idx + 1);
    assertTrue(idx2 >= 0, "Header not printed twice after HELP");
  }

  @Test
  void put_singleLine_expectInsertCalledAndUriPrinted() throws Exception {
    // Arrange
    when(endpoints.getDirectTMCI()).thenReturn(null);
    when(client.insert(any(), any(Boolean.class), any())).thenReturn(FreenetURI.EMPTY_CHK_URI);

    String output = runWithInput("PUT:Hello world!\nQUIT\n");

    // Assert the client.insert was invoked with getCHKOnly = false
    verify(client, times(1)).insert(any(), getChkOnlyCaptor.capture(), any());
    Boolean chkOnly = getChkOnlyCaptor.getValue();
    assertNotNull(chkOnly);
    assertFalse(chkOnly, "PUT must insert with getCHKOnly=false");

    assertTrue(output.contains("URI: "));
    assertTrue(output.contains("CHK@"));
  }

  @Test
  void getchk_multiline_expectInsertCalledWithChkOnlyTrue() throws Exception {
    // Arrange
    when(endpoints.getDirectTMCI()).thenReturn(null);
    when(client.insert(any(), any(Boolean.class), any())).thenReturn(FreenetURI.EMPTY_CHK_URI);

    String input = "GETCHK:\nLine 1\nLine 2\n.\nQUIT\n";
    String output = runWithInput(input);

    verify(client, times(1)).insert(any(), getChkOnlyCaptor.capture(), any());
    Boolean chkOnly = getChkOnlyCaptor.getValue();
    assertNotNull(chkOnly);
    assertTrue(chkOnly, "GETCHK must insert with getCHKOnly=true");

    assertTrue(output.contains("URI: "));
    assertTrue(output.contains("CHK@"));
  }

  @Test
  void get_withValidKey_returnsMimeTypeAndData() throws Exception {
    // Arrange a deterministic valid CHK key: CHK@<32B>,<32B>
    byte[] rk = new byte[32];
    byte[] ck = new byte[32];
    for (int i = 0; i < 32; i++) {
      rk[i] = (byte) (i + 1);
      ck[i] = (byte) (255 - i);
    }
    String key = "CHK@" + Base64.encode(rk) + "," + Base64.encode(ck);

    when(client.fetch(any(FreenetURI.class)))
        .thenReturn(
            FetchResult.create(
                new ClientMetadata("text/plain"), new ArrayBucket("Hello!".getBytes(UTF_8))));

    String output = runWithInput("GET:" + key + "\nQUIT\n");

    assertTrue(output.contains("Content MIME type: text/plain"));
    assertTrue(output.contains("Data:\r\nHello!"));
  }

  @Test
  void get_withEscapeByte_warnsAndSkipsDataPrint() throws Exception {
    // Arrange valid CHK
    byte[] rk = new byte[32];
    byte[] ck = new byte[32];
    String key = "CHK@" + Base64.encode(rk) + "," + Base64.encode(ck);

    // Return a byte 0x1B (ESC) which should be treated as potentially dangerous
    when(client.fetch(any(FreenetURI.class)))
        .thenReturn(
            FetchResult.create(
                new ClientMetadata("application/octet-stream"),
                new ArrayBucket(new byte[] {0x1B})));

    String output = runWithInput("GET:" + key + "\nQUIT\n");

    assertTrue(output.contains("Data may contain escape codes"));
    assertFalse(output.contains("Data:\r\n"));
  }

  @Test
  void get_withMalformedUri_reportsErrorAndDoesNotFetch() throws Exception {
    String output = runWithInput("GET:not_a_key\nQUIT\n");

    assertTrue(output.contains("Malformed URI: not_a_key"));
  }

  @Test
  void memstat_whenInvoked_printsMemorySummary() throws Exception {
    String output = runWithInput("MEMSTAT\nQUIT\n");
    assertTrue(output.contains("Used Java memory:"));
  }
}
