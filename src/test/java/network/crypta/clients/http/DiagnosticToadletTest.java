package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DiagnosticToadletTest {

  @Mock private DiagnosticPort diagnostic;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private DiagnosticToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new DiagnosticToadlet(diagnostic);
  }

  @Test
  void path_whenCalled_returnsDiagnosticUrl() {
    assertEquals(DiagnosticToadlet.TOADLET_URL, toadlet.path());
  }

  @Test
  void handleMethodGET_whenAccessDenied_doesNotCallPortOrWriteReply() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodGET(URI.create("http://localhost/diagnostic/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoInteractions(diagnostic);
    verify(ctx, never())
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void handleMethodHEAD_whenAccessDenied_doesNotCallPortOrWriteReply() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(false);

    toadlet.handleMethodHEAD(URI.create("http://localhost/diagnostic/"), request, ctx);

    verify(ctx).checkFullAccess(toadlet);
    verifyNoInteractions(diagnostic);
    verify(ctx, never())
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
    verifyNoMoreInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenAuthorized_rendersDetachedDiagnosticReport() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(diagnostic.snapshot())
        .thenReturn(
            new DiagnosticReportSnapshot(
                List.of(
                    new DiagnosticSectionSnapshot("Crypta Version:", List.of("3.0")),
                    new DiagnosticSectionSnapshot(
                        "System Information:", List.of("java.version=25", "")))));

    ByteArrayOutputStream body = captureBody(ctx);

    toadlet.handleMethodGET(URI.create("http://localhost/diagnostic/"), request, ctx);

    assertEquals(
        """
        Crypta Version:
        3.0
        System Information:
        java.version=25

        """,
        body.toString(StandardCharsets.UTF_8));
    verify(diagnostic).snapshot();
    verify(ctx)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
  }

  @Test
  void handleMethodHEAD_whenAuthorized_sendsHeadersWithoutDiagnosticBody() throws Exception {
    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(diagnostic.snapshot())
        .thenReturn(
            new DiagnosticReportSnapshot(
                List.of(new DiagnosticSectionSnapshot("Crypta Version:", List.of("3.0")))));
    String expectedBody =
        """
        Crypta Version:
        3.0
        """;

    toadlet.handleMethodHEAD(
        URI.create("http://localhost/diagnostic/?legacyFallback=diagnostic-export"), request, ctx);

    verify(diagnostic).snapshot();
    verify(ctx)
        .sendReplyHeaders(
            eq(200),
            eq("OK"),
            isNull(),
            eq("text/plain; charset=utf-8"),
            eq((long) expectedBody.getBytes(StandardCharsets.UTF_8).length),
            eq(true));
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  private ByteArrayOutputStream captureBody(ToadletContext context) throws Exception {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    doAnswer(_ -> null)
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
    doAnswer(
            invocation -> {
              byte[] data = invocation.getArgument(0);
              int offset = invocation.getArgument(1);
              int length = invocation.getArgument(2);
              body.write(data, offset, length);
              return null;
            })
        .when(context)
        .writeData(any(byte[].class), anyInt(), anyInt());
    return body;
  }
}
