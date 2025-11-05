package network.crypta.client.events;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import network.crypta.client.async.ClientContext;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class EventDumperTest {

  @Mock private ClientEvent clientEvent;
  @Mock private ClientContext clientContext;

  @Test
  void constructor_whenGivenArgs_setsFields() {
    StringWriter writer = new StringWriter();
    EventDumper dumper = new EventDumper(writer, true);

    // Verify constructor wired fields as given (package-visible in the same package)
    assertEquals(writer, dumper.w, "Writer should be the same instance");
    assertTrue(dumper.removeWithProducer, "Flag removeWithProducer should be stored");
  }

  @Test
  void receive_whenDescriptionProvided_writesDescriptionWithNewline() {
    StringWriter writer = new StringWriter();
    EventDumper dumper = new EventDumper(writer, false);
    when(clientEvent.getDescription()).thenReturn("hello");

    dumper.receive(clientEvent, clientContext);

    assertEquals("hello\n", writer.toString(), "Should write description followed by newline");
  }

  @Test
  void receive_whenDescriptionIsNull_writesLiteralNullWithNewline() {
    StringWriter writer = new StringWriter();
    EventDumper dumper = new EventDumper(writer, false);
    when(clientEvent.getDescription()).thenReturn(null);

    dumper.receive(clientEvent, clientContext);

    // String concatenation with null yields the literal "null"
    assertEquals("null\n", writer.toString(), "Should write literal null followed by newline");
  }

  @Test
  void receive_whenWriterThrows_ignoresIOException() {
    Writer throwingWriter =
        new Writer() {
          @Override
          public void write(char @NotNull [] cbuf, int off, int len) throws IOException {
            throw new IOException("fail");
          }

          @Override
          public void flush() {
            // Intentionally a no-op: this test double only needs to throw from write()
            // flush() is irrelevant for exercising EventDumper's error handling.
          }

          @Override
          public void close() {
            // Intentionally a no-op for the same reason as flush(): no resource management is
            // required in this minimal test double.
          }
        };

    EventDumper dumper = new EventDumper(throwingWriter, false);
    when(clientEvent.getDescription()).thenReturn("anything");

    assertDoesNotThrow(
        () -> dumper.receive(clientEvent, clientContext),
        "IOException from underlying writer must be ignored");
  }
}
