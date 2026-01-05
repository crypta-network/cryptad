package network.crypta.clients.fcp

import network.crypta.node.Node
import network.crypta.support.SimpleFieldSet
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentCaptor
import org.mockito.Mockito
import org.mockito.junit.jupiter.MockitoExtension

@ExtendWith(MockitoExtension::class)
@Suppress("java:S100")
class TestDdaRequestMessageTest {

  @Test
  fun constructor_whenDirectoryMissing_throwsMissingField() {
    val fieldSet = SimpleFieldSet(true)

    val exception =
      assertThrows(MessageInvalidException::class.java) { TestDdaRequestMessage(fieldSet) }

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode)
    assertEquals("No Directory given!", exception.message)
    assertNull(exception.ident)
    assertFalse(exception.global)
  }

  @Test
  fun constructor_whenDirectoryEmpty_throwsMissingField() {
    val fieldSet = SimpleFieldSet(true).apply { putSingle(TestDdaRequestMessage.DIRECTORY, "") }

    val exception =
      assertThrows(MessageInvalidException::class.java) { TestDdaRequestMessage(fieldSet) }

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode)
    assertEquals("The specified Directory can't be empty!", exception.message)
    assertNull(exception.ident)
    assertFalse(exception.global)
  }

  @Test
  fun constructor_whenNeitherReadNorWriteRequested_throwsInvalidMessage() {
    val directory = "/tmp/path"
    val fieldSet =
      SimpleFieldSet(true).apply { putSingle(TestDdaRequestMessage.DIRECTORY, directory) }

    val exception =
      assertThrows(MessageInvalidException::class.java) { TestDdaRequestMessage(fieldSet) }

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode)
    assertEquals(
      "Both ${TestDdaRequestMessage.WANT_READ} and ${TestDdaRequestMessage.WANT_WRITE} are set to false: what's the point of sending a message?",
      exception.message,
    )
    assertEquals(directory, exception.ident)
    assertFalse(exception.global)
  }

  @Test
  fun run_whenEnqueueSucceeds_sendsReplyWithJob() {
    val directory = "/tmp/dda"
    val fieldSet =
      SimpleFieldSet(true).apply {
        putSingle(TestDdaRequestMessage.DIRECTORY, directory)
        putSingle(TestDdaRequestMessage.WANT_READ, "true")
      }
    val message = TestDdaRequestMessage(fieldSet)
    val handler = Mockito.mock(FCPConnectionHandler::class.java)
    val node = Mockito.mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val job = Mockito.mock(DdaCheckJob::class.java)

    Mockito.`when`(handler.enqueueDDACheck(directory, true, false)).thenReturn(job)

    message.run(handler, node)

    val replyCaptor = ArgumentCaptor.forClass(TestDdaReplyMessage::class.java)
    Mockito.verify(handler).enqueueDDACheck(directory, true, false)
    Mockito.verify(handler).send(replyCaptor.capture())

    val reply = replyCaptor.value
    assertSame(job, reply.checkJob)
  }

  @Test
  fun run_whenEnqueueThrowsIllegalArgument_translatesToInvalidField() {
    val directory = "/tmp/invalid"
    val fieldSet =
      SimpleFieldSet(true).apply {
        putSingle(TestDdaRequestMessage.DIRECTORY, directory)
        putSingle(TestDdaRequestMessage.WANT_WRITE, "true")
      }
    val message = TestDdaRequestMessage(fieldSet)
    val handler = Mockito.mock(FCPConnectionHandler::class.java)
    val node = Mockito.mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)

    Mockito.`when`(handler.enqueueDDACheck(directory, false, true))
      .thenThrow(IllegalArgumentException("bad path"))

    val exception = assertThrows(MessageInvalidException::class.java) { message.run(handler, node) }

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode)
    assertEquals("bad path", exception.message)
    assertEquals(directory, exception.ident)
    assertFalse(exception.global)
  }

  @Test
  fun getName_returnsConstant() {
    val fieldSet =
      SimpleFieldSet(true).apply {
        putSingle(TestDdaRequestMessage.DIRECTORY, "/tmp/name")
        putSingle(TestDdaRequestMessage.WANT_READ, "true")
      }

    val message = TestDdaRequestMessage(fieldSet)

    assertEquals(TestDdaRequestMessage.NAME, message.name)
  }

  @Test
  fun getFieldSet_returnsNull() {
    val fieldSet =
      SimpleFieldSet(true).apply {
        putSingle(TestDdaRequestMessage.DIRECTORY, "/tmp/fieldset")
        putSingle(TestDdaRequestMessage.WANT_WRITE, "true")
      }

    val message = TestDdaRequestMessage(fieldSet)

    assertNull(message.fieldSet)
  }
}
