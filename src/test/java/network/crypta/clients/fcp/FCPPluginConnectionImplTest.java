package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.clients.fcp.FCPPluginMessage.ClientPermissions;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ServerSideFCPMessageHandler;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
final class FCPPluginConnectionImplTest {

  @Test
  void send_whenServerHandlerThrows_returnsInternalErrorReplyToClient() throws Exception {
    // Arrange
    ServerSideFCPMessageHandler server =
        (connection, message) -> {
          throw new IllegalStateException("boom");
        };
    CountDownLatch latch = new CountDownLatch(1);
    AtomicReference<FCPPluginMessage> replyRef = new AtomicReference<>();
    ClientSideFCPMessageHandler client =
        (connection, message) -> {
          replyRef.set(message);
          latch.countDown();
          return null;
        };
    FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForUnitTest(server, client);
    FCPPluginMessage message = FCPPluginMessage.construct();

    // Act
    connection.send(SendDirection.TO_SERVER, message);

    // Assert
    assertTrue(latch.await(5, TimeUnit.SECONDS), "Client should see the generated error reply");
    FCPPluginMessage reply = replyRef.get();
    assertNotNull(reply);
    assertTrue(reply.isReplyMessage());
    assertFalse(reply.success);
    assertEquals("InternalError", reply.errorCode);
    assertNotNull(reply.errorMessage);
    assertTrue(reply.errorMessage.contains("IllegalStateException"));
  }

  @Test
  void getDefaultSendDirectionAdapter_whenSendingToServer_setsPermissionsAndCopiesMessage()
      throws Exception {
    // Arrange
    CountDownLatch latch = new CountDownLatch(1);
    AtomicReference<FCPPluginMessage> delivered = new AtomicReference<>();
    ServerSideFCPMessageHandler server =
        (connection, message) -> {
          delivered.set(message);
          latch.countDown();
          return null;
        };
    ClientSideFCPMessageHandler client = (connection, message) -> null;
    FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForUnitTest(server, client);
    FCPPluginConnection adapter =
        connection.getDefaultSendDirectionAdapter(SendDirection.TO_SERVER);
    FCPPluginMessage original = FCPPluginMessage.construct();

    // Act
    adapter.send(original);

    // Assert
    assertTrue(latch.await(5, TimeUnit.SECONDS), "Server should receive the message");
    FCPPluginMessage received = delivered.get();
    assertNotNull(received);
    assertEquals(ClientPermissions.ACCESS_DIRECT, received.permissions);
    assertNotSame(original, received, "send() should wrap messages to stamp permissions");
  }

  @Test
  void sendSynchronous_whenReplyMissing_timesOutAndCleansUpState() {
    // Arrange
    ServerSideFCPMessageHandler server = (connection, message) -> null;
    ClientSideFCPMessageHandler client = (connection, message) -> null;
    FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForUnitTest(server, client);
    FCPPluginMessage message = FCPPluginMessage.construct();

    // Act + Assert
    IOException ex =
        assertThrows(
            IOException.class,
            () ->
                connection.sendSynchronous(
                    SendDirection.TO_SERVER, message, TimeUnit.MILLISECONDS.toNanos(20)),
            "Timed out calls should surface as IOExceptions");
    assertTrue(ex.getMessage().contains("timed out"));
    assertEquals(0, connection.getSendSynchronousCount());
  }

  @Test
  void send_whenDefaultDirectionMissing_throwsNoSendDirectionSpecifiedException() {
    // Arrange
    ServerSideFCPMessageHandler server = (connection, message) -> null;
    ClientSideFCPMessageHandler client = (connection, message) -> null;
    FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForUnitTest(server, client);
    FCPPluginMessage message = FCPPluginMessage.construct();

    // Act + Assert
    assertThrows(UnsupportedOperationException.class, () -> connection.send(message));
  }

  /**
   * {@link FCPPluginConnectionImpl#sendSynchronous(SendDirection, FCPPluginMessage, long)} is
   * powered by an internal map which keeps track of synchronous sends which are waiting for a
   * reply.<br>
   * As this map is accessed concurrently, one might suspect possible thread safety issues.<br>
   * This test therefore runs 100 sendSynchronous() threads in parallel to trigger race conditions,
   * and thereby checks the following:<br>
   * - Whether replies are delivered to the correct thread. This is done by having each thread send
   * a message with a certain index number, to which the server replies with the same index number.
   * The reply is checked to have the same index number as the original message.<br>
   * - Whether the map which keeps track of synchronous sends does not leak. This is done by
   * checking whether it is empty after all send threads have terminated.<br>
   */
  @Test
  void sendSynchronous_whenHundredThreadsRunInParallel_preservesRepliesAndCleansTable()
      throws InterruptedException {
    // JUnit ignores failures in threads other than the threads which it runs tests from.
    // Thus, we pass failures out with this boolean.
    // NOTICE: Use the asyncErrors queue instead of direct assertions so failures surface on the
    // main test thread after all workers join.
    final AtomicBoolean failure = new AtomicBoolean(false);
    final ConcurrentLinkedQueue<String> asyncErrors = new ConcurrentLinkedQueue<>();

    // Notice: server must be kept referenced by our local variable for the whole duration of
    // the test, otherwise it would get GCed because the FCPPluginConnectionImpl which we will
    // pass it to only keeps a WeakReference to it.
    // This is by design: Plugins are supposed to be unloadable and the FCPPluginConnectionImpl
    // must not keep them pinned in memory after unload.
    final ServerSideFCPMessageHandler server =
        (connection, message) -> {
          final FCPPluginMessage reply = FCPPluginMessage.constructSuccessReply(message);
          reply.params.putSingle("replyToThread", message.params.get("thread"));
          return reply;
        };

    final ClientSideFCPMessageHandler client =
        (connection, message) -> {
          failure.set(true);
          asyncErrors.add("Reply unexpectedly routed to client handler");
          return null;
        };

    final FCPPluginConnectionImpl connection =
        FCPPluginConnectionImpl.constructForUnitTest(server, client);

    final int threadCount = 100;
    final Thread[] threads = new Thread[threadCount];

    for (int i = 0; i < threadCount; ++i) {
      final String threadIndex = Integer.toString(i);

      final Thread thread =
          new Thread(
              new Runnable() {
                final FCPPluginMessage message;

                {
                  message = FCPPluginMessage.construct();
                  message.params.putSingle("thread", threadIndex);
                }

                @Override
                public void run() {
                  try {
                    final FCPPluginMessage reply =
                        connection.sendSynchronous(
                            SendDirection.TO_SERVER, message, TimeUnit.SECONDS.toNanos(10));

                    if (!threadIndex.equals(reply.params.get("replyToThread"))) {
                      failure.set(true);
                      asyncErrors.add(
                          "Thread "
                              + threadIndex
                              + " received reply for "
                              + reply.params.get("replyToThread"));
                    }
                  } catch (IOException e) {
                    failure.set(true);
                    asyncErrors.add("IOException " + e);
                  } catch (InterruptedException e) {
                    failure.set(true);
                    asyncErrors.add("InterruptedException " + e);
                  }
                }
              });

      threads[i] = thread;
    }

    // Start them in a separate loop, not in the loop where we construct them, to ensure that
    // they are all started at the same time, execute in parallel, and thus have maximal
    // probability of race conditions.
    for (int i = 0; i < threadCount; ++i) threads[i].start();

    for (int i = 0; i < threadCount; ++i) threads[i].join();

    assertFalse(
        failure.get(),
        asyncErrors.isEmpty()
            ? "No background failures expected"
            : String.join(System.lineSeparator(), asyncErrors));

    assertEquals(
        0,
        connection.getSendSynchronousCount(),
        "FCPPluginConnectionImpl sendSynchronous() map should not leak");
  }
}
