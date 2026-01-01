package com.onionnetworks.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.BindException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class PlainDatagramSocketFactoryTest {

  private final PlainDatagramSocketFactory factory = new PlainDatagramSocketFactory();

  @Test
  void createDatagramSocket_whenCalled_returnsOpenSocket() throws Exception {
    try (DatagramSocket socket = factory.createDatagramSocket()) {
      assertNotNull(socket);
      assertTrue(socket.isBound());
      assertTrue(socket.getLocalPort() > 0);
    }
  }

  @Test
  void createDatagramSocket_withSpecificPort_bindsToRequestedPort() throws Exception {
    int availablePort;
    try (DatagramSocket socket = new DatagramSocket(0)) {
      availablePort = socket.getLocalPort();
    }

    try (DatagramSocket socket = factory.createDatagramSocket(availablePort)) {
      assertEquals(availablePort, socket.getLocalPort());
    }
  }

  @Test
  void createDatagramSocket_whenPortInUse_throwsBindException() throws Exception {
    try (DatagramSocket reserved = new DatagramSocket(0)) {
      int portInUse = reserved.getLocalPort();

      assertThrows(
          BindException.class,
          () -> {
            //noinspection EmptyTryBlock
            try (var _ = factory.createDatagramSocket(portInUse)) {
              // unreachable when exception is thrown
            }
          });
    }
  }

  @Test
  void createDatagramSocket_whenInvalidPort_throwsIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          //noinspection EmptyTryBlock
          try (var _ = factory.createDatagramSocket(-1)) {
            // unreachable when exception is thrown
          }
        });
  }

  @Test
  void createDatagramSocket_withPortAndAddressProvided_bindsToAddress() throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();

    try (DatagramSocket socket = factory.createDatagramSocket(0, loopback)) {
      assertTrue(socket.isBound());
      assertEquals(loopback, socket.getLocalAddress());
    }
  }
}
