package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NPFPacketTest {

  static final int MAX_PACKET_SIZE = 1400;

  NullBasePeerNode pn = new NullBasePeerNode();

  @Test
  void create_whenHeaderHasNoAcks_expectNoAcksNoFragmentsNoError() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number 0
          (byte) 0x00
        }; // 0 acks
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);

    // Assert
    assertEquals(0, r.getSequenceNumber());
    assertEquals(0, r.getAcks().size());
    assertEquals(0, r.getFragments().size());
    assertFalse(r.getError());
  }

  @Test
  void create_whenSingleAckRange_expectAckPresent() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number 0
          (byte) 0x01, // 1 ack
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01
        }; // Ack for packet range [0..0] of length 1
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);

    // Assert
    assertEquals(0, r.getSequenceNumber());
    assertEquals(1, r.getAcks().size());
    assertTrue(r.getAcks().contains(0));
    assertEquals(0, r.getFragments().size());
    assertFalse(r.getError());
  }

  @Test
  void create_whenMultipleAckRanges_expectAllAcksCollected() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number 0
          (byte) 0x03, // 3 ack ranges
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x05,
          (byte) 0x01, // Ack for packet 5
          (byte) 0x05,
          (byte) 0x02, // Ack range for packets [10..11] of size 2
          (byte) 0x00 /*Far-range marker*/,
          (byte) 0x00,
          (byte) 0x0F,
          (byte) 0x57,
          (byte) 0xF3 /*Ack id (1005555)*/,
          (byte) 0x05 /*Range size*/
        };
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);

    // Assert
    assertEquals(0, r.getSequenceNumber());
    assertEquals(8, r.getAcks().size());
    assertTrue(r.getAcks().contains(5));
    assertTrue(r.getAcks().contains(10));
    assertTrue(r.getAcks().contains(11));
    assertTrue(r.getAcks().contains(1005555));
    assertTrue(r.getAcks().contains(1005556));
    assertTrue(r.getAcks().contains(1005557));
    assertTrue(r.getAcks().contains(1005558));
    assertTrue(r.getAcks().contains(1005559));
    assertEquals(0, r.getFragments().size());
    assertFalse(r.getError());
  }

  @Test
  void create_whenSingleShortUnfragmentedFragment_expectParsedFields() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number 0
          (byte) 0x00, // 0 acks
          (byte) 0xB0,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Flags (short, first fragment and full id) and messageID 0
          (byte) 0x08, // Fragment length
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        }; // Data
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);

    // Assert
    assertEquals(0, r.getSequenceNumber());
    assertEquals(0, r.getAcks().size());
    assertEquals(1, r.getFragments().size());

    MessageFragment frag = r.getFragments().getFirst();
    assertTrue(frag.shortMessage);
    assertFalse(frag.isFragmented);
    assertTrue(frag.firstFragment);
    assertEquals(0, frag.messageID);
    assertEquals(8, frag.fragmentLength);
    assertEquals(0, frag.fragmentOffset);
    assertEquals(8, frag.messageLength);
    assertArrayEquals(
        new byte[] {
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        },
        frag.fragmentData);

    assertFalse(r.getError());
  }

  @Test
  void create_whenTwoShortFragments_expectBothParsed() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number 0
          (byte) 0x00, // 0 acks
          (byte) 0xB0,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Flags (short and first fragment) and messageID 0
          (byte) 0x08, // Fragment length
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF, // Data
          (byte) 0xA0,
          (byte) 0x00, // Flags (short and first fragment) and messageID 0
          (byte) 0x08, // Fragment length
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        }; // Data
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);

    // Assert
    assertEquals(0, r.getSequenceNumber());
    assertEquals(0, r.getAcks().size());
    assertEquals(2, r.getFragments().size());

    // Check first fragment
    MessageFragment frag = r.getFragments().getFirst();
    assertTrue(frag.shortMessage);
    assertFalse(frag.isFragmented);
    assertTrue(frag.firstFragment);
    assertEquals(0, frag.messageID);
    assertEquals(8, frag.fragmentLength);
    assertEquals(0, frag.fragmentOffset);
    assertEquals(8, frag.messageLength);
    assertArrayEquals(
        new byte[] {
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        },
        frag.fragmentData);

    // Check second fragment
    frag = r.getFragments().get(1);
    assertTrue(frag.shortMessage);
    assertFalse(frag.isFragmented);
    assertTrue(frag.firstFragment);
    assertEquals(0, frag.messageID);
    assertEquals(8, frag.fragmentLength);
    assertEquals(0, frag.fragmentOffset);
    assertEquals(8, frag.messageLength);
    assertArrayEquals(
        new byte[] {
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        },
        frag.fragmentData);

    assertFalse(r.getError());
  }

  @Test
  void create_whenShortFragmentLength128_expectParsedWithoutError() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number 0
          (byte) 0x00, // 0 acks
          (byte) 0xB0,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Flags (short and first fragment) and messageID 0
          (byte) 0x80, // Fragment length
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        };
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);
    // Assert
    assertEquals(0, r.getAcks().size());
    assertEquals(1, r.getFragments().size());
    MessageFragment f = r.getFragments().getFirst();
    assertTrue(f.firstFragment);
    assertTrue(f.shortMessage);
    assertEquals(0, f.messageID);
    assertEquals(128, f.fragmentLength);
    assertFalse(r.getError());
  }

  @Test
  void create_whenCustomSequence_expectSequenceParsed() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x01,
          (byte) 0x02,
          (byte) 0x04,
          (byte) 0x08, // Sequence number
          (byte) 0x00
        }; // 0 acks
    // Act
    NPFPacket r = NPFPacket.create(packet, pn);

    // Assert
    assertEquals(16909320, r.getSequenceNumber());
    assertEquals(0, r.getAcks().size());
    assertEquals(0, r.getFragments().size());
    assertFalse(r.getError());
  }

  @Test
  void create_whenLongFragmentedNotFirst_expectOffsetAndLengthParsed() {
    // Arrange
    byte[] packetNoData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number (0)
          (byte) 0x00, // 0 acks
          (byte) 0x50,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Flags (long, fragmented, not first) and messageID 0
          (byte) 0x01,
          (byte) 0x01, // Fragment length
          (byte) 0x01,
          (byte) 0x01
        }; // Fragment offset
    byte[] packet = new byte[packetNoData.length + 257];
    System.arraycopy(packetNoData, 0, packet, 0, packetNoData.length);

    // Act
    NPFPacket r = NPFPacket.create(packet, pn);
    // Assert
    assertEquals(0, r.getSequenceNumber());
    assertEquals(0, r.getAcks().size());
    assertEquals(1, r.getFragments().size());

    MessageFragment f = r.getFragments().getFirst();
    assertFalse(f.shortMessage);
    assertFalse(f.firstFragment);
    assertTrue(f.isFragmented);
    assertEquals(257, f.fragmentLength);
    assertEquals(257, f.fragmentOffset);
    assertEquals(0, f.messageID);

    assertFalse(r.getError());
  }

  @Test
  void create_whenFragmentHeaderTruncated_expectError() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0xC0,
          (byte) 0x00,
          (byte) 0x01,
          (byte) 0x00
        };

    // Act
    NPFPacket r = NPFPacket.create(packet, pn);
    // Assert
    assertEquals(0, r.getFragments().size());
    assertTrue(r.getError());
  }

  @Test
  void create_whenZeroLengthFragment_expectEmptyData() {
    // Arrange
    byte[] packet =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0xB0,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00
        };

    // Act
    NPFPacket r = NPFPacket.create(packet, pn);
    // Assert
    assertFalse(r.getError());
    assertEquals(1, r.getFragments().size());

    MessageFragment f = r.getFragments().getFirst();
    assertEquals(0, f.fragmentLength);
    assertEquals(0, f.fragmentData.length);
    assertEquals(0, f.messageID);
  }

  @Test
  void toBytes_whenNoAcksOrFragments_expectHeaderOnly() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number (0)
          (byte) 0x00
        }; // Number of acks (0)

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenSingleAck_expectEncodedAckBlock() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);
    p.addAck(0, MAX_PACKET_SIZE);

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenSequentialAcks_expectSingleRange() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);
    p.addAck(0, MAX_PACKET_SIZE);
    p.addAck(1, MAX_PACKET_SIZE);
    p.addAck(2, MAX_PACKET_SIZE);

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x03
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenTwoNearAcks_expectTwoRanges() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);
    p.addAck(0, MAX_PACKET_SIZE);
    p.addAck(5, MAX_PACKET_SIZE);

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x02,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01,
          (byte) 0x05,
          (byte) 0x01
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenFarAck_expectFarMarkerAndFullId() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);
    p.addAck(0, MAX_PACKET_SIZE);
    p.addAck(1000000, MAX_PACKET_SIZE);

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x02,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01,
          (byte) 0x00 /* marker */,
          (byte) 0x00,
          (byte) 0x0F,
          (byte) 0x42,
          (byte) 0x40,
          (byte) 0x01
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenThreeIndependentAcks_expectThreeRanges() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);
    p.addAck(0, MAX_PACKET_SIZE);
    p.addAck(5, MAX_PACKET_SIZE);
    p.addAck(10, MAX_PACKET_SIZE);

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x03,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x01,
          (byte) 0x05,
          (byte) 0x01,
          (byte) 0x05,
          (byte) 0x01
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenSingleFragment_expectDataEncoded() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(100);
    p.addMessageFragment(
        new MessageFragment(
            true,
            false,
            true,
            0,
            8,
            8,
            0,
            new byte[] {
              (byte) 0x01,
              (byte) 0x23,
              (byte) 0x45,
              (byte) 0x67,
              (byte) 0x89,
              (byte) 0xAB,
              (byte) 0xCD,
              (byte) 0xEF
            },
            null));

    byte[] correctData =
        new byte[] {
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x64, // Sequence number (100)
          (byte) 0x00,
          (byte) 0xB0,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Flags + messageID
          (byte) 0x08, // Fragment length
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void toBytes_whenMixedAcksAndFragments_expectLayoutMatchesReference() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(2130706432);
    // Range 1 [1000000..1000000]
    p.addAck(1000000, MAX_PACKET_SIZE);

    // Range 2 [1000010..1000010]
    p.addAck(1000010, MAX_PACKET_SIZE);

    // Range 3 [1000255..1000257]
    p.addAck(1000255, MAX_PACKET_SIZE);
    p.addAck(1000256, MAX_PACKET_SIZE);
    p.addAck(1000257, MAX_PACKET_SIZE);

    // Range 4 [1005555..1005559]
    p.addAck(1005555, MAX_PACKET_SIZE);
    p.addAck(1005556, MAX_PACKET_SIZE);
    p.addAck(1005557, MAX_PACKET_SIZE);
    p.addAck(1005558, MAX_PACKET_SIZE);
    p.addAck(1005559, MAX_PACKET_SIZE);

    p.addMessageFragment(
        new MessageFragment(
            true,
            false,
            true,
            0,
            8,
            8,
            0,
            new byte[] {
              (byte) 0x01,
              (byte) 0x23,
              (byte) 0x45,
              (byte) 0x67,
              (byte) 0x89,
              (byte) 0xAB,
              (byte) 0xCD,
              (byte) 0xEF
            },
            null));
    p.addMessageFragment(
        new MessageFragment(
            false,
            true,
            false,
            4095,
            14,
            1024,
            256,
            new byte[] {
              (byte) 0xfd, (byte) 0x47, (byte) 0xc2, (byte) 0x30,
              (byte) 0x41, (byte) 0x53, (byte) 0x57, (byte) 0x56,
              (byte) 0x0e, (byte) 0x56, (byte) 0x69, (byte) 0xf5,
              (byte) 0x00, (byte) 0x0d
            },
            null));

    byte[] correctData =
        new byte[] {
          (byte) 0x7F,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Sequence number
          (byte) 0x04, // Number of ack ranges
          (byte) 0x00,
          (byte) 0x0F,
          (byte) 0x42,
          (byte) 0x40,
          (byte) 0x01, // First ack + range length
          (byte) 0x0A,
          (byte) 0x01, // 2nd Range + range length
          (byte) 0xF5,
          (byte) 0x03, // 3rd range + range length
          (byte) 0x00 /*Far-range marker*/,
          (byte) 0x00,
          (byte) 0x0F,
          (byte) 0x57,
          (byte) 0xF3 /*Ack id*/,
          (byte) 0x05 /*Range size*/,
          // First fragment
          (byte) 0xB0,
          (byte) 0x00,
          (byte) 0x00,
          (byte) 0x00, // Message id + flags
          (byte) 0x08, // Fragment length
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF,
          // Second fragment
          (byte) 0x4F,
          (byte) 0xFF,
          (byte) 0x00,
          (byte) 0x0e, // Fragment length
          (byte) 0x01,
          (byte) 0x00, // Fragment offset
          (byte) 0xfd,
          (byte) 0x47,
          (byte) 0xc2,
          (byte) 0x30,
          (byte) 0x41,
          (byte) 0x53,
          (byte) 0x57,
          (byte) 0x56,
          (byte) 0x0e,
          (byte) 0x56,
          (byte) 0x69,
          (byte) 0xf5,
          (byte) 0x00,
          (byte) 0x0d
        };

    // Act & Assert
    checkPacket(p, correctData);
  }

  @Test
  void getLength_whenAddingFragments_expectAccountingUpdates() {
    // Arrange
    NPFPacket p = new NPFPacket();

    p.addMessageFragment(new MessageFragment(true, false, true, 0, 10, 10, 0, new byte[10], null));
    // Act & Assert
    assertEquals(20, p.getLength()); // Seqnum (4), numAcks (1), msgID (4), length (1), data (10)

    p.addMessageFragment(
        new MessageFragment(true, false, true, 5000, 10, 10, 0, new byte[10], null));
    assertEquals(35, p.getLength()); // + msgID (4), length (1), data (10)

    // This fragment adds 13, but the next won't need a full message id anymore, so this should only
    // add 11
    // bytes
    p.addMessageFragment(
        new MessageFragment(true, false, true, 2500, 10, 10, 0, new byte[10], null));
    assertEquals(46, p.getLength());
  }

  @Test
  void lossyMessages_whenSingleMessage_expectRoundTrip() {
    // Arrange
    NPFPacket p = new NPFPacket();
    byte[] fragData =
        new byte[] {
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        };
    p.addMessageFragment(new MessageFragment(true, false, true, 0, 8, 8, 0, fragData, null));
    byte[] lossyFragment =
        new byte[] {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA};
    p.addLossyMessage(lossyFragment);
    byte[] encoded = new byte[p.getLength()];
    p.toBytes(encoded, 0, null);
    // Act
    NPFPacket received = NPFPacket.create(encoded, pn);
    // Assert
    assertEquals(1, received.getFragments().size());
    assertEquals(0, received.countAcks());
    assertEquals(1, received.getLossyMessages().size());
    assertEquals(encoded.length, received.getLength());
    byte[] decodedFragData = received.getFragments().getFirst().fragmentData;
    checkEquals(fragData, decodedFragData);
    byte[] decodedLossyMessage = received.getLossyMessages().getFirst();
    checkEquals(lossyFragment, decodedLossyMessage);
  }

  @Test
  void lossyMessages_whenTwoMessages_expectRoundTripBoth() {
    // Arrange
    NPFPacket p = new NPFPacket();
    byte[] fragData =
        new byte[] {
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        };
    p.addMessageFragment(new MessageFragment(true, false, true, 0, 8, 8, 0, fragData, null));
    byte[] lossyFragment =
        new byte[] {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA};
    byte[] lossyFragment2 =
        new byte[] {(byte) 0xAA, (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55};
    p.addLossyMessage(lossyFragment);
    p.addLossyMessage(lossyFragment2);
    byte[] encoded = new byte[p.getLength()];
    p.toBytes(encoded, 0, null);
    // Act
    NPFPacket received = NPFPacket.create(encoded, pn);
    // Assert
    assertEquals(1, received.getFragments().size());
    assertEquals(0, received.countAcks());
    assertEquals(2, received.getLossyMessages().size());
    assertEquals(encoded.length, received.getLength());
    byte[] decodedFragData = received.getFragments().getFirst().fragmentData;
    checkEquals(fragData, decodedFragData);
    byte[] decodedLossyMessage = received.getLossyMessages().getFirst();
    checkEquals(lossyFragment, decodedLossyMessage);
    decodedLossyMessage = received.getLossyMessages().get(1);
    checkEquals(lossyFragment2, decodedLossyMessage);
  }

  @Test
  void lossyMessages_whenTwoMessagesWithPadding_expectRoundTripAndLength() {
    // Arrange
    NPFPacket p = new NPFPacket();
    byte[] fragData =
        new byte[] {
          (byte) 0x01,
          (byte) 0x23,
          (byte) 0x45,
          (byte) 0x67,
          (byte) 0x89,
          (byte) 0xAB,
          (byte) 0xCD,
          (byte) 0xEF
        };
    p.addMessageFragment(new MessageFragment(true, false, true, 0, 8, 8, 0, fragData, null));
    byte[] lossyFragment =
        new byte[] {(byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA};
    byte[] lossyFragment2 =
        new byte[] {(byte) 0xAA, (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55};
    p.addLossyMessage(lossyFragment);
    p.addLossyMessage(lossyFragment2);
    byte[] encoded = new byte[p.getLength() + 20];
    int randomSeed = new Random().nextInt();
    p.toBytes(encoded, 0, new Random(randomSeed));
    // Act
    NPFPacket received = NPFPacket.create(encoded, pn);
    // Assert
    assertEquals(1, received.getFragments().size());
    assertEquals(0, received.countAcks());
    assertEquals(2, received.getLossyMessages().size(), "Seed was " + randomSeed);
    assertEquals(p.getLength(), received.getLength());
    assertEquals(encoded.length - 20, received.getLength());
    byte[] decodedFragData = received.getFragments().getFirst().fragmentData;
    checkEquals(fragData, decodedFragData);
    byte[] decodedLossyMessage = received.getLossyMessages().getFirst();
    checkEquals(lossyFragment, decodedLossyMessage);
    decodedLossyMessage = received.getLossyMessages().get(1);
    checkEquals(lossyFragment2, decodedLossyMessage);
  }

  // ---------------- Additional edge-case and behavior tests ----------------

  @Test
  void create_whenPnNull_throwsIllegalArgumentException() {
    // Arrange
    byte[] minimal = new byte[] {0, 0, 0, 1, 0};

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> NPFPacket.create(minimal, null));
  }

  @Test
  void create_whenAckSectionTruncated_setsErrorAndNoAcks() {
    // Arrange: seq + numAckRanges=1 but insufficient bytes for the range
    byte[] truncated = new byte[] {0, 0, 0, 0, 1};

    // Act
    NPFPacket r = NPFPacket.create(truncated, pn);

    // Assert
    assertTrue(r.getError());
    assertEquals(0, r.getAcks().size());
    assertEquals(0, r.getFragments().size());
  }

  @Test
  void create_whenLossyMessageTruncated_ignoresLossyAndStopsParsing() {
    // Arrange: seq + 0 acks + start of lossy (0x1F) claiming 16 bytes but only 2 remain
    byte[] pkt = new byte[] {0, 0, 0, 0, 0, 0x1F, 16, 0x7E, 0x7F};

    // Act
    NPFPacket r = NPFPacket.create(pkt, pn);

    // Assert: parsing stops at lossy marker; length is header (5) and no lossy messages
    assertFalse(r.getError());
    assertEquals(5, r.getLength());
    assertTrue(r.getLossyMessages().isEmpty());
    assertTrue(r.getFragments().isEmpty());
  }

  @Test
  void addAck_whenNegative_throwsIllegalArgumentException() {
    // Arrange
    NPFPacket p = new NPFPacket();

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> p.addAck(-1, 1400));
  }

  @Test
  void addAck_whenExceedsMaxPacketSize_returnsFalseAndDoesNotAdd() {
    // Arrange: first ack requires at least 10 bytes in total (5 base + 5 ack block)
    NPFPacket p = new NPFPacket();

    // Act
    boolean added = p.addAck(0, /*maxPacketSize*/ 9);

    // Assert
    assertFalse(added);
    assertTrue(p.getAcks().isEmpty());
    assertEquals(5, p.getLength());
  }

  @Test
  void addLossyMessage_whenTooLarge_throwsIllegalArgumentException() {
    // Arrange
    NPFPacket p = new NPFPacket();
    byte[] big = new byte[256];

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> p.addLossyMessage(big));
  }

  @Test
  void addLossyMessage_whenExceedsMaxPacketSize_returnsFalseAndNoChange() {
    // Arrange
    NPFPacket p = new NPFPacket();
    byte[] small = new byte[10];

    // Act
    boolean added = p.addLossyMessage(small, /*maxPacketSize*/ 5 + 1); // not enough space

    // Assert
    assertFalse(added);
    assertTrue(p.getLossyMessages().isEmpty());
    assertEquals(5, p.getLength());
  }

  @Test
  void removeLossyMessage_whenPresent_updatesLengthAndList() {
    // Arrange
    NPFPacket p = new NPFPacket();
    byte[] m1 = new byte[] {1, 2, 3};
    byte[] m2 = new byte[] {4, 5};
    int afterM2 = p.addLossyMessage(m2); // + (2+2)
    // addLossyMessage returns the updated packet size (matches getLength())
    assertEquals(5 + (2 + 2), afterM2);

    // Act
    p.removeLossyMessage(m1);

    // Assert
    assertEquals(5 + (2 + 2), p.getLength());
    assertEquals(1, p.getLossyMessages().size());
    assertArrayEquals(m2, p.getLossyMessages().getFirst());
  }

  @Test
  void toString_whenFieldsSet_includesCountsAndLength() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(123);
    p.addAck(7, 1400);
    byte[] data = new byte[] {9, 8, 7};
    p.addMessageFragment(new MessageFragment(true, false, true, 100, 3, 3, 0, data, null));

    // Act
    String s = p.toString();

    // Assert
    assertEquals("Packet 123: " + p.getLength() + " bytes, 1 acks, 1 fragments", s);
  }

  @Test
  void countAcks_and_noFragments_reportExpectedValues() {
    // Arrange
    NPFPacket p = new NPFPacket();

    // Act + Assert
    assertEquals(0, p.countAcks());
    assertTrue(p.noFragments());
    p.addAck(1, 1400);
    assertEquals(1, p.countAcks());
  }

  @Test
  void toBytes_whenSecondFragmentUsesCompressedId_encodesTwoByteHeader() {
    // Arrange
    NPFPacket p = new NPFPacket();
    p.setSequenceNumber(0);
    byte[] d1 = new byte[] {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC};
    byte[] d2 = new byte[] {(byte) 0x11, (byte) 0x22, (byte) 0x33};

    // First fragment: full id (0x10) for message 5000
    p.addMessageFragment(new MessageFragment(true, false, true, 5000, 3, 3, 0, d1, null));
    // Second fragment: new message id close to previous (delta 200 < 4096) -> compressed id
    p.addMessageFragment(new MessageFragment(true, false, true, 5200, 3, 3, 0, d2, null));

    // Act
    byte[] encoded = new byte[p.getLength()];
    p.toBytes(encoded, 0, null);

    // Assert minimal structure: 4 bytes seq, 1 byte ack count, first header (B0 + id), then
    // second header A0 with low byte C8 (delta 200), then lengths and data
    int off = 0;
    assertEquals(0, encoded[off++] & 0xFF);
    assertEquals(0, encoded[off++] & 0xFF);
    assertEquals(0, encoded[off++] & 0xFF);
    assertEquals(0, encoded[off++] & 0xFF);
    assertEquals(0, encoded[off++] & 0xFF); // 0 acks

    // First fragment header (B0 + 0x00001388)
    assertEquals(0xB0, encoded[off++] & 0xFF);
    assertEquals(0x00, encoded[off++] & 0xFF);
    assertEquals(0x13, encoded[off++] & 0xFF);
    assertEquals(0x88, encoded[off++] & 0xFF);
    assertEquals(3, encoded[off++] & 0xFF); // length
    assertEquals(0xAA, encoded[off++] & 0xFF);
    assertEquals(0xBB, encoded[off++] & 0xFF);
    assertEquals(0xCC, encoded[off++] & 0xFF);

    // Second fragment should use compressed encoding: header A0, delta 0x00C8 (two bytes => 0xA0,
    // 0xC8)
    assertEquals(0xA0, encoded[off++] & 0xFF);
    assertEquals(0xC8, encoded[off++] & 0xFF);
    assertEquals(3, encoded[off++] & 0xFF); // length
    assertEquals(0x11, encoded[off++] & 0xFF);
    assertEquals(0x22, encoded[off++] & 0xFF);
    assertEquals(0x33, encoded[off] & 0xFF);
  }

  @Test
  void onSent_whenSingleFragment_invokesWrapperWithComputedOverhead() {
    // Arrange
    NPFPacket p = new NPFPacket();
    MessageWrapper wrapper = mock(MessageWrapper.class);
    byte[] payload = new byte[] {1, 2, 3, 4};
    // shortMessage=true, isFragmented=false, firstFragment=true, messageLength=4, offset=0
    p.addMessageFragment(new MessageFragment(true, false, true, 7, 4, 4, 0, payload, wrapper));
    NullBasePeerNode peer = pn;

    // Act: totalPacketLength larger than payload by 96 -> overhead/size with size==2
    p.onSent(/*totalPacketLength*/ 100, peer);

    // Assert: onSent(start=0, end=3, overhead=48, peer)
    verify(wrapper, times(1)).onSent(0, 3, 48, peer);
  }

  private void checkPacket(NPFPacket packet, byte[] correctData) {
    byte[] data = new byte[packet.getLength()];
    packet.toBytes(data, 0, null);

    checkEquals(correctData, data);
  }

  static void checkEquals(byte[] correctData, byte[] data) {
    assertEquals(correctData.length, data.length, "Packet lengths differ:");
    for (int i = 0; i < data.length; i++) {
      if (data[i] != correctData[i]) {
        fail(
            "Different values at index "
                + i
                + ": Expected 0x"
                + Integer.toHexString(correctData[i] & 0xFF)
                + ", but was 0x"
                + Integer.toHexString(data[i] & 0xFF));
      }
    }
  }
}
