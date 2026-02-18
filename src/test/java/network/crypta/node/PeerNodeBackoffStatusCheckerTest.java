package network.crypta.node;

import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PeerNodeBackoffStatusCheckerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerManager peerManager;

  @Test
  void run_whenWeakRefCleared_expectNoInteraction() {
    // Arrange
    PeerNodeBackoffStatusChecker checker =
        new PeerNodeBackoffStatusChecker(new WeakReference<>(null));

    // Act & Assert
    assertDoesNotThrow(checker::run);
  }

  @Test
  @MockitoSettings(strictness = Strictness.LENIENT)
  void run_whenRemovedAndNotInPeers_expectNoUpdate() throws Exception {
    // Arrange
    PeerNode pn = Mockito.mock(PeerNode.class);
    setPeerNodeNodeField(pn, node);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.havePeer(pn)).thenReturn(false);
    when(pn.cachedRemoved()).thenReturn(true);

    PeerNodeBackoffStatusChecker checker =
        new PeerNodeBackoffStatusChecker(new WeakReference<>(pn));

    // Act
    checker.run();

    // Assert
    verify(pn, never()).setPeerNodeStatus(anyLong(), anyBoolean());
  }

  @Test
  void run_whenNotRemovedAndNotInPeers_expectNoUpdate() throws Exception {
    // Arrange
    PeerNode pn = Mockito.mock(PeerNode.class);
    setPeerNodeNodeField(pn, node);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.havePeer(pn)).thenReturn(false);
    when(pn.cachedRemoved()).thenReturn(false);

    PeerNodeBackoffStatusChecker checker =
        new PeerNodeBackoffStatusChecker(new WeakReference<>(pn));

    // Act
    checker.run();

    // Assert
    verify(pn, never()).setPeerNodeStatus(anyLong(), anyBoolean());
  }

  @Test
  void run_whenNotRemovedAndInPeers_expectUpdate() throws Exception {
    // Arrange
    PeerNode pn = Mockito.mock(PeerNode.class);
    setPeerNodeNodeField(pn, node);
    when(node.network().peers()).thenReturn(peerManager);
    when(peerManager.havePeer(pn)).thenReturn(true);
    when(pn.cachedRemoved()).thenReturn(false);

    PeerNodeBackoffStatusChecker checker =
        new PeerNodeBackoffStatusChecker(new WeakReference<>(pn));

    // Act
    checker.run();

    // Assert
    verify(pn, times(1)).setPeerNodeStatus(anyLong(), Mockito.eq(true));
  }

  @SuppressWarnings({"java:S3011"})
  private static void setPeerNodeNodeField(PeerNode pn, Node node)
      throws NoSuchFieldException, IllegalAccessException {
    Field f = PeerNode.class.getDeclaredField("node");
    f.setAccessible(true);
    f.set(pn, node);
  }
}
