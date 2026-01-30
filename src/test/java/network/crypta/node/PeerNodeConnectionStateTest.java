package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.io.AddressTracker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerNodeConnectionStateTest {

  @Test
  void constructor_whenLastConnectedTimeProvided_reportsLastConnectedTime() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(1234L);

    long lastConnected = state.timeLastConnected(9999L);

    assertFalse(state.isConnected());
    assertEquals(1234L, lastConnected);
  }

  @Test
  void constructor_whenLastConnectedTimeZero_reportsNeverConnected() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);

    long lastConnected = state.timeLastConnected(5000L);

    assertFalse(state.isConnected());
    assertEquals(-1L, lastConnected);
  }

  @Test
  void setConnected_whenTransitionToTrue_returnsPreviousFalseAndUpdatesTime() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);

    boolean previous = state.setConnected(true, 100L);
    long lastConnected = state.timeLastConnected(200L);

    assertFalse(previous);
    assertTrue(state.isConnected());
    assertEquals(200L, lastConnected);
  }

  @Test
  void setConnected_whenTransitionToFalse_preservesLastTrueTime() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);
    state.setConnected(true, 111L);

    boolean previous = state.setConnected(false, 222L);
    long lastConnected = state.timeLastConnected(333L);

    assertTrue(previous);
    assertFalse(state.isConnected());
    assertEquals(111L, lastConnected);
  }

  @Test
  void notifyStatusChangeListeners_whenMultipleInvokesEachListenerOnce() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);
    PeerManager.PeerStatusChangeListener listenerOne =
        Mockito.mock(PeerManager.PeerStatusChangeListener.class);
    PeerManager.PeerStatusChangeListener listenerTwo =
        Mockito.mock(PeerManager.PeerStatusChangeListener.class);

    state.registerStatusChangeListener(listenerOne);
    state.registerStatusChangeListener(listenerTwo);
    state.notifyStatusChangeListeners();

    verify(listenerOne, times(1)).onPeerStatusChange();
    verify(listenerTwo, times(1)).onPeerStatusChange();
  }

  @ParameterizedTest
  @EnumSource(
      value = AddressTracker.Status.class,
      names = {"DONT_KNOW", "DEFINITELY_NATED", "MAYBE_NATED", "MAYBE_PORT_FORWARDED"})
  void isBurstOnly_whenStatusNotForwarded_returnsFalseAndDoesNotUseRandom(
      AddressTracker.Status status) {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);
    OutgoingPacketMangler outgoingMangler = Mockito.mock(OutgoingPacketMangler.class);
    Random random = Mockito.mock(Random.class);
    when(outgoingMangler.getConnectivityStatus()).thenReturn(status);

    boolean result = state.isBurstOnly(outgoingMangler, random);

    assertFalse(result);
    verifyNoInteractions(random);
  }

  @Test
  void isBurstOnly_whenDefinitelyPortForwardedAndRandomZero_returnsTrue() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);
    OutgoingPacketMangler outgoingMangler = Mockito.mock(OutgoingPacketMangler.class);
    Random random = Mockito.mock(Random.class);
    when(outgoingMangler.getConnectivityStatus())
        .thenReturn(AddressTracker.Status.DEFINITELY_PORT_FORWARDED);
    when(random.nextInt(20)).thenReturn(0);

    boolean result = state.isBurstOnly(outgoingMangler, random);

    assertTrue(result);
    verify(random, times(1)).nextInt(20);
  }

  @Test
  void isBurstOnly_whenDefinitelyPortForwardedAndRandomNonZero_returnsFalse() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);
    OutgoingPacketMangler outgoingMangler = Mockito.mock(OutgoingPacketMangler.class);
    Random random = Mockito.mock(Random.class);
    when(outgoingMangler.getConnectivityStatus())
        .thenReturn(AddressTracker.Status.DEFINITELY_PORT_FORWARDED);
    when(random.nextInt(20)).thenReturn(1);

    boolean result = state.isBurstOnly(outgoingMangler, random);

    assertFalse(result);
    verify(random, times(1)).nextInt(20);
  }

  @Test
  void isBurstOnly_whenCalledWithinBurstPeriod_usesCachedDecision() {
    PeerNodeConnectionState state = new PeerNodeConnectionState(0L);
    OutgoingPacketMangler outgoingMangler = Mockito.mock(OutgoingPacketMangler.class);
    Random random = Mockito.mock(Random.class);
    when(outgoingMangler.getConnectivityStatus())
        .thenReturn(AddressTracker.Status.DEFINITELY_PORT_FORWARDED);

    setPrivateField(state, "burstNow", true);
    setPrivateField(state, "timeSetBurstNow", Long.MAX_VALUE);

    boolean result = state.isBurstOnly(outgoingMangler, random);

    assertTrue(result);
    verifyNoInteractions(random);
  }

  private static void setPrivateField(Object target, String name, Object value) {
    try {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException ex) {
      throw new LinkageError("Failed to set field: " + name, ex);
    }
  }
}
