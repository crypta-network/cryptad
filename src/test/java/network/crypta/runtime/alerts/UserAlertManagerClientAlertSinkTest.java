package network.crypta.runtime.alerts;

import network.crypta.client.async.alerts.ClientAlert;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100")
class UserAlertManagerClientAlertSinkTest {

  @Test
  void constructor_whenUserAlertManagerNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new UserAlertManagerClientAlertSink(null));
  }

  @Test
  void post_whenUserAlert_forwardsToUserAlertManager() {
    UserAlertManager userAlertManager = mock(UserAlertManager.class);
    UserAlertManagerClientAlertSink sink = new UserAlertManagerClientAlertSink(userAlertManager);
    UserAlert alert = mock(UserAlert.class);

    sink.post(alert);

    verify(userAlertManager).register(alert);
  }

  @Test
  void post_whenClientAlertIsNotUserAlert_throwsIllegalArgumentException() {
    UserAlertManager userAlertManager = mock(UserAlertManager.class);
    UserAlertManagerClientAlertSink sink = new UserAlertManagerClientAlertSink(userAlertManager);
    ClientAlert alert = new ClientAlert() {};

    assertThrows(IllegalArgumentException.class, () -> sink.post(alert));
    verifyNoInteractions(userAlertManager);
  }

  @Test
  void post_whenClientAlertIsNull_throwsIllegalArgumentException() {
    UserAlertManager userAlertManager = mock(UserAlertManager.class);
    UserAlertManagerClientAlertSink sink = new UserAlertManagerClientAlertSink(userAlertManager);

    assertThrows(IllegalArgumentException.class, () -> sink.post(null));
    verifyNoInteractions(userAlertManager);
  }
}
