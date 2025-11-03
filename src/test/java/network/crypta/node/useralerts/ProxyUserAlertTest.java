package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class ProxyUserAlertTest {

  @Mock private UserAlertManager manager;

  @Mock private UserAlert underlying;

  @Test
  void setAlert_whenAutoRegisterTrue_registersOnNullToNonNullTransition() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, true);

    // Act
    proxy.setAlert(underlying);

    // Assert
    verify(manager, times(1)).register(proxy);
    verifyNoMoreInteractions(manager);
  }

  @Test
  void setAlert_whenAutoRegisterTrue_unregistersOnSetNull_evenIfOldNull() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, true);

    // Act
    proxy.setAlert(null);

    // Assert
    verify(manager, times(1)).unregister(proxy);
    verifyNoMoreInteractions(manager);
  }

  @Test
  void setAlert_whenAutoRegisterTrue_unregistersOnNonNullToNullTransition() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, true);
    proxy.setAlert(underlying);
    verify(manager, times(1)).register(proxy);

    // Act
    proxy.setAlert(null);

    // Assert
    verify(manager, times(1)).unregister(proxy);
    verifyNoMoreInteractions(manager);
  }

  @Test
  void setAlert_whenAutoRegisterTrue_doesNotRegisterWhenReplacingNonNullWithNonNull() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, true);
    proxy.setAlert(underlying);
    verify(manager, times(1)).register(proxy);
    UserAlert another = mock(UserAlert.class);

    // Act
    proxy.setAlert(another);

    // Assert
    verifyNoMoreInteractions(manager);
  }

  @Test
  void setAlert_whenAutoRegisterFalse_neverTouchesManager() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);

    // Act
    proxy.setAlert(underlying);
    proxy.setAlert(null);

    // Assert
    verifyNoInteractions(manager);
  }

  @Test
  void anchor_alwaysStartsWithPrefixAndMatchesHashCode() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);
    String expected = "anchor:" + proxy.hashCode();

    // Act
    String anchor = proxy.anchor();

    // Assert
    assertNotNull(anchor);
    assertTrue(anchor.startsWith("anchor:"));
    assertEquals(expected, anchor);
  }

  @Test
  void isValid_whenUnderlyingNull_returnsFalse() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);

    // Act & Assert
    assertFalse(proxy.isValid());
  }

  @Test
  void isEventNotification_whenUnderlyingNull_returnsFalse() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);

    // Act & Assert
    assertFalse(proxy.isEventNotification());
  }

  @Test
  void isValidBoolean_whenUnderlyingNull_doesNothing() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);

    // Act
    proxy.isValid(true);
    proxy.isValid(false);

    // Assert (no exception, and no interaction with manager or underlying)
    verifyNoInteractions(manager);
    verifyNoInteractions(underlying);
  }

  @Test
  void delegatedGetters_whenUnderlyingPresent_forwardToUnderlying() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);
    HTMLNode html = new HTMLNode("div");

    when(underlying.userCanDismiss()).thenReturn(true);
    when(underlying.getTitle()).thenReturn("T");
    when(underlying.getText()).thenReturn("Body");
    when(underlying.getShortText()).thenReturn("Short");
    when(underlying.getHTMLText()).thenReturn(html);
    when(underlying.getPriorityClass()).thenReturn(UserAlert.WARNING);
    when(underlying.isValid()).thenReturn(true);
    when(underlying.dismissButtonText()).thenReturn("Dismiss");
    when(underlying.shouldUnregisterOnDismiss()).thenReturn(true);
    when(underlying.isEventNotification()).thenReturn(true);

    proxy.setAlert(underlying);

    // Act & Assert
    assertTrue(proxy.userCanDismiss());
    assertEquals("T", proxy.getTitle());
    assertEquals("Body", proxy.getText());
    assertEquals("Short", proxy.getShortText());
    assertSame(html, proxy.getHTMLText());
    assertEquals(UserAlert.WARNING, proxy.getPriorityClass());
    assertTrue(proxy.isValid());
    assertEquals("Dismiss", proxy.dismissButtonText());
    assertTrue(proxy.shouldUnregisterOnDismiss());
    assertTrue(proxy.isEventNotification());
  }

  @Test
  void isValidBoolean_whenUnderlyingPresent_forwardsValue() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);
    proxy.setAlert(underlying);
    doNothing().when(underlying).isValid(true);
    doNothing().when(underlying).isValid(false);

    // Act
    proxy.isValid(true);
    proxy.isValid(false);

    // Assert
    verify(underlying, times(1)).isValid(true);
    verify(underlying, times(1)).isValid(false);
    verifyNoMoreInteractions(underlying);
  }

  @Test
  void onDismiss_whenUnderlyingPresent_forwardsCall() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);
    proxy.setAlert(underlying);
    doNothing().when(underlying).onDismiss();

    // Act
    proxy.onDismiss();

    // Assert
    verify(underlying, times(1)).onDismiss();
    verifyNoMoreInteractions(underlying);
  }

  @Test
  void delegatedMethods_whenUnderlyingNull_throwNullPointerException() {
    // Arrange
    ProxyUserAlert proxy = new ProxyUserAlert(manager, false);

    // Act & Assert
    assertThrows(NullPointerException.class, proxy::userCanDismiss);
    assertThrows(NullPointerException.class, proxy::getTitle);
    assertThrows(NullPointerException.class, proxy::getText);
    assertThrows(NullPointerException.class, proxy::getShortText);
    assertThrows(NullPointerException.class, proxy::getHTMLText);
    assertThrows(NullPointerException.class, proxy::getPriorityClass);
    assertThrows(NullPointerException.class, proxy::dismissButtonText);
    assertThrows(NullPointerException.class, proxy::shouldUnregisterOnDismiss);
  }
}
