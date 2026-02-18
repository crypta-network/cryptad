package network.crypta.clients.http.updateableelements;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NotifierFetchListenerTest {

  @Mock private PushDataManager pushManager;

  @Mock private BaseUpdatableElement element;

  @Test
  void onEvent_whenCalled_updatesElementWithIdFromElement() {
    String updaterId = "element-123";
    when(element.getUpdaterId(null)).thenReturn(updaterId);
    NotifierFetchListener listener = new NotifierFetchListener(pushManager, element);

    listener.onEvent();

    verify(element).getUpdaterId(null);
    verify(pushManager).updateElement(updaterId);
    verifyNoMoreInteractions(pushManager, element);
  }

  @Test
  void toString_whenCalled_containsManagerAndElementDetails() {
    when(pushManager.toString()).thenReturn("PushManagerMock");
    when(element.toString()).thenReturn("ElementMock");
    NotifierFetchListener listener = new NotifierFetchListener(pushManager, element);

    String result = listener.toString();

    assertEquals("NotifierFetchListener[pushManager:PushManagerMock,element;ElementMock]", result);
  }
}
