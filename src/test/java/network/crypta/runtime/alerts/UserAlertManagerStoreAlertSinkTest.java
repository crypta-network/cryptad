package network.crypta.runtime.alerts;

import java.lang.reflect.Method;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.L10nTestUtils;
import network.crypta.l10n.NodeL10n;
import network.crypta.store.alerts.StoreMaintenanceAlertKind;
import network.crypta.store.alerts.StoreMaintenanceAlertSource;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class UserAlertManagerStoreAlertSinkTest {

  @Mock private UserAlertManager userAlertManager;

  private BaseL10n originalBase;

  @BeforeEach
  void setUp() throws ReflectiveOperationException {
    originalBase = NodeL10n.getBase();
    installBase(L10nTestUtils.createL10n(LANGUAGE.ENGLISH));
  }

  @AfterEach
  void tearDown() throws ReflectiveOperationException {
    installBase(originalBase);
  }

  @Test
  void constructor_whenUserAlertManagerNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new UserAlertManagerStoreAlertSink(null));
  }

  @Test
  void register_whenResizeAlert_registersLocalizedNonDismissableErrorAlert() {
    UserAlertManagerStoreAlertSink sink = new UserAlertManagerStoreAlertSink(userAlertManager);
    MutableAlertSource source =
        new MutableAlertSource(
            "store-cleaner-chk",
            "CHK",
            StoreMaintenanceAlertKind.RESIZE_PROGRESS,
            7,
            12,
            false,
            true);

    sink.register(source);

    UserAlert alert = captureRegisteredAlert();

    assertEquals(source.anchor(), alert.anchor());
    assertEquals(localizedTitle(source), alert.getTitle());
    assertEquals(localizedProgress("shortResizeProgress", source), alert.getShortText());
    assertEquals(localizedProgress("longResizeProgress", source), alert.getText());
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
    assertFalse(alert.userCanDismiss());
    assertTrue(alert.shouldUnregisterOnDismiss());
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
    assertTrue(alert.isValid());
    assertFalse(alert.isEventNotification());

    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    assertEquals("#", html.getName());
    assertEquals(alert.getText(), html.getContent());
  }

  @Test
  void register_whenRebuildAlertWithNewSlotFilter_usesNewFormatTextAndTracksDynamicValidity() {
    UserAlertManagerStoreAlertSink sink = new UserAlertManagerStoreAlertSink(userAlertManager);
    MutableAlertSource source =
        new MutableAlertSource(
            "store-cleaner-ssk",
            "SSK",
            StoreMaintenanceAlertKind.REBUILD_PROGRESS,
            3,
            9,
            true,
            true);

    sink.register(source);

    UserAlert alert = captureRegisteredAlert();

    assertEquals(localizedProgress("shortRebuildProgressNew", source), alert.getShortText());
    assertEquals(localizedProgress("longRebuildProgressNew", source), alert.getText());

    alert.isValid(false);
    assertTrue(alert.isValid());

    source.valid = false;
    assertFalse(alert.isValid());
    assertDoesNotThrow(alert::onDismiss);
  }

  @Test
  void register_whenRebuildAlertWithoutNewSlotFilter_usesLegacyRebuildText() {
    UserAlertManagerStoreAlertSink sink = new UserAlertManagerStoreAlertSink(userAlertManager);
    MutableAlertSource source =
        new MutableAlertSource(
            "store-cleaner-pubkey",
            "PubKey",
            StoreMaintenanceAlertKind.REBUILD_PROGRESS,
            11,
            40,
            false,
            true);

    sink.register(source);

    UserAlert alert = captureRegisteredAlert();

    assertEquals(localizedProgress("shortRebuildProgress", source), alert.getShortText());
    assertEquals(localizedProgress("longRebuildProgress", source), alert.getText());
  }

  @Test
  void register_whenSourceNull_throwsNullPointerException() {
    UserAlertManagerStoreAlertSink sink = new UserAlertManagerStoreAlertSink(userAlertManager);

    assertThrows(NullPointerException.class, () -> sink.register(null));

    verifyNoInteractions(userAlertManager);
  }

  private UserAlert captureRegisteredAlert() {
    ArgumentCaptor<UserAlert> captor = ArgumentCaptor.forClass(UserAlert.class);
    verify(userAlertManager).register(captor.capture());
    return captor.getValue();
  }

  private static String localizedTitle(StoreMaintenanceAlertSource source) {
    return NodeL10n.getBase()
        .getString(
            "SaltedHashCryptaStore.cleanerAlertTitle",
            new String[] {"name"},
            new String[] {source.storeName()});
  }

  private static String localizedProgress(String key, StoreMaintenanceAlertSource source) {
    return NodeL10n.getBase()
        .getString(
            "SaltedHashCryptaStore." + key,
            new String[] {"name", "processed", "total"},
            new String[] {
              source.storeName(), String.valueOf(source.processed()), String.valueOf(source.total())
            });
  }

  private static void installBase(BaseL10n base) throws ReflectiveOperationException {
    Method setBase = NodeL10n.class.getDeclaredMethod("setBase", BaseL10n.class);
    setBase.setAccessible(true);
    setBase.invoke(null, base);
  }

  private static final class MutableAlertSource implements StoreMaintenanceAlertSource {
    private final String anchor;
    private final String storeName;
    private final StoreMaintenanceAlertKind kind;
    private final long processed;
    private final long total;
    private final boolean newSlotFilter;
    private boolean valid;

    private MutableAlertSource(
        String anchor,
        String storeName,
        StoreMaintenanceAlertKind kind,
        long processed,
        long total,
        boolean newSlotFilter,
        boolean valid) {
      this.anchor = anchor;
      this.storeName = storeName;
      this.kind = kind;
      this.processed = processed;
      this.total = total;
      this.newSlotFilter = newSlotFilter;
      this.valid = valid;
    }

    @Override
    public String anchor() {
      return anchor;
    }

    @Override
    public String storeName() {
      return storeName;
    }

    @Override
    public StoreMaintenanceAlertKind kind() {
      return kind;
    }

    @Override
    public long processed() {
      return processed;
    }

    @Override
    public long total() {
      return total;
    }

    @Override
    public boolean newSlotFilter() {
      return newSlotFilter;
    }

    @Override
    public boolean isValid() {
      return valid;
    }
  }
}
