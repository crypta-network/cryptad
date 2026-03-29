package network.crypta.clients.http;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.Config;
import network.crypta.config.IntCallback;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.ToadletSymlinkPort;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FProxyRegistrarTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private RuntimePorts runtimePorts;

  @Mock private HighLevelSimpleClient client;
  @Mock private FProxyToadlet fproxy;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private WelcomePagePort welcomePagePort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private WelcomeActionPort welcomeActionPort;
  @Mock private FirstTimeWizardPort firstTimeWizardPort;
  @Mock private SecurityLevelsPort securityLevelsPort;
  @Mock private CoreUpdateActionPort coreUpdateActionPort;
  @Mock private ToadletSymlinkPort toadletSymlinkPort;
  @Mock private TransferAccessPort transferAccess;
  @Mock private SimpleToadletServer server;

  private Config config;

  @BeforeEach
  void setUp() {
    config = new Config();
    SubConfig nodeConfig = config.createSubConfig("node");
    registerBandwidthOption(nodeConfig, "outputBandwidthLimit", 1024);
    registerBandwidthOption(nodeConfig, "inputBandwidthLimit", 2048);
    nodeConfig.finishedInitialization();

    SubConfig alphaConfig = config.createSubConfig("alpha");
    alphaConfig.finishedInitialization();
    SubConfig securityLevelsConfig = config.createSubConfig("security-levels");
    securityLevelsConfig.finishedInitialization();

    when(runtimePorts.queueCompletion()).thenReturn(queueCompletionPort);
    when(runtimePorts.welcomePage()).thenReturn(welcomePagePort);
    when(runtimePorts.darknetConnections()).thenReturn(darknetConnectionsPort);
    when(runtimePorts.darknetMessaging()).thenReturn(darknetMessagingPort);
    when(runtimePorts.lifecycle()).thenReturn(lifecyclePort);
    when(runtimePorts.welcomeAction()).thenReturn(welcomeActionPort);
    when(runtimePorts.firstTimeWizard()).thenReturn(firstTimeWizardPort);
    when(runtimePorts.securityLevels()).thenReturn(securityLevelsPort);
    when(runtimePorts.coreUpdateAction()).thenReturn(coreUpdateActionPort);
    when(runtimePorts.toadletSymlinks()).thenReturn(toadletSymlinkPort);
    when(runtimePorts.transferAccess()).thenReturn(transferAccess);
    when(toadletSymlinkPort.loadConfiguredSymlinks()).thenReturn(List.of());
  }

  @Test
  void maybeCreateFProxyEtc_whenInvoked_registersMenusSetsFProxyAndStartsQueueCompletion() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        new FProxyRegistrarDependencies(client, runtimePorts, config, fproxy), server);

    verify(server)
        .registerMenu("/", FProxyToadlet.CATEGORY_BROWSING, "FProxyToadlet.categoryTitleBrowsing");
    verify(server)
        .registerMenu(
            FProxyToadlet.DOWNLOADS_PATH,
            FProxyToadlet.CATEGORY_QUEUE,
            "FProxyToadlet.categoryTitleQueue");
    verify(server)
        .registerMenu(
            FProxyToadlet.FRIENDS_PATH,
            FProxyToadlet.CATEGORY_FRIENDS,
            "FProxyToadlet.categoryTitleFriends");
    verify(server)
        .registerMenu("/chat/", "FProxyToadlet.categoryChat", "FProxyToadlet.categoryTitleChat");
    verify(server)
        .registerMenu(
            "/alerts/", FProxyToadlet.CATEGORY_STATUS, "FProxyToadlet.categoryTitleStatus");
    verify(server)
        .registerMenu(
            "/seclevels/", FProxyToadlet.CATEGORY_CONFIG, "FProxyToadlet.categoryTitleConfig");

    InOrder queueCompletionOrder = inOrder(queueCompletionPort);
    queueCompletionOrder.verify(queueCompletionPort).ensureTrackingStarted(false);
    queueCompletionOrder.verify(queueCompletionPort).ensureTrackingStarted(true);

    List<RegisteredToadlet> registrations = capturedRegistrations();
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    registered.toadlet() == fproxy
                        && "/".equals(registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    QueueToadlet.PATH_DOWNLOADS.equals(registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    QueueToadlet.PATH_UPLOADS.equals(registered.registration().urlPrefix())));
    assertTrue(
        registrations.stream()
            .anyMatch(
                registered ->
                    FirstTimeWizardToadlet.TOADLET_URL.equals(
                        registered.registration().urlPrefix())));
    RegisteredToadlet wizardRegistration =
        registrations.stream()
            .filter(
                registered ->
                    FirstTimeWizardToadlet.TOADLET_URL.equals(
                        registered.registration().urlPrefix()))
            .findFirst()
            .orElseThrow();
    assertSame(firstTimeWizardPort, readWizardPortField(wizardRegistration.toadlet()));
    RegisteredToadlet symlinkerRegistration =
        registrations.stream()
            .filter(registered -> registered.toadlet() instanceof SymlinkerToadlet)
            .findFirst()
            .orElseThrow();
    assertSame(toadletSymlinkPort, readField(symlinkerRegistration.toadlet(), "symlinkPort"));
    RegisteredToadlet coreActionRegistration =
        registrations.stream()
            .filter(
                registered ->
                    registered.toadlet()
                        instanceof network.crypta.clients.http.updater.CoreActionToadlet)
            .findFirst()
            .orElseThrow();
    assertSame(
        coreUpdateActionPort, readField(coreActionRegistration.toadlet(), "coreUpdateActionPort"));
    RegisteredToadlet fileInsertWizardRegistration =
        registrations.stream()
            .filter(
                registered ->
                    FileInsertWizardToadlet.PATH.equals(registered.registration().urlPrefix()))
            .findFirst()
            .orElseThrow();
    FileInsertWizardToadletRuntimePorts fileInsertWizardRuntimePorts =
        (FileInsertWizardToadletRuntimePorts)
            readField(fileInsertWizardRegistration.toadlet(), "runtimePorts");
    assertSame(securityLevelsPort, fileInsertWizardRuntimePorts.securityLevelsPort());
    RegisteredToadlet bookmarkEditorRegistration =
        registrations.stream()
            .filter(registered -> registered.toadlet() instanceof BookmarkEditorToadlet)
            .findFirst()
            .orElseThrow();
    BookmarkEditorToadletRuntimePorts bookmarkRuntimePorts =
        (BookmarkEditorToadletRuntimePorts)
            readField(bookmarkEditorRegistration.toadlet(), "runtimePorts");
    assertSame(darknetConnectionsPort, bookmarkRuntimePorts.darknetConnectionsPort());
    assertSame(darknetMessagingPort, bookmarkRuntimePorts.darknetMessagingPort());
    verify(runtimePorts, atLeastOnce()).firstTimeWizard();
  }

  @Test
  void maybeCreateFProxyEtc_whenSecurityLevelsSubconfigPresent_skipsSecurityLevelsConfigToadlet() {
    FProxyRegistrar.maybeCreateFProxyEtc(
        new FProxyRegistrarDependencies(client, runtimePorts, config, fproxy), server);

    Set<String> configToadletPrefixes =
        capturedRegistrations().stream()
            .filter(registered -> registered.toadlet() instanceof ConfigToadlet)
            .map(registered -> registered.registration().urlPrefix())
            .collect(Collectors.toSet());

    assertEquals(
        Set.of(FProxyToadlet.CONFIG_PATH + "alpha", FProxyToadlet.CONFIG_PATH + "node"),
        configToadletPrefixes);
    assertFalse(configToadletPrefixes.contains(FProxyToadlet.CONFIG_PATH + "security-levels"));
  }

  private static void registerBandwidthOption(
      SubConfig subConfig, String optionName, int defaultValue) {
    subConfig.register(optionName, defaultValue, optionMeta(), new MemoryIntCallback(defaultValue));
  }

  private static Option.Meta optionMeta() {
    return new Option.Meta(0, false, false, "", "");
  }

  private List<RegisteredToadlet> capturedRegistrations() {
    ArgumentCaptor<Toadlet> toadletCaptor = ArgumentCaptor.forClass(Toadlet.class);
    ArgumentCaptor<ToadletRegistration> registrationCaptor =
        ArgumentCaptor.forClass(ToadletRegistration.class);
    verify(server, atLeastOnce()).register(toadletCaptor.capture(), registrationCaptor.capture());

    List<RegisteredToadlet> registrations = new ArrayList<>();
    List<Toadlet> toadlets = toadletCaptor.getAllValues();
    List<ToadletRegistration> registrationValues = registrationCaptor.getAllValues();
    for (int i = 0; i < toadlets.size(); i++) {
      registrations.add(new RegisteredToadlet(toadlets.get(i), registrationValues.get(i)));
    }
    return registrations;
  }

  private static FirstTimeWizardPort readWizardPortField(Object target) {
    return (FirstTimeWizardPort) readField(target, "wizardPort");
  }

  private static Object readField(Object target, String fieldName) {
    try {
      java.lang.reflect.Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final class MemoryIntCallback extends IntCallback {
    private int value;

    private MemoryIntCallback(int value) {
      this.value = value;
    }

    @Override
    public Integer get() {
      return value;
    }

    @Override
    public void set(Integer value) {
      this.value = value;
    }
  }

  private record RegisteredToadlet(Toadlet toadlet, ToadletRegistration registration) {}
}
