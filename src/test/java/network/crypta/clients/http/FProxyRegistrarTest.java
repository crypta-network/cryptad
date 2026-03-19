package network.crypta.clients.http;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;
import network.crypta.support.api.IntCallback;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
  private NodeClientCore core;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private RuntimePorts runtimePorts;

  @Mock private HighLevelSimpleClient client;
  @Mock private FetchContext fetchContext;
  @Mock private RandomSource randomSource;
  @Mock private ClientEndpoints endpoints;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private WelcomePagePort welcomePagePort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private WelcomeActionPort welcomeActionPort;
  @Mock private SimpleToadletServer server;

  private Config config;
  private SubConfig nodeConfig;

  @BeforeEach
  void setUp() {
    config = new Config();
    nodeConfig = config.createSubConfig("node");
    registerBandwidthOption(nodeConfig, "outputBandwidthLimit", 1024);
    registerBandwidthOption(nodeConfig, "inputBandwidthLimit", 2048);
    nodeConfig.finishedInitialization();

    SubConfig alphaConfig = config.createSubConfig("alpha");
    alphaConfig.finishedInitialization();
    SubConfig securityLevelsConfig = config.createSubConfig("security-levels");
    securityLevelsConfig.finishedInitialization();

    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
    when(core.getRuntimePorts()).thenReturn(runtimePorts);
    when(core.getRandom()).thenReturn(randomSource);
    when(core.getClientContext())
        .thenReturn(org.mockito.Mockito.mock(network.crypta.client.async.ClientContext.class));
    when(core.getEndpoints()).thenReturn(endpoints);
    when(client.getFetchContext()).thenReturn(fetchContext);
    when(runtimePorts.queueCompletion()).thenReturn(queueCompletionPort);
    when(runtimePorts.welcomePage()).thenReturn(welcomePagePort);
    when(runtimePorts.darknetConnections()).thenReturn(darknetConnectionsPort);
    when(runtimePorts.lifecycle()).thenReturn(lifecyclePort);
    when(runtimePorts.welcomeAction()).thenReturn(welcomeActionPort);
  }

  @Test
  void maybeCreateFProxyEtc_whenInvoked_registersMenusSetsFProxyAndStartsQueueCompletion() {
    FProxyRegistrar.maybeCreateFProxyEtc(core, node, config, server);

    ArgumentCaptor<byte[]> randomCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(randomSource).nextBytes(randomCaptor.capture());
    assertSame(FProxyToadlet.random, randomCaptor.getValue());
    assertEquals(32, randomCaptor.getValue().length);

    ArgumentCaptor<FProxyToadlet> fproxyCaptor = ArgumentCaptor.forClass(FProxyToadlet.class);
    verify(endpoints).setFProxy(fproxyCaptor.capture());
    FProxyToadlet fproxyToadlet = fproxyCaptor.getValue();

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
                    registered.toadlet() == fproxyToadlet
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
  }

  @Test
  void maybeCreateFProxyEtc_whenSecurityLevelsSubconfigPresent_skipsSecurityLevelsConfigToadlet() {
    FProxyRegistrar.maybeCreateFProxyEtc(core, node, config, server);

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

  @Test
  void legacyCurrentBandwidthLimits_whenOutputBandwidthLimitIsDefault_returnsNull()
      throws Exception {
    BandwidthLimit bandwidthLimit = invokeLegacyCurrentBandwidthLimits(config, node);

    assertNull(bandwidthLimit);
  }

  @Test
  void legacyCurrentBandwidthLimits_whenOutputBandwidthLimitIsConfigured_returnsCurrentLimit()
      throws Exception {
    nodeConfig.set("outputBandwidthLimit", "8192");
    when(node.network().inputBandwidthLimit()).thenReturn(2048);
    when(node.network().outputBandwidthLimit()).thenReturn(4096);

    BandwidthLimit bandwidthLimit = invokeLegacyCurrentBandwidthLimits(config, node);

    assertNotNull(bandwidthLimit);
    assertEquals(2048L, bandwidthLimit.downBytes);
    assertEquals(4096L, bandwidthLimit.upBytes);
    assertEquals("bandwidthCurrent", bandwidthLimit.descriptionKey);
    assertFalse(bandwidthLimit.maybeDefault);
  }

  private static void registerBandwidthOption(
      SubConfig subConfig, String optionName, int defaultValue) {
    subConfig.register(optionName, defaultValue, optionMeta(), new MemoryIntCallback(defaultValue));
  }

  private static Option.Meta optionMeta() {
    return new Option.Meta(0, false, false, "", "");
  }

  private BandwidthLimit invokeLegacyCurrentBandwidthLimits(Config config, Node node)
      throws Exception {
    Method method =
        FProxyRegistrar.class.getDeclaredMethod(
            "legacyCurrentBandwidthLimits", Config.class, Node.class);
    method.setAccessible(true);
    return (BandwidthLimit) method.invoke(null, config, node);
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
