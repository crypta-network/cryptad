package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDefinition;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginFlags;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginVersionPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // JUnit-style names: method_whenCondition_expectOutcome
class PluginDownLoaderOfficialFreenetTest {

  private static final String GROUP = "group";

  private static HighLevelSimpleClient mockHighLevelSimpleClient(HighLevelSimpleClient copy) {
    HighLevelSimpleClient hlsc = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    when(hlsc.copy()).thenReturn(copy);
    return hlsc;
  }

  private static Stream<String> missingPluginNames() {
    return Stream.of(null, "", "SomePlugin");
  }

  @ParameterizedTest
  @MethodSource("missingPluginNames")
  void checkSource_whenNotInOfficialList_expectPluginNotFoundException(String source) {
    // Arrange
    HighLevelSimpleClient hlscCopy = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc = mockHighLevelSimpleClient(hlscCopy);

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PluginManager pluginManager = org.mockito.Mockito.mock(PluginManager.class);
    when(node.services().pluginManager()).thenReturn(pluginManager);
    when(pluginManager.getOfficialPlugin(any())).thenReturn(null);

    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(hlsc, node, false);

    // Act
    PluginNotFoundException ex =
        assertThrows(PluginNotFoundException.class, () -> downloader.checkSource(source));

    // Assert
    assertEquals("Not in the official plugins list: " + source, ex.getMessage());
    verify(node.services(), never()).nodeUpdater();
  }

  @Test
  void checkSource_whenOfficialPluginHasExplicitUri_expectThatUriReturned() throws Exception {
    // Arrange
    HighLevelSimpleClient hlscCopy = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc = mockHighLevelSimpleClient(hlscCopy);

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PluginManager pluginManager = org.mockito.Mockito.mock(PluginManager.class);
    when(node.services().pluginManager()).thenReturn(pluginManager);

    String source = "WebOfTrust";
    FreenetURI explicitUri = org.mockito.Mockito.mock(FreenetURI.class);
    OfficialPluginDescription desc =
        new OfficialPluginDescription(
            new OfficialPluginDefinition(source, GROUP, explicitUri),
            new OfficialPluginVersionPolicy(-1, 123, false),
            new OfficialPluginFlags(false, false, false, false, false, false));
    when(pluginManager.getOfficialPlugin(source)).thenReturn(desc);

    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(hlsc, node, false);

    // Act
    FreenetURI out = downloader.checkSource(source);

    // Assert
    assertSame(explicitUri, out);
    verify(node.services(), never()).nodeUpdater();
  }

  @ParameterizedTest
  @ValueSource(longs = {-1, 0, 1, 42, Long.MAX_VALUE})
  void checkSource_whenOfficialPluginHasNullUri_expectDerivedUriFromUpdateUsk(
      long recommendedVersion) throws Exception {
    // Arrange
    HighLevelSimpleClient hlscCopy = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc = mockHighLevelSimpleClient(hlscCopy);

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PluginManager pluginManager = org.mockito.Mockito.mock(PluginManager.class);
    when(node.services().pluginManager()).thenReturn(pluginManager);

    NodeUpdateManager nodeUpdateManager = org.mockito.Mockito.mock(NodeUpdateManager.class);
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);

    String source = "UPnP";
    OfficialPluginDescription desc =
        new OfficialPluginDescription(
            new OfficialPluginDefinition(source, GROUP, null),
            new OfficialPluginVersionPolicy(-1, recommendedVersion, false),
            new OfficialPluginFlags(false, false, false, false, false, false));
    when(pluginManager.getOfficialPlugin(source)).thenReturn(desc);

    FreenetURI updateUsk = org.mockito.Mockito.mock(FreenetURI.class);
    FreenetURI withDocName = org.mockito.Mockito.mock(FreenetURI.class);
    FreenetURI withEdition = org.mockito.Mockito.mock(FreenetURI.class);
    FreenetURI expected = org.mockito.Mockito.mock(FreenetURI.class);
    when(nodeUpdateManager.getURI()).thenReturn(updateUsk);
    when(updateUsk.setDocName(source)).thenReturn(withDocName);
    when(withDocName.setSuggestedEdition(recommendedVersion)).thenReturn(withEdition);
    when(withEdition.sskForUSK()).thenReturn(expected);

    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(hlsc, node, false);

    // Act
    FreenetURI out = downloader.checkSource(source);

    // Assert
    assertSame(expected, out);
    verify(nodeUpdateManager).getURI();
    verify(updateUsk).setDocName(source);
    verify(withDocName).setSuggestedEdition(recommendedVersion);
    verify(withEdition).sskForUSK();
  }

  @ParameterizedTest
  @ValueSource(strings = {"ExamplePlugin", "ExamplePlugin.jar", "dir/ExamplePlugin"})
  void getPluginName_whenCalled_expectJarSuffixAppended(String source) {
    // Arrange
    HighLevelSimpleClient hlscCopy = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc = mockHighLevelSimpleClient(hlscCopy);

    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(
            hlsc,
            org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
            false);

    // Act
    String name = downloader.getPluginName(source);

    // Assert
    assertEquals(source + ".jar", name);
  }

  @Test
  void setSource_whenOfficialPluginResolves_expectStoresUriAndReturnsDerivedName()
      throws Exception {
    // Arrange
    HighLevelSimpleClient hlscCopy = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc = mockHighLevelSimpleClient(hlscCopy);

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PluginManager pluginManager = org.mockito.Mockito.mock(PluginManager.class);
    when(node.services().pluginManager()).thenReturn(pluginManager);

    String source = "HelloWorld";
    FreenetURI uri = org.mockito.Mockito.mock(FreenetURI.class);
    OfficialPluginDescription desc =
        new OfficialPluginDescription(
            new OfficialPluginDefinition(source, GROUP, uri),
            new OfficialPluginVersionPolicy(-1, -1, false),
            new OfficialPluginFlags(false, false, false, false, false, false));
    when(pluginManager.getOfficialPlugin(source)).thenReturn(desc);

    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(hlsc, node, false);

    // Act
    String pluginName = downloader.setSource(source);

    // Assert
    assertEquals(source + ".jar", pluginName);
    assertSame(uri, downloader.getSource());
  }

  @Test
  void isOfficialPluginLoader_whenCalled_expectTrue() {
    // Arrange
    HighLevelSimpleClient hlscCopy = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc = mockHighLevelSimpleClient(hlscCopy);

    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(
            hlsc,
            org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS),
            false);

    // Act + Assert
    assertTrue(downloader.isOfficialPluginLoader());
    assertTrue(downloader.isLoadingFromFreenet());
  }

  @Test
  void getRetryDownloader_whenCalled_expectNewOfficialDownloaderWithDesperateEnabled() {
    // Arrange
    HighLevelSimpleClient hlscCopy1 = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlscCopy2 = org.mockito.Mockito.mock(HighLevelSimpleClient.class);
    HighLevelSimpleClient hlsc =
        mockHighLevelSimpleClient(
            hlscCopy1); // initial constructor will use hlsc.copy() -> hlscCopy1
    when(hlscCopy1.copy()).thenReturn(hlscCopy2); // retry constructor copies hlscCopy1 -> hlscCopy2

    Node node = org.mockito.Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    PluginDownLoaderOfficialFreenet downloader =
        new PluginDownLoaderOfficialFreenet(hlsc, node, false);

    // Act
    PluginDownLoader<FreenetURI> retry = downloader.getRetryDownloader();

    // Assert
    assertNotSame(downloader, retry);
    assertInstanceOf(PluginDownLoaderOfficialFreenet.class, retry);
    PluginDownLoaderOfficialFreenet retryTyped = (PluginDownLoaderOfficialFreenet) retry;
    assertTrue(retryTyped.desperate);
    assertSame(node, retryTyped.node);
    assertSame(hlscCopy2, retryTyped.hlsc);
    verify(hlsc, times(1)).copy();
    verify(hlscCopy1, times(1)).copy();
  }
}
