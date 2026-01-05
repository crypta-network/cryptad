package network.crypta.node.updater

import java.io.File
import java.net.URI
import java.nio.file.Path
import network.crypta.client.HighLevelSimpleClient
import network.crypta.clients.http.PageMaker
import network.crypta.clients.http.PageNode
import network.crypta.clients.http.ToadletContext
import network.crypta.fs.AppEnv
import network.crypta.node.Node
import network.crypta.support.HTMLNode
import network.crypta.support.MultiValueTable
import network.crypta.support.api.HTTPRequest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.io.TempDir
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.*
import org.mockito.Mockito.*
import org.mockito.junit.jupiter.MockitoExtension

@ExtendWith(MockitoExtension::class)
@Suppress("java:S100")
internal class CoreActionToadletTest {
  @TempDir private lateinit var tempDir: Path

  @Test
  internal fun path_whenCalled_expectCoreUpdatePath() {
    val toadlet =
      CoreActionToadlet(
        mock(HighLevelSimpleClient::class.java),
        mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS),
      )

    assertEquals(CORE_UPDATE_PATH, toadlet.path())
  }

  @Test
  internal fun handleMethodGET_whenCalled_expectRedirectToAlerts() {
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet =
      CoreActionToadlet(
        mock(HighLevelSimpleClient::class.java),
        mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS),
      )

    doNothing().`when`(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L))

    toadlet.handleMethodGET(URI("http://localhost/core-update/"), request, ctx)

    @Suppress("UNCHECKED_CAST")
    val headersCaptor =
      ArgumentCaptor.forClass(MultiValueTable::class.java)
        as ArgumentCaptor<MultiValueTable<String, String>>
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L))
    assertEquals("/alerts/", headersCaptor.value.getFirst("Location"))
  }

  @Test
  internal fun handleMethodPOST_whenFormPasswordInvalid_expectNoRedirect() {
    val client = mock(HighLevelSimpleClient::class.java)
    val node = mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet = CoreActionToadlet(client, node)

    `when`(ctx.checkFormPassword(request)).thenReturn(false)

    toadlet.handleMethodPOST(URI("http://localhost/core-update/"), request, ctx)

    verify(node, never()).services()
    verify(ctx, never()).sendReplyHeaders(anyInt(), anyString(), any(), any(), anyLong())
    verify(ctx, never())
      .sendReplyHeaders(anyInt(), anyString(), any(), any(), anyLong(), anyBoolean())
  }

  @Test
  internal fun handleMethodPOST_whenCoreUpdaterMissing_expectRedirect() {
    val client = mock(HighLevelSimpleClient::class.java)
    val node = mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val services = mock(network.crypta.node.subsystem.NodeServicesSubsystem::class.java)
    val nodeUpdater = mock(NodeUpdateManager::class.java)
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet = CoreActionToadlet(client, node)

    `when`(ctx.checkFormPassword(request)).thenReturn(true)
    `when`(node.services()).thenReturn(services)
    `when`(services.nodeUpdater()).thenReturn(nodeUpdater)
    `when`(nodeUpdater.coreUpdater).thenReturn(null)
    doNothing().`when`(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L))

    toadlet.handleMethodPOST(URI("http://localhost/core-update/"), request, ctx)

    @Suppress("UNCHECKED_CAST")
    val headersCaptor =
      ArgumentCaptor.forClass(MultiValueTable::class.java)
        as ArgumentCaptor<MultiValueTable<String, String>>
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L))
    assertEquals("/alerts/", headersCaptor.value.getFirst("Location"))
  }

  @Test
  internal fun handleMethodPOST_whenDownloadAction_expectStartDownloadAndRedirect() {
    val client = mock(HighLevelSimpleClient::class.java)
    val node = mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val services = mock(network.crypta.node.subsystem.NodeServicesSubsystem::class.java)
    val nodeUpdater = mock(NodeUpdateManager::class.java)
    val coreUpdater = mock(CoreUpdater::class.java)
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet = CoreActionToadlet(client, node)

    `when`(ctx.checkFormPassword(request)).thenReturn(true)
    `when`(node.services()).thenReturn(services)
    `when`(services.nodeUpdater()).thenReturn(nodeUpdater)
    `when`(nodeUpdater.coreUpdater).thenReturn(coreUpdater)
    `when`(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("download")
    doNothing().`when`(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), isNull(), eq(0L))

    toadlet.handleMethodPOST(URI("http://localhost/core-update/"), request, ctx)

    verify(coreUpdater).startDownloadFromUI()
    @Suppress("UNCHECKED_CAST")
    val headersCaptor =
      ArgumentCaptor.forClass(MultiValueTable::class.java)
        as ArgumentCaptor<MultiValueTable<String, String>>
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L))
    assertEquals("/alerts/", headersCaptor.value.getFirst("Location"))
  }

  @Test
  internal fun handleMethodPOST_whenInstallPathInvalid_expectFailurePage() {
    val client = mock(HighLevelSimpleClient::class.java)
    val node = mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val services = mock(network.crypta.node.subsystem.NodeServicesSubsystem::class.java)
    val nodeUpdater = mock(NodeUpdateManager::class.java)
    val coreUpdater = mock(CoreUpdater::class.java)
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet = CoreActionToadlet(client, node)
    val baseDir = tempDir.resolve("node").toFile()
    val invalidPath = tempDir.resolve("outside/installer.deb").toFile().absolutePath

    baseDir.mkdirs()
    `when`(ctx.checkFormPassword(request)).thenReturn(true)
    `when`(node.services()).thenReturn(services)
    `when`(services.nodeUpdater()).thenReturn(nodeUpdater)
    `when`(nodeUpdater.coreUpdater).thenReturn(coreUpdater)
    `when`(node.nodeDir).thenReturn(baseDir)
    `when`(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("install")
    `when`(request.getPartAsStringFailsafe(eq("path"), anyInt())).thenReturn(invalidPath)

    stubHtmlContext(ctx)

    toadlet.handleMethodPOST(URI("http://localhost/core-update/"), request, ctx)

    verify(ctx)
      .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong())
    verify(ctx).writeData(any(), anyInt(), anyInt())
  }

  @Test
  internal fun handleMethodPOST_whenInstallPathValidInServiceMode_expectFailurePage() {
    val client = mock(HighLevelSimpleClient::class.java)
    val node = mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val services = mock(network.crypta.node.subsystem.NodeServicesSubsystem::class.java)
    val nodeUpdater = mock(NodeUpdateManager::class.java)
    val coreUpdater = mock(CoreUpdater::class.java)
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet = CoreActionToadlet(client, node)
    val baseDir = tempDir.resolve("node").toFile()
    val updatesDir = File(baseDir, "updates/core")
    val installer = File(updatesDir, "cryptad.deb")

    updatesDir.mkdirs()
    installer.writeText("dummy")
    `when`(ctx.checkFormPassword(request)).thenReturn(true)
    `when`(node.services()).thenReturn(services)
    `when`(services.nodeUpdater()).thenReturn(nodeUpdater)
    `when`(nodeUpdater.coreUpdater).thenReturn(coreUpdater)
    `when`(node.nodeDir).thenReturn(baseDir)
    `when`(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("install")
    `when`(request.getPartAsStringFailsafe(eq("path"), anyInt())).thenReturn(installer.absolutePath)

    val appEnv = mock(AppEnv::class.java)
    `when`(appEnv.osKind()).thenReturn(AppEnv.OsKind.LINUX)
    `when`(appEnv.isServiceMode()).thenReturn(true)
    `when`(appEnv.onPath(anyString())).thenReturn(false)
    replaceAppEnv(toadlet, appEnv)

    stubHtmlContext(ctx)

    toadlet.handleMethodPOST(URI("http://localhost/core-update/"), request, ctx)

    verify(ctx)
      .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong())
    verify(ctx).writeData(any(), anyInt(), anyInt())
  }

  @Test
  internal fun handleMethodPOST_whenOpenStoreUnknown_expectFailurePage() {
    val client = mock(HighLevelSimpleClient::class.java)
    val node = mock(Node::class.java, org.mockito.Answers.RETURNS_DEEP_STUBS)
    val services = mock(network.crypta.node.subsystem.NodeServicesSubsystem::class.java)
    val nodeUpdater = mock(NodeUpdateManager::class.java)
    val coreUpdater = mock(CoreUpdater::class.java)
    val ctx = mock(ToadletContext::class.java)
    val request = mock(HTTPRequest::class.java)
    val toadlet = CoreActionToadlet(client, node)

    `when`(ctx.checkFormPassword(request)).thenReturn(true)
    `when`(node.services()).thenReturn(services)
    `when`(services.nodeUpdater()).thenReturn(nodeUpdater)
    `when`(nodeUpdater.coreUpdater).thenReturn(coreUpdater)
    `when`(request.getPartAsStringFailsafe(eq("action"), anyInt())).thenReturn("openStore")
    `when`(request.getPartAsStringFailsafe(eq("kind"), anyInt())).thenReturn("unknown")
    `when`(request.getPartAsStringFailsafe(eq("id"), anyInt())).thenReturn("")
    `when`(request.getPartAsStringFailsafe(eq("url"), anyInt())).thenReturn("")

    stubHtmlContext(ctx)

    toadlet.handleMethodPOST(URI("http://localhost/core-update/"), request, ctx)

    verify(ctx)
      .sendReplyHeaders(eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong())
    verify(ctx).writeData(any(), anyInt(), anyInt())
  }

  private fun stubHtmlContext(ctx: ToadletContext) {
    val pageMaker = mock(PageMaker::class.java)
    val pageNode = mock(PageNode::class.java)
    val contentNode = HTMLNode("div")
    val infoboxNode = HTMLNode("div")

    `when`(ctx.pageMaker).thenReturn(pageMaker)
    `when`(pageMaker.getPageNode(anyString(), eq(ctx), any(PageMaker.RenderParameters::class.java)))
      .thenReturn(pageNode)
    `when`(pageNode.contentNode).thenReturn(contentNode)
    `when`(pageNode.generate()).thenReturn("<html></html>")
    `when`(pageMaker.getInfobox(anyString(), anyString(), eq(contentNode), anyString(), eq(true)))
      .thenReturn(infoboxNode)

    doNothing().`when`(ctx).sendReplyHeaders(anyInt(), anyString(), any(), any(), anyLong())
    doNothing().`when`(ctx).writeData(any(), anyInt(), anyInt())
  }

  private fun replaceAppEnv(toadlet: CoreActionToadlet, appEnv: AppEnv) {
    val field = CoreActionToadlet::class.java.getDeclaredField("appEnv")
    field.isAccessible = true
    field.set(toadlet, appEnv)
    assertTrue(field.get(toadlet) === appEnv)
  }
}
