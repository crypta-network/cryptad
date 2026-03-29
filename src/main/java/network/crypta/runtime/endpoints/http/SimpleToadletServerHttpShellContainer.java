package network.crypta.runtime.endpoints.http;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.PageMaker.THEME;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PermanentRedirectException;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletRegistration;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.TempBucketFactory;

/**
 * Adapter that exposes {@link SimpleToadletServer} through the runtime-owned {@link
 * HttpShellContainer} seam.
 *
 * <p>This class is intentionally thin. It does not reinterpret configuration, lifecycle, or
 * toadlet-registration behavior; it forwards those operations directly to the wrapped legacy shell
 * server so the refactor remains dependency-oriented rather than behavior-changing. The adapter
 * exists to keep the knowledge of the concrete shell type inside this bridge package while the rest
 * of runtime code works only with the narrower seam.
 *
 * <p>Most methods are direct pass-through delegations. The only notable translation is {@link
 * #markStartupPrngReady()}, which hides the concrete startup-toadlet access pattern from callers so
 * bootstrap code no longer reaches into the legacy shell's internal startup page structure.
 */
final class SimpleToadletServerHttpShellContainer implements HttpShellContainer {
  /** Wrapped legacy shell server that performs all concrete HTTP host work. */
  private final SimpleToadletServer delegate;

  /**
   * Creates a runtime-facing wrapper around an existing legacy shell server.
   *
   * <p>The caller retains responsibility for choosing and constructing the concrete server
   * instance. This adapter simply stores that instance and forwards all later operations to it so
   * the surrounding runtime code can depend on {@link HttpShellContainer} instead of the concrete
   * legacy class.
   *
   * @param delegate concrete legacy shell server that should back every delegated seam operation
   */
  SimpleToadletServerHttpShellContainer(SimpleToadletServer delegate) {
    this.delegate = delegate;
  }

  @Override
  public void start() {
    delegate.start();
  }

  @Override
  public void setRuntimeSupport(HttpShellRuntimeSupport runtimeSupport) {
    delegate.setRuntimeSupport(runtimeSupport);
  }

  @Override
  public void setBucketFactory(TempBucketFactory tempBucketFactory) {
    delegate.setBucketFactory(tempBucketFactory);
  }

  @Override
  public boolean isEnabled() {
    return delegate.isEnabled();
  }

  @Override
  public void finishStart() {
    delegate.finishStart();
  }

  @Override
  public void createFproxy() {
    delegate.createFproxy();
  }

  @Override
  public void removeStartupToadlet() {
    delegate.removeStartupToadlet();
  }

  @Override
  public void markStartupPrngReady() {
    delegate.getStartupToadlet().setIsPRNGReady();
  }

  @Override
  public boolean isAdvancedModeEnabled() {
    return delegate.isAdvancedModeEnabled();
  }

  @Override
  public boolean isFProxyJavascriptEnabled() {
    return delegate.isFProxyJavascriptEnabled();
  }

  @Override
  public boolean isLinkExcepted(URI link) {
    return delegate.isLinkExcepted(link);
  }

  @Override
  public void register(Toadlet t, ToadletRegistration registration) {
    delegate.register(t, registration);
  }

  @Override
  public void unregister(Toadlet t) {
    delegate.unregister(t);
  }

  @Override
  public Toadlet findToadlet(URI uri) throws PermanentRedirectException {
    return delegate.findToadlet(uri);
  }

  @Override
  public THEME getTheme() {
    return delegate.getTheme();
  }

  @Override
  public String getFormPassword() {
    return delegate.getFormPassword();
  }

  @Override
  public boolean isAllowedFullAccess(InetAddress remoteAddr) {
    return delegate.isAllowedFullAccess(remoteAddr);
  }

  @Override
  public boolean doRobots() {
    return delegate.doRobots();
  }

  @Override
  public HTMLNode addFormChild(HTMLNode parentNode, String target, String name) {
    return delegate.addFormChild(parentNode, target, name);
  }

  @Override
  public boolean enablePersistentConnections() {
    return delegate.enablePersistentConnections();
  }

  @Override
  public boolean enableInlinePrefetch() {
    return delegate.enableInlinePrefetch();
  }

  @Override
  public boolean enableExtendedMethodHandling() {
    return delegate.enableExtendedMethodHandling();
  }

  @Override
  public boolean enableCachingForChkAndSskKeys() {
    return delegate.enableCachingForChkAndSskKeys();
  }

  @Override
  public BucketFactory getBucketFactory() {
    return delegate.getBucketFactory();
  }

  @Override
  public boolean allowPosts() {
    return delegate.allowPosts();
  }

  @Override
  public boolean publicGatewayMode() {
    return delegate.publicGatewayMode();
  }

  @Override
  public boolean enableActivelinks() {
    return delegate.enableActivelinks();
  }

  @Override
  public boolean sendAllThemes() {
    return delegate.sendAllThemes();
  }

  @Override
  public boolean isFProxyWebPushingEnabled() {
    return delegate.isFProxyWebPushingEnabled();
  }

  @Override
  public boolean disableProgressPage() {
    return delegate.disableProgressPage();
  }

  @Override
  public PageMaker getPageMaker() {
    return delegate.getPageMaker();
  }

  @Override
  public void setAdvancedMode(boolean enabled) {
    delegate.setAdvancedMode(enabled);
  }

  @Override
  public boolean fproxyHasCompletedWizard() {
    return delegate.fproxyHasCompletedWizard();
  }

  @Override
  public REFILTER_POLICY getReFilterPolicy() {
    return delegate.getReFilterPolicy();
  }

  @Override
  public File getOverrideFile() {
    return delegate.getOverrideFile();
  }

  @Override
  public String getURL() {
    return delegate.getURL();
  }

  @Override
  public String getURL(String host) {
    return delegate.getURL(host);
  }

  @Override
  public boolean isSSL() {
    return delegate.isSSL();
  }

  @Override
  public long generateUniqueID() {
    return delegate.generateUniqueID();
  }
}
