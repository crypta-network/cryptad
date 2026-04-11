package network.crypta.runtime.updater;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventDispatchContext;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.fs.AppEnv;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.Version;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.Bucket;
import network.crypta.support.http.ExternalLinkSupport;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Package-oriented core updater that tracks update metadata and package download state.
 *
 * <p>This updater consumes core-update information editions published under the core info USK path
 * (for example, {@code .../info/N}) and chooses the most suitable package artifact for the current
 * platform and package-manager environment. Instead of replacing the running JAR in-place, it
 * downloads OS-native installer artifacts, exposes progress and failure status to the UI, and
 * renders action forms for download, install, and store-open flows. Selection logic accounts for
 * architecture, sandbox constraints, and available managers while retaining fallback behavior when
 * exact matches are unavailable.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Parsing core info descriptors and selecting preferred package variants.
 *   <li>Managing asynchronous package fetch lifecycle and error state.
 *   <li>Rendering updater properties, forms, and links for the web UI.
 * </ul>
 */
public class CoreUpdater extends NodeUpdater {
  private static final String LOG_TAG = "[CoreUpdater]";
  private static final String UNKNOWN_VERSION = "unknown";
  private static final String LOG_MESSAGE_PATTERN = "{} {}";
  private static final String EXT_FLATPAK = "flatpak";
  private static final String EXT_SNAP = "snap";
  private static final String FORM_FIELD_ACTION = "action";
  private static final String FORM_FIELD_FORM_PASSWORD = "formPassword";
  private static final int[] NO_BLOCK_PROGRESS = new int[0];

  private final Logger log = LoggerFactory.getLogger(CoreUpdater.class);
  private final AppEnv appEnv = new AppEnv();

  private final AtomicReference<CoreInfo> latestInfo = new AtomicReference<>();
  private final AtomicReference<Integer> latestVersionBuild = new AtomicReference<>();
  private volatile String selectedKey; // "<arch>.<ext>"
  private final AtomicReference<PackageSpec> selectedSpec = new AtomicReference<>();
  private final AtomicReference<PackageFetcher> fetcher = new AtomicReference<>();
  private final AtomicReference<AppEnv.EnvDetection> env = new AtomicReference<>();

  /**
   * Creates a core updater bound to the shared node updater manager context.
   *
   * @param params immutable parameter bundle provided by updater manager bootstrap
   */
  public CoreUpdater(NodeUpdaterParams params) {
    super(params);
  }

  private File getUpdatesRoot() {
    return new File(manager.getNode().nodeDir().dir(), "updates/core");
  }

  private void logInfo(String message) {
    log.info(LOG_MESSAGE_PATTERN, LOG_TAG, message);
  }

  private void logError(String message, Throwable throwable) {
    if (throwable != null) {
      log.error(LOG_MESSAGE_PATTERN, LOG_TAG, message, throwable);
    } else {
      log.error(LOG_MESSAGE_PATTERN, LOG_TAG, message);
    }
  }

  @Override
  public String artifactName() {
    return "core-info.json";
  }

  @Override
  protected void onStartFetching() {
    // No-op for UI; we render state via renderProperties.
  }

  @Override
  protected void maybeParseManifest(FetchResult result, int build) {
    CoreInfo info = parseInfo(result);
    latestInfo.set(info);
    Integer parsedBuild = parseStrictIntegerVersion(info.version());
    latestVersionBuild.set(parsedBuild);
    AppEnv.EnvDetection detected = appEnv.detectEnvironment();
    env.set(detected);
    selectArtifact(info, detected);
    logParsedDescriptor(info, detected, parsedBuild);

    PackageSpec selected = selectedSpec.get();
    if (manager.isAutoUpdateAllowed()
        && selected != null
        && selected.chk() != null
        && isNewerThanCurrentBuild(parsedBuild)
        && !hasUsableFetcher()) {
      tryStartDownload();
    }
  }

  private void logParsedDescriptor(
      CoreInfo info, AppEnv.EnvDetection detected, Integer parsedBuild) {
    try {
      String versionLabel = info.version() != null ? info.version() : "?";
      String managers = String.join(",", detected.getAvailableManagers());
      logInfo(
          "info.json parsed: version="
              + versionLabel
              + ", env="
              + detected.getOs()
              + "/"
              + detected.getArch()
              + " managers="
              + managers
              + " selectedKey="
              + (selectedKey != null ? selectedKey : "none"));
      if (info.releasePageUrl() != null && !info.releasePageUrl().isBlank()) {
        logInfo("release_page_url=" + info.releasePageUrl());
      }
      if ((info.changelogChk() != null && !info.changelogChk().isEmpty())
          || (info.fullChangelogChk() != null && !info.fullChangelogChk().isEmpty())) {
        logInfo(
            "changelogs: short="
                + (info.changelogChk() != null ? info.changelogChk() : "-")
                + ", full="
                + (info.fullChangelogChk() != null ? info.fullChangelogChk() : "-"));
      }
      if (parsedBuild == null) {
        log.warn(
            "{} Ignoring core-info version '{}' for release gating: expected an integer build",
            LOG_TAG,
            versionLabel);
      }
    } catch (Exception _) {
      // best effort logging
    }
  }

  @Override
  protected void processSuccess(int fetched, FetchResult result, File blobFile) {
    // Nothing to persist from info JSON beyond the in-memory state.
  }

  /**
   * Returns the short changelog CHK from the latest parsed core info descriptor.
   *
   * @return short changelog CHK string, or {@code null} when unavailable
   */
  public String getShortChangelogCHK() {
    CoreInfo info = latestInfo.get();
    return info != null ? info.changelogChk() : null;
  }

  /**
   * Returns the full changelog CHK from the latest parsed core info descriptor.
   *
   * @return full changelog CHK string, or {@code null} when unavailable
   */
  public String getFullChangelogCHK() {
    CoreInfo info = latestInfo.get();
    return info != null ? info.fullChangelogChk() : null;
  }

  /**
   * Returns the version label advertised by the latest parsed core info descriptor.
   *
   * @return descriptor version label, or {@code null} when unavailable
   */
  public String getAdvertisedVersionLabel() {
    CoreInfo info = latestInfo.get();
    return info != null ? info.version() : null;
  }

  @Override
  public synchronized boolean canUpdateNow() {
    return isNewerThanCurrentBuild(latestVersionBuild.get());
  }

  @Override
  public void onChangeURI(FreenetURI newUri, int subscribeEditionSeed) {
    resetDescriptorStateForUriChange();
    super.onChangeURI(newUri, subscribeEditionSeed);
  }

  private void resetDescriptorStateForUriChange() {
    cancelPackageFetchForUriChange();
    latestInfo.set(null);
    latestVersionBuild.set(null);
    selectedKey = null;
    selectedSpec.set(null);
    env.set(null);
  }

  private void cancelPackageFetchForUriChange() {
    PackageFetcher previous = fetcher.getAndSet(null);
    if (previous != null) {
      previous.cancelForUriChange();
    }
  }

  private CoreInfo parseInfo(FetchResult result) {
    try (Bucket bucket = result.asBucket();
        InputStream input = bucket.getInputStream();
        Reader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
      String json = readerToString(reader);
      return CoreJson.parse(json);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to parse core info JSON", e);
    }
  }

  private static String readerToString(Reader reader) throws java.io.IOException {
    StringBuilder sb = new StringBuilder();
    char[] buf = new char[8192];
    int n;
    while ((n = reader.read(buf)) != -1) {
      sb.append(buf, 0, n);
    }
    return sb.toString();
  }

  static Integer parseStrictIntegerVersion(String versionLabel) {
    if (versionLabel == null) {
      return null;
    }
    String trimmed = versionLabel.trim();
    if (trimmed.isEmpty()) {
      return null;
    }
    for (int i = 0; i < trimmed.length(); i++) {
      if (!Character.isDigit(trimmed.charAt(i))) {
        return null;
      }
    }
    try {
      return Integer.parseInt(trimmed);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  private static boolean isNewerThanCurrentBuild(Integer parsedBuild) {
    return parsedBuild != null && parsedBuild > Version.currentBuildNumber();
  }

  private void selectArtifact(CoreInfo info, AppEnv.EnvDetection env) {
    Map<String, PackageSpec> pkgs = info.packages();
    String arch = env.getArch();
    List<String> order = preferredExtensions(env);

    Map.Entry<String, PackageSpec> chosen = null;
    for (String ext : order) {
      String key = arch + "." + ext;
      PackageSpec spec = pkgs.get(key);
      if (isSelectableArtifact(env, ext, spec)) {
        chosen = Map.entry(key, spec);
        break;
      }
    }
    if (chosen == null) {
      chosen = firstAvailableForArch(pkgs, arch);
    }
    selectedKey = chosen != null ? chosen.getKey() : null;
    selectedSpec.set(chosen != null ? chosen.getValue() : null);
  }

  private static boolean isSelectableArtifact(
      AppEnv.EnvDetection env, String extension, PackageSpec spec) {
    if (spec == null) {
      return false;
    }
    if (spec.chk() != null) {
      return true;
    }
    return env.getOs() == AppEnv.OsKind.LINUX
        && isStorePackageExtension(extension)
        && hasText(spec.storeUrl());
  }

  private static boolean isStorePackageExtension(String extension) {
    return EXT_FLATPAK.equals(extension) || EXT_SNAP.equals(extension);
  }

  private List<String> preferredExtensions(AppEnv.EnvDetection env) {
    return switch (env.getOs()) {
      case WINDOWS -> List.of("exe");
      case MAC -> List.of("dmg");
      case LINUX -> linuxPreferredExtensions(env);
      case OTHER -> List.of();
    };
  }

  private List<String> linuxPreferredExtensions(AppEnv.EnvDetection env) {
    List<String> managers = env.getAvailableManagers();
    List<String> preferred = new ArrayList<>();
    if (safeIsFlatpak()) {
      preferred.add(EXT_FLATPAK);
    } else {
      addIfManagerPresent(managers, preferred, "rpm", "rpm");
      addIfManagerPresent(managers, preferred, "dpkg", "deb");
      addIfManagerPresent(managers, preferred, EXT_FLATPAK, EXT_FLATPAK);
      addIfManagerPresent(managers, preferred, EXT_SNAP, EXT_SNAP);
    }
    return mergeWithFallback(preferred, List.of("rpm", "deb", EXT_FLATPAK, EXT_SNAP));
  }

  private static void addIfManagerPresent(
      List<String> managers, List<String> preferred, String manager, String extension) {
    if (managers.contains(manager)) {
      preferred.add(extension);
    }
  }

  private static List<String> mergeWithFallback(List<String> preferred, List<String> fallback) {
    List<String> out = new ArrayList<>();
    addMissing(out, preferred);
    addMissing(out, fallback);
    return out;
  }

  private static void addMissing(List<String> out, List<String> values) {
    for (String value : values) {
      if (!out.contains(value)) {
        out.add(value);
      }
    }
  }

  private boolean safeIsFlatpak() {
    try {
      return appEnv.isFlatpak();
    } catch (Exception _) {
      return false;
    }
  }

  private static Map.Entry<String, PackageSpec> firstAvailableForArch(
      Map<String, PackageSpec> packages, String arch) {
    for (Map.Entry<String, PackageSpec> entry : packages.entrySet()) {
      if (entry.getKey().startsWith(arch + ".") && entry.getValue().chk() != null) {
        return Map.entry(entry.getKey(), entry.getValue());
      }
    }
    return null;
  }

  private File updatesDir() {
    CoreInfo info = latestInfo.get();
    String version = info != null && info.version() != null ? info.version() : UNKNOWN_VERSION;
    return new File(getUpdatesRoot(), version);
  }

  private File downloadTarget() {
    String key = selectedKey;
    if (key == null) {
      return null;
    }
    File outDir = updatesDir();
    if (!outDir.exists() && !outDir.mkdirs()) {
      logError("Failed to create updates directory at " + outDir.getAbsolutePath(), null);
      return null;
    }
    return new File(outDir, key);
  }

  private PackageFetcher fetcherMatchesSelection() {
    PackageSpec spec = selectedSpec.get();
    if (spec == null || spec.chk() == null) {
      return null;
    }
    PackageFetcher f = fetcher.get();
    if (f != null && f.matchesChk(spec.chk())) {
      return f;
    }
    return null;
  }

  private boolean hasUsableFetcher() {
    PackageFetcher f = fetcherMatchesSelection();
    return f != null && !f.hasFailed();
  }

  private void tryStartDownload() {
    PackageSpec spec = selectedSpec.get();
    File target = downloadTarget();
    if (spec == null || target == null || spec.chk() == null) {
      return;
    }
    String chk = spec.chk();
    FreenetURI uri;
    try {
      uri = new FreenetURI(chk);
    } catch (MalformedURLException e) {
      logError("Invalid CHK URI for selected package: " + chk, e);
      return;
    }
    PackageFetcher f = new PackageFetcher(target, uri, chk);
    fetcher.set(f);
    logInfo(
        "starting download: key="
            + (selectedKey != null ? selectedKey : "?")
            + ", target="
            + target.getAbsolutePath()
            + ", chk="
            + chk);
    f.start();
  }

  /** Start downloading the currently selected package if not already in progress. */
  public void startDownloadFromUI() {
    if (selectedSpec.get() == null) {
      return;
    }
    PackageFetcher matchingFetcher = fetcherMatchesSelection();
    if (matchingFetcher != null) {
      if (matchingFetcher.isInProgress() || matchingFetcher.isSuccess()) {
        return;
      }
    } else {
      PackageFetcher inFlight = fetcher.get();
      if (inFlight != null && inFlight.isInProgress()) {
        logInfo("Skipping download start: another package download is still running");
        return;
      }
    }
    tryStartDownload();
  }

  /**
   * Returns the completed package file for the currently selected artifact.
   *
   * @return the downloaded package file when fetch completed successfully, otherwise {@code null}
   */
  public File getDownloadedFile() {
    PackageFetcher f = fetcherMatchesSelection();
    if (f != null && f.isSuccess()) {
      return f.completedFileOrNull();
    }
    return null;
  }

  /**
   * Renders updater status, links, and action controls into the supplied alert node.
   *
   * @param alertNode parent HTML node that receives updater status content and forms
   */
  public void renderProperties(HTMLNode alertNode) {
    CoreInfo info = latestInfo.get();
    if (info == null) {
      return;
    }

    AppEnv.EnvDetection envNow = env.get();
    if (envNow == null) {
      envNow = appEnv.detectEnvironment();
      env.set(envNow);
    }

    String chosen = selectedKey;
    PackageSpec spec = selectedSpec.get();

    addHeader(alertNode, info, envNow, chosen, spec);
    alertNode.addChild(buildLinksNode(info, spec, chosen));

    PackageFetcher f = fetcherMatchesSelection();
    if (f == null) {
      if (spec != null && spec.chk() != null) {
        alertNode.addChild(buildDownloadForm());
      }
      return;
    }

    if (f.hasFailed()) {
      String msg = f.errorMessage() != null ? f.errorMessage() : "Download failed.";
      HTMLNode p = new HTMLNode("p");
      p.addChild("#", "Download failed: " + msg);
      alertNode.addChild(p);
      alertNode.addChild(buildRetryForm(!f.isFatalFailure()));
      return;
    }

    alertNode.addChild(buildProgressNode(f));
    boolean ready = f.isSuccess();
    File downloaded = getDownloadedFile();
    String path = downloaded != null ? downloaded.getAbsolutePath() : null;
    alertNode.addChild(buildInstallForm(ready, path));
  }

  private void addHeader(
      HTMLNode alertNode, CoreInfo info, AppEnv.EnvDetection env, String chosen, PackageSpec spec) {
    HTMLNode status = new HTMLNode("p");
    status.addChild(
        "#", "Core update available: version " + (info.version() != null ? info.version() : "?"));
    alertNode.addChild(status);

    HTMLNode det = new HTMLNode("p");
    det.addChild(
        "#",
        "Detected: "
            + env.getOs()
            + " / "
            + env.getArch()
            + "  •  Selected package: "
            + (chosen != null ? chosen : "n/a"));
    alertNode.addChild(det);

    Long size = spec != null ? spec.size() : null;
    if (size != null && size > 0) {
      HTMLNode sizeLine = new HTMLNode("p");
      sizeLine.addChild("#", "Package size: " + SizeUtil.formatSize(size, true));
      alertNode.addChild(sizeLine);
    }
  }

  private HTMLNode buildLinksNode(CoreInfo info, PackageSpec spec, String chosenKey) {
    HTMLNode links = new HTMLNode("p");
    addReleaseNotesLink(links, info.releasePageUrl());

    String storeUrl = spec != null ? spec.storeUrl() : null;
    String kind = storeKind(chosenKey);

    if (shouldRenderStoreForm(storeUrl, kind)) {
      String id = deriveStoreId(kind, storeUrl);
      links.addChild(buildOpenStoreForm(kind, id, storeUrl));
      links.addChild("#", "  ");
    } else if (hasText(storeUrl)) {
      links.addChild("a", "href", ExternalLinkSupport.escape(storeUrl), "Open in Store");
      links.addChild("#", "  ");
    }
    return links;
  }

  private static void addReleaseNotesLink(HTMLNode links, String releasePageUrl) {
    if (hasText(releasePageUrl)) {
      links.addChild("a", "href", ExternalLinkSupport.escape(releasePageUrl), "Release Notes");
      links.addChild("#", "  ");
    }
  }

  private static String storeKind(String chosenKey) {
    String extension = extensionFromChosenKey(chosenKey);
    if (EXT_FLATPAK.equals(extension)) {
      return EXT_FLATPAK;
    }
    if (EXT_SNAP.equals(extension)) {
      return EXT_SNAP;
    }
    return null;
  }

  private static String extensionFromChosenKey(String chosenKey) {
    if (!hasText(chosenKey)) {
      return null;
    }
    int idx = chosenKey.lastIndexOf('.');
    if (idx < 0 || idx + 1 >= chosenKey.length()) {
      return null;
    }
    return chosenKey.substring(idx + 1).toLowerCase(Locale.ROOT);
  }

  private boolean shouldRenderStoreForm(String storeUrl, String kind) {
    return hasText(storeUrl) && kind != null && isLinuxEnvironment();
  }

  private boolean isLinuxEnvironment() {
    AppEnv.EnvDetection detected = env.get();
    return (detected != null && detected.getOs() == AppEnv.OsKind.LINUX) || safeIsLinux();
  }

  private static boolean hasText(String value) {
    return value != null && !value.isEmpty();
  }

  private boolean safeIsLinux() {
    try {
      return appEnv.isLinux();
    } catch (Exception _) {
      return false;
    }
  }

  private HTMLNode buildOpenStoreForm(String kind, String id, String url) {
    HTMLNode form = newPostForm();
    hiddenInput(form, FORM_FIELD_ACTION, "openStore");
    hiddenInput(form, "kind", kind);
    if (hasText(id)) {
      hiddenInput(form, "id", id);
    }
    if (hasText(url)) {
      hiddenInput(form, "url", url);
    }
    hiddenInput(form, FORM_FIELD_FORM_PASSWORD, formPassword());
    submitButton(form, "Open in Store", "openStore", false);
    return form;
  }

  private String deriveStoreId(String kind, String url) {
    try {
      java.net.URI u = java.net.URI.create(url);
      String path = u.getPath();
      if (!hasText(path)) {
        return null;
      }
      int lastSeparator = path.lastIndexOf('/');
      String last = lastSeparator >= 0 ? path.substring(lastSeparator + 1) : path;
      if (!hasText(last)) {
        return null;
      }
      if (EXT_SNAP.equalsIgnoreCase(kind) || EXT_FLATPAK.equalsIgnoreCase(kind)) {
        return last;
      }
      return null;
    } catch (Exception _) {
      return null;
    }
  }

  private String formPassword() {
    return manager.getNode().services().clientCore().getFormPassword();
  }

  private HTMLNode newPostForm() {
    return new HTMLNode(
        "form",
        new String[] {FORM_FIELD_ACTION, "method"},
        new String[] {UpdaterPaths.CORE_UPDATE_PATH, "post"});
  }

  private static void hiddenInput(HTMLNode node, String name, String value) {
    node.addChild(
        "input", new String[] {"type", "name", "value"}, new String[] {"hidden", name, value});
  }

  private static void submitButton(HTMLNode node, String value, String name, boolean disabled) {
    List<String> attrs = new ArrayList<>();
    List<String> vals = new ArrayList<>();
    attrs.add("type");
    vals.add("submit");
    attrs.add("value");
    vals.add(value);
    if (name != null) {
      attrs.add("name");
      vals.add(name);
    }
    if (disabled) {
      attrs.add("disabled");
      vals.add("disabled");
    }
    node.addChild("input", attrs.toArray(String[]::new), vals.toArray(String[]::new));
  }

  private HTMLNode buildDownloadForm() {
    HTMLNode form = newPostForm();
    hiddenInput(form, FORM_FIELD_ACTION, "download");
    hiddenInput(form, FORM_FIELD_FORM_PASSWORD, formPassword());
    submitButton(form, defaultDownloadLabel(), "start", false);
    return form;
  }

  private HTMLNode buildRetryForm(boolean isRetry) {
    HTMLNode form = newPostForm();
    hiddenInput(form, FORM_FIELD_ACTION, "download");
    hiddenInput(form, FORM_FIELD_FORM_PASSWORD, formPassword());
    submitButton(form, isRetry ? "Retry" : defaultDownloadLabel(), "start", false);
    return form;
  }

  private String defaultDownloadLabel() {
    PackageSpec spec = selectedSpec.get();
    Long bytes = spec != null ? spec.size() : null;
    if (bytes != null && bytes > 0) {
      return "Download (" + SizeUtil.formatSize(bytes, true) + ")";
    }
    return "Download";
  }

  private HTMLNode buildProgressNode(PackageFetcher f) {
    HTMLNode p = new HTMLNode("p");
    int pct = f.progressPercent();
    int[] blocks = f.blockProgressOrNull();
    String text;
    if (f.isSuccess()) {
      text = "Download Completed";
    } else if (pct >= 0 && blocks.length == 2) {
      text = "Downloading: " + pct + "% (" + blocks[0] + "/" + blocks[1] + ")";
    } else if (pct >= 0) {
      text = "Downloading: " + pct + "%";
    } else {
      text = "Downloading…";
    }
    p.addChild("#", text);
    return p;
  }

  private HTMLNode buildInstallForm(boolean ready, String path) {
    HTMLNode form = newPostForm();
    hiddenInput(form, FORM_FIELD_ACTION, "install");
    hiddenInput(form, "path", path != null ? path : "");
    hiddenInput(form, FORM_FIELD_FORM_PASSWORD, formPassword());
    submitButton(form, "Install", null, !ready);
    return form;
  }

  /** Lightweight fetcher for a single CHK saved directly to a file. */
  class PackageFetcher implements ClientGetCallback, RequestClient, ClientEventListener {
    private final File outFile;
    private final FreenetURI chk;
    private final String chkString;
    private final AtomicReference<FetchContext> fetchContext = new AtomicReference<>();
    private final AtomicReference<ClientGetter> clientGetter = new AtomicReference<>();

    private volatile int lastPct = -1;
    private volatile int lastDone = -1;
    private volatile int lastNeed = -1;
    private volatile boolean complete = false;
    private volatile File successFile;
    private volatile boolean failed = false;
    private volatile String errorMsg;
    private volatile boolean fatal = false;

    PackageFetcher(File outFile, FreenetURI chk, String chkString) {
      this.outFile = outFile;
      this.chk = chk;
      this.chkString = chkString;
    }

    void start() {
      var ctx =
          manager
              .getNode()
              .services()
              .clientCore()
              .makeClient((short) 0, true, false)
              .getFetchContext();
      var fb = new FileBucket(outFile, false, false, false, false);
      var createdGetter =
          new ClientGetter(
              this, chk, ctx, RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, fb, null, null);
      fetchContext.set(ctx);
      clientGetter.set(createdGetter);
      ctx.getEventProducer().addEventListener(this);
      try {
        manager.getNode().services().clientCore().getClientContext().start(createdGetter);
        CoreUpdater.this.logInfo(
            "download started (listener attached): target=" + outFile.getAbsolutePath());
      } catch (FetchException e) {
        markStartFailure(
            e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(), safeIsFatal(e));
        detachProgressListener();
        CoreUpdater.this.logError(
            "Failed to start package download: "
                + (errorMsg != null ? errorMsg : e.getClass().getSimpleName()),
            e);
      } catch (Exception e) {
        markStartFailure(
            e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(), false);
        detachProgressListener();
        CoreUpdater.this.logError(
            "Error starting package download: "
                + (errorMsg != null ? errorMsg : e.getClass().getSimpleName()),
            e);
      }
    }

    void cancelForUriChange() {
      ClientGetter getter = clientGetter.get();
      if (getter == null || getter.isFinished()) {
        detachProgressListener();
        return;
      }
      try {
        getter.cancel(manager.getNode().services().clientCore().getClientContext());
        CoreUpdater.this.logInfo("Cancelled in-flight package download after update URI change");
      } catch (Exception e) {
        CoreUpdater.this.logError(
            "Error while cancelling in-flight package download after URI change", e);
      } finally {
        detachProgressListener();
      }
    }

    boolean isInProgress() {
      return !complete;
    }

    File completedFileOrNull() {
      return successFile;
    }

    int progressPercent() {
      return lastPct;
    }

    int[] blockProgressOrNull() {
      if (lastNeed > 0 && lastDone >= 0) {
        return new int[] {lastDone, lastNeed};
      }
      return NO_BLOCK_PROGRESS;
    }

    boolean isSuccess() {
      return complete && !failed && successFile != null;
    }

    boolean hasFailed() {
      return complete && failed;
    }

    String errorMessage() {
      return errorMsg;
    }

    boolean isFatalFailure() {
      return failed && fatal;
    }

    boolean matchesChk(String candidate) {
      return candidate != null && candidate.equals(chkString);
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      detachProgressListener();
      clientGetter.set(null);
      complete = true;
      successFile = outFile;
      failed = false;
      errorMsg = null;
      CoreUpdater.this.logInfo(
          "download complete: " + outFile.getAbsolutePath() + " (size=" + outFile.length() + ")");
    }

    @Override
    public void onFailure(FetchException e) {
      detachProgressListener();
      clientGetter.set(null);
      complete = true;
      successFile = null;
      failed = true;
      try {
        fatal = e.isFatal();
      } catch (Exception _) {
        fatal = false;
      }
      errorMsg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
      if (e.mode == FetchExceptionMode.CANCELLED) {
        return;
      }
      CoreUpdater.this.logError(
          "Package download failed: " + (errorMsg != null ? errorMsg : "unknown error"), e);
    }

    @Override
    public void onResume(ClientContext context) {
      // no-op
    }

    @Override
    public boolean realTimeFlag() {
      return false;
    }

    @Override
    public boolean persistent() {
      return false;
    }

    @Override
    public RequestClient getRequestClient() {
      return this;
    }

    @Override
    public void receive(ClientEvent ce, ClientEventDispatchContext context) {
      try {
        if (ce instanceof SplitfileProgressEvent progress) {
          int done = progress.succeedBlocks;
          int need = progress.getMinSuccessfulBlocks();
          if (need <= 0) {
            need = progress.totalBlocks > 0 ? progress.totalBlocks : 1;
          }
          int pctNow = (100 * done) / need;
          if (pctNow != lastPct || done != lastDone || need != lastNeed) {
            lastPct = pctNow;
            lastDone = done;
            lastNeed = need;
            CoreUpdater.this.logInfo(
                "progress: "
                    + pctNow
                    + "% ("
                    + done
                    + "/"
                    + need
                    + ", total="
                    + progress.totalBlocks
                    + ")");
          }
        }
      } catch (Exception _) {
        // ignore progress failures
      }
    }

    private boolean safeIsFatal(FetchException e) {
      try {
        return e.isFatal();
      } catch (Exception _) {
        return false;
      }
    }

    private void detachProgressListener() {
      FetchContext localContext = fetchContext.getAndSet(null);
      if (localContext == null) {
        return;
      }
      try {
        localContext.getEventProducer().removeEventListener(this);
      } catch (Exception _) {
        // Best-effort listener cleanup.
      }
    }

    private void markStartFailure(String message, boolean fatalFlag) {
      complete = true;
      successFile = null;
      failed = true;
      fatal = fatalFlag;
      errorMsg = message != null ? message : "Failed to start download";
      clientGetter.set(null);
    }
  }
}

/** Minimal JSON parser for the CoreInfo schema used by CoreUpdater. */
final class CoreJson {
  private CoreJson() {}

  static CoreInfo parse(String json) {
    Map<String, Object> map = JsonMini.parseObject(json);
    String version = asString(map.get("version"));
    String release = asString(map.get("release_page_url"));
    Object pkgsRawObj = map.get("packages");
    Map<?, ?> pkgsRaw = pkgsRawObj instanceof Map<?, ?> m ? m : Map.of();

    Map<String, PackageSpec> pkgs = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : pkgsRaw.entrySet()) {
      if (!(entry.getKey() instanceof String key) || !(entry.getValue() instanceof Map<?, ?> o)) {
        continue;
      }
      Long size = null;
      Object sizeObj = o.get("size");
      if (sizeObj instanceof Number n) {
        size = n.longValue();
      }
      pkgs.put(key, new PackageSpec(asString(o.get("chk")), size, asString(o.get("store_url"))));
    }

    String shortC = asString(map.get("changelog_chk"));
    String fullC = asString(map.get("fullchangelog_chk"));
    return new CoreInfo(version, release, pkgs, shortC, fullC);
  }

  private static String asString(Object o) {
    return o instanceof String s ? s : null;
  }
}

/** Minimal JSON reader sufficient for CoreInfo. Not a general-purpose JSON parser. */
final class JsonMini {
  private JsonMini() {}

  private static final class P {
    private final String s;
    private int i;

    private P(String s) {
      this.s = s;
      this.i = 0;
    }
  }

  static Map<String, Object> parseObject(String s) {
    P p = new P(s);
    return parseObjectInPlace(p);
  }

  private static Map<String, Object> parseObjectInPlace(P p) {
    skipWs(p);
    expect(p, '{');
    Map<String, Object> out = new LinkedHashMap<>();
    skipWs(p);
    if (peek(p) == '}') {
      p.i++;
      return out;
    }
    while (true) {
      skipWs(p);
      String key = parseString(p);
      skipWs(p);
      expect(p, ':');
      skipWs(p);
      Object value = parseValue(p);
      out.put(key, value);
      skipWs(p);
      char ch = next(p);
      if (ch == '}') {
        break;
      }
      if (ch != ',') {
        throw new IllegalArgumentException("Expected , or } at " + p.i);
      }
    }
    return out;
  }

  private static List<Object> parseArrayInPlace(P p) {
    expect(p, '[');
    List<Object> out = new ArrayList<>();
    skipWs(p);
    if (peek(p) == ']') {
      p.i++;
      return out;
    }
    while (true) {
      out.add(parseValue(p));
      skipWs(p);
      char ch = next(p);
      if (ch == ']') {
        break;
      }
      if (ch != ',') {
        throw new IllegalArgumentException("Expected , or ] at " + p.i);
      }
    }
    return out;
  }

  private static Object parseValue(P p) {
    skipWs(p);
    char ch = peek(p);
    return switch (ch) {
      case '"' -> parseString(p);
      case '{' -> parseObjectInPlace(p);
      case '[' -> parseArrayInPlace(p);
      case 't' -> {
        expectWord(p, "true");
        yield Boolean.TRUE;
      }
      case 'f' -> {
        expectWord(p, "false");
        yield Boolean.FALSE;
      }
      case 'n' -> {
        expectWord(p, "null");
        yield null;
      }
      default -> {
        if (ch == '-' || Character.isDigit(ch)) {
          yield parseNumber(p);
        }
        throw new IllegalArgumentException("Unexpected char '" + ch + "' at " + p.i);
      }
    };
  }

  private static Number parseNumber(P p) {
    int start = p.i;
    if (peek(p) == '-') {
      p.i++;
    }
    while (Character.isDigit(peek(p))) {
      p.i++;
    }
    if (peek(p) == '.') {
      do {
        p.i++;
      } while (Character.isDigit(peek(p)));
    }
    String sub = p.s.substring(start, p.i);
    double d = Double.parseDouble(sub);
    return d % 1.0 == 0.0 ? (long) d : d;
  }

  private static String parseString(P p) {
    expect(p, '"');
    StringBuilder sb = new StringBuilder();
    while (true) {
      char ch = next(p);
      if (ch == '"') {
        return sb.toString();
      }
      if (ch == '\\') {
        char e = next(p);
        switch (e) {
          case '"' -> sb.append('"');
          case '\\' -> sb.append('\\');
          case '/' -> sb.append('/');
          case 'b' -> sb.append('\b');
          case 'f' -> sb.append('\f');
          case 'n' -> sb.append('\n');
          case 'r' -> sb.append('\r');
          case 't' -> sb.append('\t');
          case 'u' -> {
            String hex = p.s.substring(p.i, p.i + 4);
            p.i += 4;
            sb.append((char) Integer.parseInt(hex, 16));
          }
          default -> throw new IllegalArgumentException("Bad escape \\" + e + " at " + p.i);
        }
      } else {
        sb.append(ch);
      }
    }
  }

  private static void skipWs(P p) {
    while (p.i < p.s.length() && Character.isWhitespace(p.s.charAt(p.i))) {
      p.i++;
    }
  }

  private static char next(P p) {
    return p.s.charAt(p.i++);
  }

  private static char peek(P p) {
    return p.i < p.s.length() ? p.s.charAt(p.i) : '\0';
  }

  private static void expect(P p, char ch) {
    char c = next(p);
    if (c != ch) {
      throw new IllegalArgumentException("Expected '" + ch + "' got '" + c + "' at " + p.i);
    }
  }

  private static void expectWord(P p, String w) {
    for (int j = 0; j < w.length(); j++) {
      expect(p, w.charAt(j));
    }
  }
}
