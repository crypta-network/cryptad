package network.crypta.node.updater;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.events.ClientEvent;
import network.crypta.client.events.ClientEventListener;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.clients.http.ExternalLinkToadlet;
import network.crypta.fs.AppEnv;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Package-based updater that subscribes to `USK@.../info/<N>` and offers OS installers instead of
 * self-updating the running JAR.
 */
public class CoreUpdater extends NodeUpdater {
  private static final String LOG_TAG = "[CoreUpdater]";
  private static final String UNKNOWN_VERSION = "unknown";

  private final Logger log = LoggerFactory.getLogger(CoreUpdater.class);
  private final AppEnv appEnv = new AppEnv();

  private volatile CoreInfo latestInfo;
  private volatile String selectedKey; // "<arch>.<ext>"
  private volatile PackageSpec selectedSpec;
  private volatile PackageFetcher fetcher;
  private volatile AppEnv.EnvDetection env;

  public CoreUpdater(NodeUpdaterParams params) {
    super(params);
  }

  private File getUpdatesRoot() {
    return new File(manager.getNode().nodeDir().dir(), "updates/core");
  }

  private void logInfo(String message) {
    log.info("{} {}", LOG_TAG, message);
  }

  private void logError(String message, Throwable throwable) {
    if (throwable != null) {
      log.error("{} {}", LOG_TAG, message, throwable);
    } else {
      log.error("{} {}", LOG_TAG, message);
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
    latestInfo = info;
    AppEnv.EnvDetection detected = appEnv.detectEnvironment();
    env = detected;
    selectArtifact(info, detected);

    try {
      String versionLabel = info.getVersion() != null ? info.getVersion() : "?";
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
      if (info.getReleasePageUrl() != null && !info.getReleasePageUrl().isBlank()) {
        logInfo("release_page_url=" + info.getReleasePageUrl());
      }
      if ((info.getChangelogChk() != null && !info.getChangelogChk().isEmpty())
          || (info.getFullChangelogChk() != null && !info.getFullChangelogChk().isEmpty())) {
        logInfo(
            "changelogs: short="
                + (info.getChangelogChk() != null ? info.getChangelogChk() : "-")
                + ", full="
                + (info.getFullChangelogChk() != null ? info.getFullChangelogChk() : "-"));
      }
    } catch (Throwable ignored) {
      // best effort logging
    }

    if (manager.isAutoUpdateAllowed()
        && selectedSpec != null
        && selectedSpec.getChk() != null
        && !hasUsableFetcher()) {
      tryStartDownload();
    }
  }

  @Override
  protected void processSuccess(int fetched, FetchResult result, File blobFile) {
    // Nothing to persist from info JSON beyond in-memory state.
  }

  public String getShortChangelogCHK() {
    return latestInfo != null ? latestInfo.getChangelogChk() : null;
  }

  public String getFullChangelogCHK() {
    return latestInfo != null ? latestInfo.getFullChangelogChk() : null;
  }

  private CoreInfo parseInfo(FetchResult result) {
    try (InputStream input = result.asBucket().getInputStream();
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

  private void selectArtifact(CoreInfo info, AppEnv.EnvDetection env) {
    Map<String, PackageSpec> pkgs = info.getPackages();
    String arch = env.getArch();
    List<String> order = preferredExtensions(env);

    Map.Entry<String, PackageSpec> chosen = null;
    for (String ext : order) {
      String key = arch + "." + ext;
      PackageSpec spec = pkgs.get(key);
      if (spec == null) {
        continue;
      }
      if (spec.getChk() != null) {
        chosen = Map.entry(key, spec);
        break;
      }
      if (env.getOs() == AppEnv.OsKind.LINUX
          && ("flatpak".equals(ext) || "snap".equals(ext))
          && spec.getStoreUrl() != null
          && !spec.getStoreUrl().isEmpty()) {
        chosen = Map.entry(key, spec);
        break;
      }
    }
    if (chosen == null) {
      chosen = firstAvailableForArch(pkgs, arch);
    }
    selectedKey = chosen != null ? chosen.getKey() : null;
    selectedSpec = chosen != null ? chosen.getValue() : null;
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
    List<String> fallback = List.of("rpm", "deb", "flatpak", "snap");
    if (safeIsFlatpak()) {
      preferred.add("flatpak");
    } else {
      if (managers.contains("rpm")) {
        preferred.add("rpm");
      }
      if (managers.contains("dpkg")) {
        preferred.add("deb");
      }
      if (managers.contains("flatpak")) {
        preferred.add("flatpak");
      }
      if (managers.contains("snap")) {
        preferred.add("snap");
      }
    }
    List<String> out = new ArrayList<>();
    for (String e : preferred) {
      if (!out.contains(e)) {
        out.add(e);
      }
    }
    for (String e : fallback) {
      if (!out.contains(e)) {
        out.add(e);
      }
    }
    return out;
  }

  private boolean safeIsFlatpak() {
    try {
      return appEnv.isFlatpak();
    } catch (Throwable ignored) {
      return false;
    }
  }

  private static Map.Entry<String, PackageSpec> firstAvailableForArch(
      Map<String, PackageSpec> packages, String arch) {
    for (Map.Entry<String, PackageSpec> entry : packages.entrySet()) {
      if (entry.getKey().startsWith(arch + ".") && entry.getValue().getChk() != null) {
        return Map.entry(entry.getKey(), entry.getValue());
      }
    }
    return null;
  }

  private File updatesDir() {
    String version =
        latestInfo != null && latestInfo.getVersion() != null
            ? latestInfo.getVersion()
            : UNKNOWN_VERSION;
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
    PackageSpec spec = selectedSpec;
    if (spec == null || spec.getChk() == null) {
      return null;
    }
    PackageFetcher f = fetcher;
    if (f != null && f.matchesChk(spec.getChk())) {
      return f;
    }
    return null;
  }

  private boolean hasUsableFetcher() {
    PackageFetcher f = fetcherMatchesSelection();
    return f != null && !f.hasFailed();
  }

  private void tryStartDownload() {
    PackageSpec spec = selectedSpec;
    File target = downloadTarget();
    if (spec == null || target == null || spec.getChk() == null) {
      return;
    }
    String chk = spec.getChk();
    FreenetURI uri;
    try {
      uri = new FreenetURI(chk);
    } catch (MalformedURLException e) {
      logError("Invalid CHK URI for selected package: " + chk, e);
      return;
    }
    PackageFetcher f = new PackageFetcher(target, uri, chk);
    fetcher = f;
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
    if (selectedSpec == null) {
      return;
    }
    PackageFetcher matchingFetcher = fetcherMatchesSelection();
    if (matchingFetcher != null) {
      if (!matchingFetcher.isComplete() || matchingFetcher.isSuccess()) {
        return;
      }
    } else {
      PackageFetcher inFlight = fetcher;
      if (inFlight != null && !inFlight.isComplete()) {
        logInfo("Skipping download start: another package download is still running");
        return;
      }
    }
    tryStartDownload();
  }

  /** Returns the completed download file on success or null. */
  public File getDownloadedFile() {
    PackageFetcher f = fetcherMatchesSelection();
    if (f != null && f.isSuccess()) {
      return f.completedFileOrNull();
    }
    return null;
  }

  /** Renders updater status section into the supplied Alerts HTML node. */
  public void renderProperties(HTMLNode alertNode) {
    CoreInfo info = latestInfo;
    if (info == null) {
      return;
    }

    AppEnv.EnvDetection envNow = env;
    if (envNow == null) {
      envNow = appEnv.detectEnvironment();
      env = envNow;
    }

    String chosen = selectedKey;
    PackageSpec spec = selectedSpec;

    addHeader(alertNode, info, envNow, chosen, spec);
    alertNode.addChild(buildLinksNode(info, spec, chosen));

    PackageFetcher f = fetcherMatchesSelection();
    if (f == null) {
      if (spec != null && spec.getChk() != null) {
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
        "#",
        "Core update available: version " + (info.getVersion() != null ? info.getVersion() : "?"));
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

    Long size = spec != null ? spec.getSize() : null;
    if (size != null && size > 0) {
      HTMLNode sizeLine = new HTMLNode("p");
      sizeLine.addChild("#", "Package size: " + SizeUtil.formatSize(size, true));
      alertNode.addChild(sizeLine);
    }
  }

  private HTMLNode buildLinksNode(CoreInfo info, PackageSpec spec, String chosenKey) {
    HTMLNode links = new HTMLNode("p");
    if (info.getReleasePageUrl() != null && !info.getReleasePageUrl().isEmpty()) {
      links.addChild(
          "a", "href", ExternalLinkToadlet.escape(info.getReleasePageUrl()), "Release Notes");
      links.addChild("#", "  ");
    }

    String storeUrl = spec != null ? spec.getStoreUrl() : null;
    String ext = null;
    if (chosenKey != null) {
      int idx = chosenKey.lastIndexOf('.');
      if (idx >= 0 && idx + 1 < chosenKey.length()) {
        ext = chosenKey.substring(idx + 1).toLowerCase();
      }
    }
    boolean isLinux = (env != null && env.getOs() == AppEnv.OsKind.LINUX) || safeIsLinux();
    String kind = "flatpak".equals(ext) ? "flatpak" : ("snap".equals(ext) ? "snap" : null);

    if (storeUrl != null && !storeUrl.isEmpty() && kind != null && isLinux) {
      String id = deriveStoreId(kind, storeUrl);
      links.addChild(buildOpenStoreForm(kind, id, storeUrl));
      links.addChild("#", "  ");
    } else if (storeUrl != null && !storeUrl.isEmpty()) {
      links.addChild("a", "href", ExternalLinkToadlet.escape(storeUrl), "Open in Store");
      links.addChild("#", "  ");
    }
    return links;
  }

  private boolean safeIsLinux() {
    try {
      return appEnv.isLinux();
    } catch (Throwable ignored) {
      return false;
    }
  }

  private HTMLNode buildOpenStoreForm(String kind, String id, String url) {
    HTMLNode form = newPostForm();
    hiddenInput(form, "action", "openStore");
    hiddenInput(form, "kind", kind);
    if (id != null && !id.isEmpty()) {
      hiddenInput(form, "id", id);
    }
    if (url != null && !url.isEmpty()) {
      hiddenInput(form, "url", url);
    }
    hiddenInput(form, "formPassword", formPassword());
    submitButton(form, "Open in Store", "openStore", false);
    return form;
  }

  private String deriveStoreId(String kind, String url) {
    try {
      java.net.URI u = java.net.URI.create(url);
      String path = u.getPath();
      if (path == null) {
        return null;
      }
      String[] segs = path.split("/");
      String last = null;
      for (String s : segs) {
        if (!s.isEmpty()) {
          last = s;
        }
      }
      if (last == null) {
        return null;
      }
      if ("snap".equalsIgnoreCase(kind) || "flatpak".equalsIgnoreCase(kind)) {
        return last;
      }
      return null;
    } catch (Throwable ignored) {
      return null;
    }
  }

  private String formPassword() {
    return manager.getNode().services().clientCore().getFormPassword();
  }

  private HTMLNode newPostForm() {
    return new HTMLNode(
        "form",
        new String[] {"action", "method"},
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
    hiddenInput(form, "action", "download");
    hiddenInput(form, "formPassword", formPassword());
    submitButton(form, defaultDownloadLabel(), "start", false);
    return form;
  }

  private HTMLNode buildRetryForm(boolean isRetry) {
    HTMLNode form = newPostForm();
    hiddenInput(form, "action", "download");
    hiddenInput(form, "formPassword", formPassword());
    submitButton(form, isRetry ? "Retry" : defaultDownloadLabel(), "start", false);
    return form;
  }

  private String defaultDownloadLabel() {
    Long bytes = selectedSpec != null ? selectedSpec.getSize() : null;
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
    } else if (pct >= 0 && blocks != null) {
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
    hiddenInput(form, "action", "install");
    hiddenInput(form, "path", path != null ? path : "");
    hiddenInput(form, "formPassword", formPassword());
    submitButton(form, "Install", null, !ready);
    return form;
  }

  /** Lightweight fetcher for a single CHK saved directly to a file. */
  class PackageFetcher implements ClientGetCallback, RequestClient, ClientEventListener {
    private final File outFile;
    private final FreenetURI chk;
    private final String chkString;

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
      ctx.getEventProducer().addEventListener(this);
      try {
        manager.getNode().services().clientCore().getClientContext().start(createdGetter);
        CoreUpdater.this.logInfo(
            "download started (listener attached): target=" + outFile.getAbsolutePath());
      } catch (FetchException e) {
        markStartFailure(
            e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(), safeIsFatal(e));
        ctx.getEventProducer().removeEventListener(this);
        CoreUpdater.this.logError(
            "Failed to start package download: "
                + (errorMsg != null ? errorMsg : e.getClass().getSimpleName()),
            e);
      } catch (Exception e) {
        markStartFailure(
            e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(), false);
        ctx.getEventProducer().removeEventListener(this);
        CoreUpdater.this.logError(
            "Error starting package download: "
                + (errorMsg != null ? errorMsg : e.getClass().getSimpleName()),
            e);
      }
    }

    boolean isComplete() {
      return complete;
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
      return null;
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
      complete = true;
      successFile = outFile;
      failed = false;
      errorMsg = null;
      CoreUpdater.this.logInfo(
          "download complete: " + outFile.getAbsolutePath() + " (size=" + outFile.length() + ")");
    }

    @Override
    public void onFailure(FetchException e) {
      complete = true;
      successFile = null;
      failed = true;
      try {
        fatal = e.isFatal();
      } catch (Throwable ignored) {
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
    public void receive(ClientEvent ce, ClientContext context) {
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
      } catch (Throwable ignored) {
        // ignore progress failures
      }
    }

    private boolean safeIsFatal(FetchException e) {
      try {
        return e.isFatal();
      } catch (Throwable ignored) {
        return false;
      }
    }

    private void markStartFailure(String message, boolean fatalFlag) {
      complete = true;
      successFile = null;
      failed = true;
      fatal = fatalFlag;
      errorMsg = message != null ? message : "Failed to start download";
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
      p.i++;
      while (Character.isDigit(peek(p))) {
        p.i++;
      }
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
