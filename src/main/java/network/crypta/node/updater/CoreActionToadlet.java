package network.crypta.node.updater;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.ReplyHeaders;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.fs.AppEnv;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP endpoint bridging update-alert actions to the package-based core updater flow.
 *
 * <p>Supports three alert-panel actions:
 *
 * <ul>
 *   <li>{@code download}: start package download through {@link CoreUpdater}
 *   <li>{@code install}: launch an OS installer for a previously downloaded package
 *   <li>{@code openStore}: open/store-install package via URL or known package ID
 * </ul>
 */
public class CoreActionToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(CoreActionToadlet.class);
  private static final String LOG_TAG = "[CoreActionToadlet]";
  private static final String INFOBOX_INFORMATION = "infobox-information";

  private final Node node;
  private final AppEnv appEnv = new AppEnv();
  private final BaseL10n l10n = NodeL10n.getBase();

  public CoreActionToadlet(HighLevelSimpleClient client, Node node) {
    super(client);
    this.node = node;
  }

  @Override
  public String path() {
    return UpdaterPaths.CORE_UPDATE_PATH;
  }

  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    redirect(ctx);
  }

  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    logInfo("POST /core-update uri=" + uri);
    if (!ctx.checkFormPassword(request)) {
      logInfo("POST /core-update rejected: invalid form password");
      return;
    }

    CoreUpdater updater = null;
    if (node.services().nodeUpdater() != null) {
      updater = node.services().nodeUpdater().getCoreUpdater();
    }
    if (updater == null) {
      redirect(ctx);
      return;
    }

    String action = request.getPartAsStringFailsafe("action", 32);
    switch (action) {
      case "download" -> handleDownload(updater, ctx);
      case "install" -> handleInstall(request, ctx);
      case "openStore" -> handleOpenStore(request, ctx);
      default -> redirect(ctx);
    }
  }

  private void handleDownload(CoreUpdater updater, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    logInfo("POST /core-update action=download");
    updater.startDownloadFromUI();
    redirect(ctx);
  }

  private void handleInstall(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String path = request.getPartAsStringFailsafe("path", 4096);
    logInfo("POST /core-update action=install path=" + path);

    File candidate = validatePath(path);
    if (candidate == null) {
      logInfo("install rejected: invalid path");
      writeMessage(ctx, false, t("invalidPath"));
      return;
    }

    InstallOutcome outcome = tryInstall(candidate);
    logInfo(
        "install result: success="
            + outcome.success
            + ", messageKey="
            + outcome.message.key
            + ", replacements="
            + outcome.message.replacements);
    writeInstallResult(ctx, outcome.success, outcome.message.render(this), candidate);
  }

  private void handleOpenStore(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String kind = request.getPartAsStringFailsafe("kind", 32);
    String id = request.getPartAsStringFailsafe("id", 256);
    String url = request.getPartAsStringFailsafe("url", 2048);
    logInfo("POST /core-update action=openStore kind=" + kind + " id=" + id + " url=" + url);

    InstallerDelegate delegate =
        switch (appEnv.osKind()) {
          case LINUX -> linuxOpenStore(kind, blankToNull(id), blankToNull(url));
          case MAC -> {
            if (!url.isBlank()) {
              yield new InstallerDelegate.Spawn(
                  new ProcessBuilder("open", url), msg("store.openingPage"));
            }
            yield new InstallerDelegate.Manual(msg("store.invalidUrl.mac"));
          }
          case WINDOWS -> {
            if (!url.isBlank()) {
              yield new InstallerDelegate.Spawn(
                  new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url),
                  msg("store.openingPage"));
            }
            yield new InstallerDelegate.Manual(msg("store.invalidUrl.windows"));
          }
          case OTHER -> new InstallerDelegate.Manual(msg("store.unsupportedPlatform"));
        };

    if (delegate instanceof InstallerDelegate.Spawn spawn) {
      try {
        spawn.pb.start();
        writeMessage(ctx, true, spawn.message.render(this));
      } catch (Throwable throwable) {
        String reason =
            throwable.getMessage() != null
                ? throwable.getMessage()
                : throwable.getClass().getSimpleName();
        writeMessage(ctx, false, msg("store.openFailed", Map.of("reason", reason)).render(this));
      }
      return;
    }

    writeMessage(ctx, false, ((InstallerDelegate.Manual) delegate).message.render(this));
  }

  private File validatePath(String rawPath) {
    if (rawPath == null || rawPath.isBlank()) {
      return null;
    }

    try {
      File base = new File(node.getNodeDir(), "updates/core").getCanonicalFile();
      File candidate = new File(rawPath).getCanonicalFile();
      Path basePath = base.toPath();
      Path candidatePath = candidate.toPath();
      return candidatePath.startsWith(basePath) ? candidate : null;
    } catch (IOException e) {
      return null;
    }
  }

  private InstallOutcome tryInstall(File file) {
    InstallerDelegate delegate =
        switch (appEnv.osKind()) {
          case WINDOWS ->
              new InstallerDelegate.Spawn(
                  new ProcessBuilder("cmd", "/c", '"' + file.getAbsolutePath() + '"'),
                  msg("installer.launched.windows"));
          case MAC -> macInstaller(file);
          case LINUX -> linuxInstaller(file);
          case OTHER -> new InstallerDelegate.Manual(msg("installer.unsupportedOs"));
        };

    try {
      if (delegate instanceof InstallerDelegate.Spawn spawn) {
        spawn.pb.start();
        return new InstallOutcome(true, spawn.message);
      }
      return new InstallOutcome(false, ((InstallerDelegate.Manual) delegate).message);
    } catch (Throwable throwable) {
      String reason =
          throwable.getMessage() != null
              ? throwable.getMessage()
              : throwable.getClass().getSimpleName();
      return new InstallOutcome(false, msg("installer.launchFailed", Map.of("reason", reason)));
    }
  }

  private InstallerDelegate macInstaller(File file) {
    return new InstallerDelegate.Spawn(
        new ProcessBuilder("open", file.getAbsolutePath()), msg("installer.launched.mac"));
  }

  private InstallerDelegate linuxInstaller(File file) {
    String lower = file.getName().toLowerCase(Locale.ROOT);
    boolean ostree = isOstree();

    if (appEnv.isServiceMode()) {
      InstallerDelegate unit = headlessUnitDelegate(file);
      if (unit != null) {
        return unit;
      }
      return new InstallerDelegate.Manual(headlessGuidance(lower, file, ostree));
    }

    if (lower.endsWith(".snap") && appEnv.isSnap()) {
      return new InstallerDelegate.Manual(msg("linux.snapSandboxManualHost"));
    }

    ProcessBuilder guiOpen = guiOpenCommand(file, appEnv.isFlatpak());
    if (guiOpen != null && !lower.endsWith(".snap")) {
      return new InstallerDelegate.Spawn(guiOpen, msg("installer.guiHandOff"));
    }

    if (lower.endsWith(".deb")) {
      return debFallback(file);
    }
    if (lower.endsWith(".rpm")) {
      return rpmFallback(file, ostree);
    }
    if (lower.endsWith(".flatpak") || lower.endsWith(".flatpakref")) {
      return flatpakFallback(file);
    }
    if (lower.endsWith(".snap")) {
      return snapFallback(file);
    }

    return new InstallerDelegate.Manual(
        msg("installer.unsupportedPackage", Map.of("name", file.getName())));
  }

  private InstallerDelegate linuxOpenStore(String kind, String id, String url) {
    boolean preferHost = appEnv.isFlatpak();

    if ("snap".equalsIgnoreCase(kind) && appEnv.isSnap()) {
      return new InstallerDelegate.Manual(
          msg("store.snapSandboxManual", Map.of("package", id != null ? id : "<package>")));
    }

    String targetUrl = url;
    if (targetUrl == null && id != null) {
      if ("snap".equalsIgnoreCase(kind)) {
        targetUrl = "snap://" + id;
      } else if ("flatpak".equalsIgnoreCase(kind)) {
        targetUrl =
            appEnv.onPath("gio") || appEnv.onPath("xdg-open")
                ? "appstream://" + id
                : "https://flathub.org/apps/" + id;
      }
    }

    if (targetUrl != null) {
      ProcessBuilder opener = guiOpenUrlCommand(targetUrl, preferHost);
      if (opener != null) {
        return new InstallerDelegate.Spawn(
            opener, msg("store.openingSpecificPage", Map.of("url", targetUrl)));
      }
    }

    if ("flatpak".equalsIgnoreCase(kind) && id != null && appEnv.onPath("flatpak")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("flatpak", "install", "--assumeyes", "--user", "flathub", id),
          msg("store.installFlathub", Map.of("id", id)));
    }
    if ("snap".equalsIgnoreCase(kind)
        && id != null
        && appEnv.onPath("pkexec")
        && appEnv.onPath("snap")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "snap", "install", id),
          msg("store.installSnap", Map.of("id", id)));
    }

    return new InstallerDelegate.Manual(
        msg("store.unableToOpen", Map.of("idOrUrl", id != null ? id : (url != null ? url : "?"))));
  }

  private ProcessBuilder guiOpenCommand(File file, boolean preferHost) {
    return guiOpenCommandForTarget(file.getAbsolutePath(), preferHost);
  }

  private ProcessBuilder guiOpenUrlCommand(String url, boolean preferHost) {
    return guiOpenCommandForTarget(url, preferHost);
  }

  private ProcessBuilder guiOpenCommandForTarget(String target, boolean preferHost) {
    if (preferHost && appEnv.onPath("xdg-open")) {
      return new ProcessBuilder("xdg-open", target);
    }

    List<String> opener = pickGuiOpener();
    if (opener == null) {
      return null;
    }

    if (preferHost && appEnv.onPath("flatpak-spawn")) {
      List<String> cmd = new java.util.ArrayList<>();
      cmd.add("flatpak-spawn");
      cmd.add("--host");
      cmd.addAll(opener);
      cmd.add(target);
      return new ProcessBuilder(cmd);
    }

    List<String> cmd = new java.util.ArrayList<>(opener);
    cmd.add(target);
    return new ProcessBuilder(cmd);
  }

  private List<String> pickGuiOpener() {
    if (appEnv.onPath("gio")) {
      return List.of("gio", "open");
    }
    if (appEnv.onPath("xdg-open")) {
      return List.of("xdg-open");
    }
    return null;
  }

  private InstallerDelegate debFallback(File file) {
    String path = file.getAbsolutePath();
    if (appEnv.onPath("pkcon")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkcon", "install-local", "-y", path), msg("linux.packagekitInstall"));
    }
    if (appEnv.onPath("pkexec") && appEnv.onPath("apt-get")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "apt-get", "install", "-y", "./" + file.getName())
              .directory(file.getParentFile()),
          msg("linux.aptInstall"));
    }
    if (appEnv.onPath("pkexec") && appEnv.onPath("dpkg")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "dpkg", "-i", path), msg("linux.dpkgInstall"));
    }
    return new InstallerDelegate.Manual(manualMsg("DEB", path));
  }

  private InstallerDelegate rpmFallback(File file, boolean ostree) {
    String path = file.getAbsolutePath();
    if (ostree) {
      return new InstallerDelegate.Manual(msg("linux.rpmOstreeManual", Map.of("path", path)));
    }
    if (appEnv.onPath("pkcon")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkcon", "install-local", "-y", path), msg("linux.packagekitInstall"));
    }
    if (appEnv.onPath("pkexec") && appEnv.onPath("dnf")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "dnf", "install", "-y", path), msg("linux.dnfInstall"));
    }
    if (appEnv.onPath("pkexec") && appEnv.onPath("zypper")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "zypper", "--non-interactive", "install", path),
          msg("linux.zypperInstall"));
    }
    if (appEnv.onPath("pkexec") && appEnv.onPath("rpm")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "rpm", "-Uvh", path), msg("linux.rpmInstall"));
    }
    return new InstallerDelegate.Manual(manualMsg("RPM", path));
  }

  private InstallerDelegate flatpakFallback(File file) {
    String path = file.getAbsolutePath();
    if (!appEnv.onPath("flatpak")) {
      return new InstallerDelegate.Manual(manualMsg("Flatpak", path));
    }
    return new InstallerDelegate.Spawn(
        new ProcessBuilder("flatpak", "install", "--assumeyes", "--user", path),
        msg("linux.flatpakInstall"));
  }

  private InstallerDelegate snapFallback(File file) {
    String path = file.getAbsolutePath();
    if (appEnv.isSnap()) {
      return new InstallerDelegate.Manual(msg("linux.snapSandboxManualHost"));
    }
    if (appEnv.onPath("pkexec") && appEnv.onPath("snap")) {
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("pkexec", "snap", "install", "--dangerous", path),
          msg("linux.snapInstall"));
    }
    return new InstallerDelegate.Manual(msg("linux.snapManualHost", Map.of("path", path)));
  }

  private LocalMessage headlessGuidance(String lowerName, File file, boolean ostree) {
    String path = file.getAbsolutePath();
    String tag;
    if (lowerName.endsWith(".deb")) {
      tag = "DEB";
    } else if (lowerName.endsWith(".rpm")) {
      tag = ostree ? "RPM-OSTREE" : "RPM";
    } else if (lowerName.endsWith(".flatpak") || lowerName.endsWith(".flatpakref")) {
      tag = "Flatpak";
    } else if (lowerName.endsWith(".snap")) {
      tag = "Snap";
    } else {
      tag = "Package";
    }

    String command =
        switch (tag) {
          case "DEB" -> "pkcon install-local -y '" + path + "'";
          case "RPM-OSTREE" -> "rpm-ostree install '" + path + "'";
          case "RPM" -> "pkcon install-local -y '" + path + "'";
          case "Flatpak" -> "flatpak install --assumeyes --system '" + path + "'";
          case "Snap" -> "snap install --dangerous '" + path + "'";
          default -> "<install-command> '" + path + "'";
        };

    String extra = "RPM-OSTREE".equals(tag) ? " " + t("linux.headlessGuidanceExtra") : "";
    return msg("linux.headlessGuidance", Map.of("command", command, "extra", extra));
  }

  private LocalMessage manualMsg(String kind, String path) {
    return msg("linux.manualGuidance", Map.of("kind", kind, "path", path));
  }

  private InstallerDelegate headlessUnitDelegate(File file) {
    if (!appEnv.onPath("systemctl") || !appEnv.onPath("systemd-escape")) {
      return null;
    }

    try {
      Process escape =
          new ProcessBuilder("systemd-escape", "--path", file.getAbsolutePath())
              .redirectErrorStream(true)
              .start();
      String escaped;
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(escape.getInputStream(), StandardCharsets.UTF_8))) {
        escaped = reader.readLine();
      }
      escape.waitFor();

      if (escape.exitValue() != 0 || escaped == null || escaped.isBlank()) {
        return null;
      }

      String unit = "cryptad-core-install@" + escaped.trim() + ".service";
      return new InstallerDelegate.Spawn(
          new ProcessBuilder("systemctl", "start", unit),
          msg("linux.headlessUnit", Map.of("unit", unit)));
    } catch (Throwable ignored) {
      return null;
    }
  }

  private boolean isOstree() {
    return new File("/run/ostree-booted").exists() || appEnv.onPath("rpm-ostree");
  }

  private void redirect(ToadletContext ctx) throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", "/alerts/");
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  private void writeMessage(ToadletContext ctx, boolean success, String message)
      throws ToadletContextClosedException, IOException {
    ResultPage page = renderResultPage(ctx, success, message);
    addHomepageLink(page.content);
    writeHTMLReply(
        ctx, ReplyHeaders.of(200, "OK", "text/html; charset=utf-8"), page.page.generate());
  }

  private void writeInstallResult(ToadletContext ctx, boolean success, String message, File file)
      throws ToadletContextClosedException, IOException {
    ResultPage page = renderResultPage(ctx, success, message);
    addInstallGuidance(page.content, page.pageMaker, file);
    addHomepageLink(page.content);
    writeHTMLReply(
        ctx, ReplyHeaders.of(200, "OK", "text/html; charset=utf-8"), page.page.generate());
  }

  private ResultPage renderResultPage(ToadletContext ctx, boolean success, String message) {
    PageMaker pm = ctx.getPageMaker();
    String title = success ? t("install.titleSuccess") : t("install.titleFailure");
    PageNode page =
        pm.getPageNode(
            title,
            ctx,
            new PageMaker.RenderParameters().renderNavigationLinks(true).renderStatus(true));
    HTMLNode content = page.getContentNode();
    HTMLNode box =
        pm.getInfobox(
            success ? "infobox-success" : "infobox-warning",
            title,
            content,
            "core-installer-result",
            true);
    box.addChild("p").addChild("#", message);
    return new ResultPage(pm, page, content);
  }

  private void addInstallGuidance(HTMLNode content, PageMaker pm, File file) {
    String lower = file.getName().toLowerCase(Locale.ROOT);
    switch (appEnv.osKind()) {
      case MAC -> {
        if (lower.endsWith(".dmg")) {
          macDmgGuidance(content, pm);
        }
      }
      case WINDOWS -> {
        if (lower.endsWith(".exe")) {
          windowsExeGuidance(content, pm);
        }
      }
      case LINUX -> {
        if (lower.endsWith(".snap")) {
          linuxSnapGuidance(content, pm, file, appEnv.onPath("snap"));
        }
      }
      case OTHER -> {
        // no extra guidance
      }
    }
  }

  private void macDmgGuidance(HTMLNode content, PageMaker pm) {
    HTMLNode box =
        pm.getInfobox(
            INFOBOX_INFORMATION,
            t("macGuidance.title"),
            content,
            "core-install-guidance-macos",
            true);
    box.addChild("p").addChild("#", t("macGuidance.intro"));
    HTMLNode steps = box.addChild("ul");
    steps.addChild("li").addChild("#", t("macGuidance.stepDrag"));
    steps.addChild("li").addChild("#", t("macGuidance.stepOpenConfirm"));
    steps.addChild("li").addChild("#", t("macGuidance.stepSettings"));
    box.addChild("pre").addChild("#", t("macGuidance.commandXattr"));
    box.addChild("pre").addChild("#", t("macGuidance.commandSpctl"));
  }

  private void windowsExeGuidance(HTMLNode content, PageMaker pm) {
    HTMLNode box =
        pm.getInfobox(
            INFOBOX_INFORMATION,
            t("windowsGuidance.title"),
            content,
            "core-install-guidance-windows",
            true);
    box.addChild("p").addChild("#", t("windowsGuidance.intro"));
    HTMLNode steps = box.addChild("ul");
    steps.addChild("li").addChild("#", t("windowsGuidance.stepRunAnyway"));
    steps.addChild("li").addChild("#", t("windowsGuidance.stepUnblock"));
    box.addChild("pre").addChild("#", t("windowsGuidance.commandUnblock"));
    box.addChild("pre").addChild("#", t("windowsGuidance.commandHash"));
  }

  private void linuxSnapGuidance(HTMLNode content, PageMaker pm, File file, boolean hasSnap) {
    HTMLNode box =
        pm.getInfobox(
            INFOBOX_INFORMATION,
            t("linuxSnapGuidance.title"),
            content,
            "core-install-guidance-snap",
            true);
    box.addChild("p").addChild("#", t("linuxSnapGuidance.intro"));
    if (!hasSnap) {
      box.addChild("pre").addChild("#", t("linuxSnapGuidance.commandInstallSnapd"));
      box.addChild("pre").addChild("#", t("linuxSnapGuidance.commandEnableSnapd"));
    }
    String command = t("linuxSnapGuidance.commandRun", Map.of("path", file.getAbsolutePath()));
    HTMLNode cmdRow = box.addChild("div", "class", "copy-row");
    cmdRow.addChild("span", "class", "label", t("linuxSnapGuidance.runCommandLabel"));
    cmdRow.addChild(
        "input",
        new String[] {"type", "readonly", "value", "class"},
        new String[] {"text", "readonly", command, "copy-input"});
  }

  private String t(String key) {
    return t(key, Map.of());
  }

  private String t(String key, Map<String, String> replacements) {
    if (replacements.isEmpty()) {
      return l10n.getString("CoreActionToadlet." + key);
    }

    String[] patterns = new String[replacements.size()];
    String[] values = new String[replacements.size()];
    int i = 0;
    for (Map.Entry<String, String> entry : replacements.entrySet()) {
      patterns[i] = entry.getKey();
      values[i] = entry.getValue();
      i++;
    }
    return l10n.getString("CoreActionToadlet." + key, patterns, values);
  }

  private LocalMessage msg(String key) {
    return msg(key, Map.of());
  }

  private LocalMessage msg(String key, Map<String, String> replacements) {
    return new LocalMessage(key, new LinkedHashMap<>(replacements));
  }

  private static String blankToNull(String s) {
    return s == null || s.isBlank() ? null : s;
  }

  private void logInfo(String message) {
    LOG.info("{} {}", LOG_TAG, message);
  }

  private record LocalMessage(String key, Map<String, String> replacements) {
    String render(CoreActionToadlet owner) {
      return owner.t(key, replacements);
    }
  }

  private record InstallOutcome(boolean success, LocalMessage message) {}

  private sealed interface InstallerDelegate {
    record Spawn(ProcessBuilder pb, LocalMessage message) implements InstallerDelegate {}

    record Manual(LocalMessage message) implements InstallerDelegate {}
  }

  private record ResultPage(PageMaker pageMaker, PageNode page, HTMLNode content) {}
}
