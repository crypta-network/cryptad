package network.crypta.clients.http.updater;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.ReplyHeaders;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.fs.AppEnv;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.updater.UpdaterPaths;
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
 *   <li>{@code download}: start package download through {@link CoreUpdateActionPort}
 *   <li>{@code install}: launch an OS installer for a previously downloaded package
 *   <li>{@code openStore}: open/store-install package via URL or known package ID
 * </ul>
 */
public class CoreActionToadlet extends Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(CoreActionToadlet.class);
  private static final String LOG_TAG = "[CoreActionToadlet]";
  private static final String INFOBOX_INFORMATION = "infobox-information";
  private static final String ACTION_DOWNLOAD = "download";
  private static final String ACTION_INSTALL = "install";
  private static final String ACTION_OPEN_STORE = "openStore";
  private static final String KIND_SNAP = "snap";
  private static final String KIND_FLATPAK = "flatpak";
  private static final String EXT_DEB = ".deb";
  private static final String EXT_DMG = ".dmg";
  private static final String EXT_EXE = ".exe";
  private static final String EXT_FLATPAK = ".flatpak";
  private static final String EXT_FLATPAKREF = ".flatpakref";
  private static final String EXT_RPM = ".rpm";
  private static final String EXT_SNAP = ".snap";
  private static final String TAG_DEB = "DEB";
  private static final String TAG_FLATPAK = "Flatpak";
  private static final String TAG_PACKAGE = "Package";
  private static final String TAG_RPM = "RPM";
  private static final String TAG_RPM_OSTREE = "RPM-OSTREE";
  private static final String TAG_SNAP = "Snap";
  private static final String CMD_APT_GET = "apt-get";
  private static final String CMD_CMD = "cmd";
  private static final String CMD_DNF = "dnf";
  private static final String CMD_DPKG = "dpkg";
  private static final String CMD_FLATPAK = "flatpak";
  private static final String CMD_FLATPAK_SPAWN = "flatpak-spawn";
  private static final String CMD_GIO = "gio";
  private static final String CMD_OPEN = "open";
  private static final String CMD_PKCON = "pkcon";
  private static final String CMD_PKEXEC = "pkexec";
  private static final String CMD_RPM = "rpm";
  private static final String CMD_RPM_OSTREE = "rpm-ostree";
  private static final String CMD_RUN_DLL_32 = "rundll32";
  private static final String CMD_SNAP = "snap";
  private static final String CMD_SYSTEMCTL = "systemctl";
  private static final String CMD_SYSTEMD_ESCAPE = "systemd-escape";
  private static final String CMD_XDG_OPEN = "xdg-open";
  private static final String CMD_ZYPPER = "zypper";
  private static final String FLATHUB_URL_PREFIX = "https://flathub.org/apps/";
  private static final String MSG_INSTALLER_UNSUPPORTED_OS = "installer.unsupportedOs";
  private static final String PATH_OSTREE_BOOTED = "/run/ostree-booted";
  private static final String SCHEME_APPSTREAM = "appstream://";
  private static final String SCHEME_SNAP = "snap://";
  private static final String HTML_ATTR_CLASS = "class";
  private static final List<String> TRUSTED_UNIX_BIN_DIRS =
      List.of("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin");

  private final CoreUpdateActionPort coreUpdateActionPort;
  private final AppEnv appEnv = new AppEnv();
  private final BaseL10n l10n = NodeL10n.getBase();

  /**
   * Creates the toadlet that handles core-update action requests from the updater UI.
   *
   * <p>The provided runtime port is used to access updater availability, download start, and
   * installer path validation while the toadlet keeps runtime environment and response rendering
   * behavior in the HTTP layer.
   *
   * @param coreUpdateActionPort runtime port that exposes the remaining daemon-backed updater
   *     actions needed by this toadlet
   */
  public CoreActionToadlet(CoreUpdateActionPort coreUpdateActionPort) {
    super();
    this.coreUpdateActionPort =
        Objects.requireNonNull(coreUpdateActionPort, "coreUpdateActionPort");
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

  /**
   * Handles action form submissions for core updater operations.
   *
   * <p>Accepted actions include download start, local installer launch, and package-store opening.
   * Requests are rejected when form-password validation fails. Download requests are dispatched
   * directly through the runtime port, so updater lookup and start happen as one operation, while
   * the remaining actions still redirect when no core updater is available. Unknown actions are
   * redirected back to the updater path.
   *
   * @param uri request URI for the POST action endpoint
   * @param request parsed HTTP form request containing action and payload fields
   * @param ctx request context used for authentication, redirects, and response writes
   * @throws ToadletContextClosedException if the client connection is closed before response
   *     writing
   * @throws IOException if response generation or downstream action dispatch fails with I/O errors
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    logInfo("POST /core-update uri=" + uri);
    if (!ctx.checkFormPassword(request)) {
      logInfo("POST /core-update rejected: invalid form password");
      return;
    }

    String action = request.getPartAsStringFailsafe("action", 32);
    if (ACTION_DOWNLOAD.equals(action)) {
      handleDownload(ctx);
      return;
    }

    if (!coreUpdateActionPort.isCoreUpdaterAvailable()) {
      redirect(ctx);
      return;
    }

    switch (action) {
      case ACTION_INSTALL -> handleInstall(request, ctx);
      case ACTION_OPEN_STORE -> handleOpenStore(request, ctx);
      default -> redirect(ctx);
    }
  }

  private void handleDownload(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    logInfo("POST /core-update action=download");
    coreUpdateActionPort.startCoreDownloadFromUi();
    redirect(ctx);
  }

  private void handleInstall(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String path = request.getPartAsStringFailsafe("path", 4096);
    logInfo("POST /core-update action=" + ACTION_INSTALL + " path=" + path);

    File candidate =
        coreUpdateActionPort.resolveDownloadedInstaller(path).map(Path::toFile).orElse(null);
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
              ProcessBuilder openUrl = processBuilder(CMD_OPEN, url);
              if (openUrl != null) {
                yield new InstallerDelegate.Spawn(openUrl, msg("store.openingPage"));
              }
            }
            yield new InstallerDelegate.Manual(msg("store.invalidUrl.mac"));
          }
          case WINDOWS -> {
            if (!url.isBlank()) {
              ProcessBuilder openUrl =
                  processBuilder(CMD_RUN_DLL_32, "url.dll,FileProtocolHandler", url);
              if (openUrl != null) {
                yield new InstallerDelegate.Spawn(openUrl, msg("store.openingPage"));
              }
            }
            yield new InstallerDelegate.Manual(msg("store.invalidUrl.windows"));
          }
          case OTHER -> new InstallerDelegate.Manual(msg("store.unsupportedPlatform"));
        };

    if (delegate instanceof InstallerDelegate.Spawn(ProcessBuilder pb, LocalMessage message)) {
      try {
        pb.start();
        writeMessage(ctx, true, message.render(this));
      } catch (Exception throwable) {
        String reason =
            throwable.getMessage() != null
                ? throwable.getMessage()
                : throwable.getClass().getSimpleName();
        writeMessage(ctx, false, msg("store.openFailed", Map.of("reason", reason)).render(this));
      }
      return;
    }

    if (delegate instanceof InstallerDelegate.Manual(LocalMessage message)) {
      writeMessage(ctx, false, message.render(this));
    }
  }

  private InstallOutcome tryInstall(File file) {
    InstallerDelegate delegate =
        switch (appEnv.osKind()) {
          case WINDOWS ->
              spawn(
                  CMD_CMD,
                  msg("installer.launched.windows"),
                  "/c",
                  '"' + file.getAbsolutePath() + '"');
          case MAC -> macInstaller(file);
          case LINUX -> linuxInstaller(file);
          case OTHER -> new InstallerDelegate.Manual(msg(MSG_INSTALLER_UNSUPPORTED_OS));
        };

    try {
      if (delegate instanceof InstallerDelegate.Spawn(ProcessBuilder pb, LocalMessage message)) {
        pb.start();
        return new InstallOutcome(true, message);
      }
      if (delegate instanceof InstallerDelegate.Manual(LocalMessage message)) {
        return new InstallOutcome(false, message);
      }
      return new InstallOutcome(false, msg(MSG_INSTALLER_UNSUPPORTED_OS));
    } catch (Exception throwable) {
      String reason =
          throwable.getMessage() != null
              ? throwable.getMessage()
              : throwable.getClass().getSimpleName();
      return new InstallOutcome(false, msg("installer.launchFailed", Map.of("reason", reason)));
    }
  }

  private InstallerDelegate macInstaller(File file) {
    return spawn(CMD_OPEN, msg("installer.launched.mac"), file.getAbsolutePath());
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

    if (lower.endsWith(EXT_SNAP) && appEnv.isSnap()) {
      return new InstallerDelegate.Manual(msg("linux.snapSandboxManualHost"));
    }

    ProcessBuilder guiOpen = guiOpenCommand(file, appEnv.isFlatpak());
    if (guiOpen != null && !lower.endsWith(EXT_SNAP)) {
      return new InstallerDelegate.Spawn(guiOpen, msg("installer.guiHandOff"));
    }

    if (lower.endsWith(EXT_DEB)) {
      return debFallback(file);
    }
    if (lower.endsWith(EXT_RPM)) {
      return rpmFallback(file, ostree);
    }
    if (isFlatpakPackage(lower)) {
      return flatpakFallback(file);
    }
    if (lower.endsWith(EXT_SNAP)) {
      return snapFallback(file);
    }

    return new InstallerDelegate.Manual(
        msg("installer.unsupportedPackage", Map.of("name", file.getName())));
  }

  private InstallerDelegate linuxOpenStore(String kind, String id, String url) {
    boolean preferHost = appEnv.isFlatpak();

    if (isKind(kind, KIND_SNAP) && appEnv.isSnap()) {
      return new InstallerDelegate.Manual(
          msg("store.snapSandboxManual", Map.of("package", id != null ? id : "<package>")));
    }

    String targetUrl = resolveStoreUrl(kind, id, url);
    InstallerDelegate urlDelegate = openStoreUrl(targetUrl, preferHost);
    if (urlDelegate != null) {
      return urlDelegate;
    }

    InstallerDelegate installDelegate = storeInstallDelegate(kind, id);
    if (installDelegate != null) {
      return installDelegate;
    }

    String idOrUrl = resolveIdOrUrl(id, url);
    return new InstallerDelegate.Manual(msg("store.unableToOpen", Map.of("idOrUrl", idOrUrl)));
  }

  private boolean isFlatpakPackage(String lowerName) {
    return lowerName.endsWith(EXT_FLATPAK) || lowerName.endsWith(EXT_FLATPAKREF);
  }

  private boolean isKind(String kind, String expected) {
    return expected.equalsIgnoreCase(kind);
  }

  private String resolveStoreUrl(String kind, String id, String url) {
    if (url != null) {
      return url;
    }
    if (id == null) {
      return null;
    }
    if (isKind(kind, KIND_SNAP)) {
      return SCHEME_SNAP + id;
    }
    if (isKind(kind, KIND_FLATPAK)) {
      return hasCommand(CMD_GIO) || hasCommand(CMD_XDG_OPEN)
          ? SCHEME_APPSTREAM + id
          : FLATHUB_URL_PREFIX + id;
    }
    return null;
  }

  private InstallerDelegate openStoreUrl(String targetUrl, boolean preferHost) {
    if (targetUrl == null) {
      return null;
    }
    ProcessBuilder opener = guiOpenUrlCommand(targetUrl, preferHost);
    if (opener == null) {
      return null;
    }
    return new InstallerDelegate.Spawn(
        opener, msg("store.openingSpecificPage", Map.of("url", targetUrl)));
  }

  private String resolveIdOrUrl(String id, String url) {
    if (id != null) {
      return id;
    }
    return url != null ? url : "?";
  }

  private InstallerDelegate storeInstallDelegate(String kind, String id) {
    if (id == null) {
      return null;
    }
    if (isKind(kind, KIND_FLATPAK) && hasCommand(CMD_FLATPAK)) {
      return spawn(
          CMD_FLATPAK,
          msg("store.installFlathub", Map.of("id", id)),
          ACTION_INSTALL,
          "--assumeyes",
          "--user",
          "flathub",
          id);
    }
    if (isKind(kind, KIND_SNAP) && hasCommand(CMD_PKEXEC) && hasCommand(CMD_SNAP)) {
      String pkexec = commandPath(CMD_PKEXEC);
      String snap = commandPath(CMD_SNAP);
      if (pkexec != null && snap != null) {
        return new InstallerDelegate.Spawn(
            new ProcessBuilder(pkexec, snap, ACTION_INSTALL, id),
            msg("store.installSnap", Map.of("id", id)));
      }
    }
    return null;
  }

  private ProcessBuilder guiOpenCommand(File file, boolean preferHost) {
    return guiOpenCommandForTarget(file.getAbsolutePath(), preferHost);
  }

  private ProcessBuilder guiOpenUrlCommand(String url, boolean preferHost) {
    return guiOpenCommandForTarget(url, preferHost);
  }

  private ProcessBuilder guiOpenCommandForTarget(String target, boolean preferHost) {
    if (preferHost) {
      ProcessBuilder direct = processBuilder(CMD_XDG_OPEN, target);
      if (direct != null) {
        return direct;
      }
    }

    List<String> opener = pickGuiOpener();
    if (opener.isEmpty()) {
      return null;
    }

    String flatpakSpawn = preferHost ? commandPath(CMD_FLATPAK_SPAWN) : null;
    if (flatpakSpawn != null) {
      List<String> cmd = new ArrayList<>();
      cmd.add(flatpakSpawn);
      cmd.add("--host");
      cmd.addAll(opener);
      cmd.add(target);
      return new ProcessBuilder(cmd);
    }

    List<String> cmd = new ArrayList<>(opener);
    cmd.add(target);
    return new ProcessBuilder(cmd);
  }

  private List<String> pickGuiOpener() {
    String gio = commandPath(CMD_GIO);
    if (gio != null) {
      return List.of(gio, CMD_OPEN);
    }
    String xdgOpen = commandPath(CMD_XDG_OPEN);
    if (xdgOpen != null) {
      return List.of(xdgOpen);
    }
    return List.of();
  }

  private InstallerDelegate debFallback(File file) {
    String path = file.getAbsolutePath();
    if (hasCommand(CMD_PKCON)) {
      return spawn(CMD_PKCON, msg("linux.packagekitInstall"), "install-local", "-y", path);
    }
    if (hasCommand(CMD_PKEXEC) && hasCommand(CMD_APT_GET)) {
      String pkexec = commandPath(CMD_PKEXEC);
      String aptGet = commandPath(CMD_APT_GET);
      if (pkexec != null && aptGet != null) {
        return new InstallerDelegate.Spawn(
            new ProcessBuilder(pkexec, aptGet, ACTION_INSTALL, "-y", "./" + file.getName())
                .directory(file.getParentFile()),
            msg("linux.aptInstall"));
      }
    }
    if (hasCommand(CMD_PKEXEC) && hasCommand(CMD_DPKG)) {
      String pkexec = commandPath(CMD_PKEXEC);
      String dpkg = commandPath(CMD_DPKG);
      if (pkexec != null && dpkg != null) {
        return new InstallerDelegate.Spawn(
            new ProcessBuilder(pkexec, dpkg, "-i", path), msg("linux.dpkgInstall"));
      }
    }
    return new InstallerDelegate.Manual(manualMsg(TAG_DEB, path));
  }

  private InstallerDelegate rpmFallback(File file, boolean ostree) {
    String path = file.getAbsolutePath();
    if (ostree) {
      return new InstallerDelegate.Manual(msg("linux.rpmOstreeManual", Map.of("path", path)));
    }
    if (hasCommand(CMD_PKCON)) {
      return spawn(CMD_PKCON, msg("linux.packagekitInstall"), "install-local", "-y", path);
    }
    InstallerDelegate dnf =
        spawnViaPkexec(CMD_DNF, msg("linux.dnfInstall"), ACTION_INSTALL, "-y", path);
    if (dnf != null) {
      return dnf;
    }
    InstallerDelegate zypper =
        spawnViaPkexec(
            CMD_ZYPPER, msg("linux.zypperInstall"), "--non-interactive", ACTION_INSTALL, path);
    if (zypper != null) {
      return zypper;
    }
    InstallerDelegate rpm = spawnViaPkexec(CMD_RPM, msg("linux.rpmInstall"), "-Uvh", path);
    if (rpm != null) {
      return rpm;
    }
    return new InstallerDelegate.Manual(manualMsg(TAG_RPM, path));
  }

  private InstallerDelegate spawnViaPkexec(String command, LocalMessage message, String... args) {
    if (!hasCommand(CMD_PKEXEC) || !hasCommand(command)) {
      return null;
    }
    String pkexec = commandPath(CMD_PKEXEC);
    String executable = commandPath(command);
    if (pkexec == null || executable == null) {
      return null;
    }
    List<String> cmd = new ArrayList<>();
    cmd.add(pkexec);
    cmd.add(executable);
    cmd.addAll(List.of(args));
    return new InstallerDelegate.Spawn(new ProcessBuilder(cmd), message);
  }

  private InstallerDelegate flatpakFallback(File file) {
    String path = file.getAbsolutePath();
    if (!hasCommand(CMD_FLATPAK)) {
      return new InstallerDelegate.Manual(manualMsg(TAG_FLATPAK, path));
    }
    return spawn(
        CMD_FLATPAK, msg("linux.flatpakInstall"), ACTION_INSTALL, "--assumeyes", "--user", path);
  }

  private InstallerDelegate snapFallback(File file) {
    String path = file.getAbsolutePath();
    if (appEnv.isSnap()) {
      return new InstallerDelegate.Manual(msg("linux.snapSandboxManualHost"));
    }
    if (hasCommand(CMD_PKEXEC) && hasCommand(CMD_SNAP)) {
      String pkexec = commandPath(CMD_PKEXEC);
      String snap = commandPath(CMD_SNAP);
      if (pkexec != null && snap != null) {
        return new InstallerDelegate.Spawn(
            new ProcessBuilder(pkexec, snap, ACTION_INSTALL, "--dangerous", path),
            msg("linux.snapInstall"));
      }
    }
    return new InstallerDelegate.Manual(msg("linux.snapManualHost", Map.of("path", path)));
  }

  private LocalMessage headlessGuidance(String lowerName, File file, boolean ostree) {
    String path = file.getAbsolutePath();
    String tag;
    if (lowerName.endsWith(EXT_DEB)) {
      tag = TAG_DEB;
    } else if (lowerName.endsWith(EXT_RPM)) {
      tag = ostree ? TAG_RPM_OSTREE : TAG_RPM;
    } else if (isFlatpakPackage(lowerName)) {
      tag = TAG_FLATPAK;
    } else if (lowerName.endsWith(EXT_SNAP)) {
      tag = TAG_SNAP;
    } else {
      tag = TAG_PACKAGE;
    }

    String command =
        switch (tag) {
          case TAG_DEB, TAG_RPM -> CMD_PKCON + " install-local -y '" + path + "'";
          case TAG_RPM_OSTREE -> CMD_RPM_OSTREE + " " + ACTION_INSTALL + " '" + path + "'";
          case TAG_FLATPAK ->
              CMD_FLATPAK + " " + ACTION_INSTALL + " --assumeyes --system '" + path + "'";
          case TAG_SNAP -> CMD_SNAP + " " + ACTION_INSTALL + " --dangerous '" + path + "'";
          default -> "<install-command> '" + path + "'";
        };

    String extra = TAG_RPM_OSTREE.equals(tag) ? " " + t("linux.headlessGuidanceExtra") : "";
    return msg("linux.headlessGuidance", Map.of("command", command, "extra", extra));
  }

  private LocalMessage manualMsg(String kind, String path) {
    return msg("linux.manualGuidance", Map.of("kind", kind, "path", path));
  }

  private InstallerDelegate spawn(String command, LocalMessage message, String... args) {
    ProcessBuilder pb = processBuilder(command, args);
    return pb != null
        ? new InstallerDelegate.Spawn(pb, message)
        : new InstallerDelegate.Manual(msg(MSG_INSTALLER_UNSUPPORTED_OS));
  }

  private boolean hasCommand(String command) {
    return commandPath(command) != null;
  }

  private String commandPath(String command) {
    if (command == null || command.isBlank()) {
      return null;
    }
    if (command.contains("/") || command.contains("\\")) {
      File explicit = new File(command);
      return explicit.isFile() && explicit.canExecute() ? explicit.getAbsolutePath() : null;
    }
    return appEnv.osKind() == AppEnv.OsKind.WINDOWS
        ? resolveWindowsCommand(command)
        : resolveUnixCommand(command);
  }

  private String resolveUnixCommand(String command) {
    for (String dir : TRUSTED_UNIX_BIN_DIRS) {
      File candidate = new File(dir, command);
      if (candidate.isFile() && candidate.canExecute()) {
        return candidate.getAbsolutePath();
      }
    }
    return null;
  }

  private String resolveWindowsCommand(String command) {
    String exe = command.toLowerCase(Locale.ROOT).endsWith(EXT_EXE) ? command : command + EXT_EXE;
    List<String> roots = new ArrayList<>();
    String systemRoot = System.getenv("SystemRoot");
    if (systemRoot != null && !systemRoot.isBlank()) {
      roots.add(systemRoot);
    }
    String winDir = System.getenv("WINDIR");
    if (winDir != null && !winDir.isBlank()) {
      roots.add(winDir);
    }
    roots.add("C:\\Windows");

    for (String root : roots) {
      File candidate = new File(root + "\\System32", exe);
      if (candidate.isFile() && candidate.canExecute()) {
        return candidate.getAbsolutePath();
      }
    }
    return null;
  }

  private ProcessBuilder processBuilder(String command, String... args) {
    String executable = commandPath(command);
    if (executable == null) {
      return null;
    }
    List<String> cmd = new ArrayList<>();
    cmd.add(executable);
    cmd.addAll(List.of(args));
    return new ProcessBuilder(cmd);
  }

  private InstallerDelegate headlessUnitDelegate(File file) {
    if (!hasCommand(CMD_SYSTEMCTL) || !hasCommand(CMD_SYSTEMD_ESCAPE)) {
      return null;
    }

    try {
      ProcessBuilder escapeBuilder =
          processBuilder(CMD_SYSTEMD_ESCAPE, "--path", file.getAbsolutePath());
      if (escapeBuilder == null) {
        return null;
      }
      Process escape = escapeBuilder.redirectErrorStream(true).start();
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
      return spawn(CMD_SYSTEMCTL, msg("linux.headlessUnit", Map.of("unit", unit)), "start", unit);
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return null;
    } catch (Exception _) {
      return null;
    }
  }

  private boolean isOstree() {
    return new File(PATH_OSTREE_BOOTED).exists() || hasCommand(CMD_RPM_OSTREE);
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
      case AppEnv.OsKind os when os == AppEnv.OsKind.MAC && lower.endsWith(EXT_DMG) ->
          macDmgGuidance(content, pm);
      case AppEnv.OsKind os when os == AppEnv.OsKind.WINDOWS && lower.endsWith(EXT_EXE) ->
          windowsExeGuidance(content, pm);
      case AppEnv.OsKind os when os == AppEnv.OsKind.LINUX && lower.endsWith(EXT_SNAP) ->
          linuxSnapGuidance(content, pm, file, hasCommand(CMD_SNAP));
      default -> {
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
    HTMLNode cmdRow = box.addChild("div", HTML_ATTR_CLASS, "copy-row");
    cmdRow.addChild("span", HTML_ATTR_CLASS, "label", t("linuxSnapGuidance.runCommandLabel"));
    cmdRow.addChild(
        "input",
        new String[] {"type", "readonly", "value", HTML_ATTR_CLASS},
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
