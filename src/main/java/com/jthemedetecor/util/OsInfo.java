package com.jthemedetecor.util;

import io.github.g00fy2.versioncompare.Version;
import java.util.Locale;
import org.jetbrains.annotations.NotNull;
import oshi.PlatformEnum;
import oshi.SystemInfo;
import oshi.software.os.OperatingSystem;

public class OsInfo {
  private static final PlatformEnum PLATFORM_TYPE;
  private static final String FAMILY;
  private static final String VERSION;

  static {
    final SystemInfo systemInfo = new SystemInfo();
    final OperatingSystem osInfo = systemInfo.getOperatingSystem();
    final OperatingSystem.OSVersionInfo osVersionInfo = osInfo.getVersionInfo();

    PLATFORM_TYPE = SystemInfo.getCurrentPlatform();
    FAMILY = osInfo.getFamily();
    VERSION = osVersionInfo.getVersion();
  }

  public static boolean isWindows10OrLater() {
    return hasTypeAndVersionOrHigher(PlatformEnum.WINDOWS, "10");
  }

  public static boolean isLinux() {
    return hasType(PlatformEnum.LINUX);
  }

  public static boolean isMacOsMojaveOrLater() {
    return hasTypeAndVersionOrHigher(PlatformEnum.MACOS, "10.14");
  }

  @NotNull
  public static String getCurrentLinuxDesktopEnvironmentName() {
    String currentDesktop = System.getenv("XDG_CURRENT_DESKTOP");
    return currentDesktop == null ? "" : currentDesktop;
  }

  public static boolean isGnome() {
    return isLinux()
        && getCurrentLinuxDesktopEnvironmentName().toLowerCase(Locale.ROOT).contains("gnome");
  }

  public static boolean isKde() {
    return isLinux()
        && getCurrentLinuxDesktopEnvironmentName()
            .toLowerCase(Locale.ROOT)
            .contains("KDE".toLowerCase(Locale.ROOT));
  }

  public static boolean hasType(PlatformEnum platformType) {
    return PLATFORM_TYPE.equals(platformType);
  }

  public static boolean isVersionAtLeast(String version) {
    return new Version(VERSION).isAtLeast(version);
  }

  public static boolean hasTypeAndVersionOrHigher(PlatformEnum platformType, String version) {
    return hasType(platformType) && isVersionAtLeast(version);
  }

  public static String getVersion() {
    return VERSION;
  }

  public static String getFamily() {
    return FAMILY;
  }

  private OsInfo() {}
}
