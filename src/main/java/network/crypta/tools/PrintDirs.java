package network.crypta.tools;

import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;

public final class PrintDirs {
  private PrintDirs() {}

  public static void main(String[] args) {
    AppEnv appEnv = new AppEnv(System.getenv());
    System.out.println("cryptad.service.mode=" + System.getProperty("cryptad.service.mode"));
    if (appEnv.isServiceMode()) {
      Resolved r = new ServiceDirs().resolve();
      System.out.println("mode=service");
      printDirs(r);
    } else {
      Resolved r = new AppDirs().resolve();
      System.out.println("mode=user");
      printDirs(r);
    }
  }

  private static void printDirs(Resolved resolved) {
    System.out.println("configDir=" + resolved.getConfigDir());
    System.out.println("dataDir=" + resolved.getDataDir());
    System.out.println("cacheDir=" + resolved.getCacheDir());
    System.out.println("runDir=" + resolved.getRunDir());
    System.out.println("logsDir=" + resolved.getLogsDir());
  }
}
