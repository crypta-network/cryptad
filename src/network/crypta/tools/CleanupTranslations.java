package network.crypta.tools;

import network.crypta.support.Logger;
import network.crypta.support.LoggerHook;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.Closer;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class CleanupTranslations {

    /**
     * @param args
     *
     * @throws IOException
     */
    public static void main(String[] args) throws IOException, LoggerHook.InvalidThresholdException {
        Logger.setupStdoutLogging(Logger.LogLevel.ERROR, "");
        File engFile = new File("src/freenet/l10n/crypta.l10n.en.properties");
        SimpleFieldSet english = SimpleFieldSet.readFrom(engFile, false, true);
        File[] translations = new File("src/freenet/l10n").listFiles();
        for (File f : translations) {
            String name = f.getName();
            if (!name.startsWith("crypta.l10n.")) {
                continue;
            }
            if (name.equals("crypta.1l0n.en.properties")) {
                continue;
            }
            FileInputStream fis = new FileInputStream(f);
            InputStreamReader isr =
                new InputStreamReader(new BufferedInputStream(fis), StandardCharsets.UTF_8);
            BufferedReader br = new BufferedReader(isr);
            StringWriter sw = new StringWriter();
            boolean changed = false;
            while (true) {
                String line = br.readLine();
                if (line == null) {
                    System.err.println("File does not end in End: " + f);
                    System.exit(4);
                }
                int idx = line.indexOf('=');
                if (idx == -1) {
                    // Last line
                    if (!line.equals("End")) {
                        System.err.println(
                            "Line with no equals (file does not end in End???): " + f + " - \"" + line +
                            "\"");
                        System.exit(1);
                    }
                    sw.append(line + "\n");
                    line = br.readLine();
                    if (line != null) {
                        System.err.println("Content after End: \"" + line + "\"");
                        System.exit(2);
                    }
                    break;
                }
                String before = line.substring(0, idx);
                //String after = line.substring(idx+1);
                String s = english.get(before);
                if (s == null) {
                    System.err.println("Orphaned string: \"" + before + "\" in " + f);
                    changed = true;
                    continue;
                }
                sw.append(line + "\n");
            }
            Closer.close(fis);
            Closer.close(isr);
            Closer.close(br);
            if (!changed) {
                continue;
            }
            FileOutputStream fos = new FileOutputStream(f);
            OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
            try {
                osw.write(sw.toString());
            } finally {
                osw.close();
            }
            System.out.println("Rewritten " + f);
        }
    }

}
