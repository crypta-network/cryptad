package network.crypta.support.io;

import java.io.IOException;
import java.util.zip.ZipFile;
import network.crypta.support.Logger;

/**
 * Utility methods for I/O operations, particularly for closing resources quietly.
 * These methods swallow exceptions during close operations, logging them instead.
 * 
 * Use these methods in finally blocks or when migrating from IOUtils.closeQuietly() calls.
 * For new code, prefer try-with-resources where possible.
 */
public class IOUtils {
    
    /**
     * Closes the given AutoCloseable resource quietly, logging any exceptions.
     * Null-safe: does nothing if the resource is null.
     * 
     * @param resource The resource to close (may be null)
     */
    public static void closeQuietly(AutoCloseable resource) {
        if (resource != null) {
            try {
                resource.close();
            } catch (Exception e) {
                Logger.error(IOUtils.class, "Error during close() on " + resource, e);
            }
        }
    }
    
    /**
     * Closes the given ZipFile quietly, logging any IOException.
     * Null-safe: does nothing if the zipFile is null.
     * 
     * @param zipFile The ZipFile to close (may be null)
     */
    public static void closeQuietly(ZipFile zipFile) {
        if (zipFile != null) {
            try {
                zipFile.close();
            } catch (IOException e) {
                Logger.error(IOUtils.class, "Error during close() on ZipFile", e);
            }
        }
    }
}