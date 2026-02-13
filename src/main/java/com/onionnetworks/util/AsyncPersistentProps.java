package com.onionnetworks.util;

import java.io.*;
import java.nio.file.Files;
import java.util.*;

/**
 * Asynchronously persists a {@link Properties} instance to a backing file while allowing callers to
 * continue mutating the in-memory view without blocking on disk I/O.
 *
 * <p>This helper owns a daemon writer thread that snapshots the current {@code Properties} content
 * whenever a change is observed and writes the snapshot atomically to the target file. Callers
 * typically obtain the shared {@link Properties} via {@link #getProperties()}, mutate it through
 * {@link #setProperty(String, String)} or {@link #remove(Object)}, and optionally invoke {@link
 * #flush()} to wait until all enqueued changes are durable. The underlying file is replaced on each
 * write to avoid partial updates that would corrupt the persisted state.
 *
 * <p>State changes are synchronized on the instance; the class is safe for concurrent callers that
 * follow the provided API but does not attempt to enforce external consistency beyond its own
 * monitor. The writer thread exits once {@link #close()} is called or if an {@link IOException}
 * occurs; subsequent write attempts surface the failure through {@link IllegalStateException}. Use
 * this class when lightweight, file-based persistence is needed without dedicating calling threads
 * to blocking I/O.
 *
 * <ul>
 *   <li>Writes occur lazily after mutations and are serialized by a background thread.
 *   <li>{@link #flush()} provides a barrier so callers can wait for durability.
 *   <li>Instances cannot be reused after a failure or explicit close.
 * </ul>
 *
 * @author Justin F. Chapweske
 */
public final class AsyncPersistentProps implements Runnable {

  private final File f;
  private final Properties p;
  private IOException ioe;
  private boolean closed;
  private boolean changed;
  private boolean writing;
  private boolean writerThreadStarted;
  private final Thread writerThread;

  /**
   * Creates a new asynchronous property store bound to the given file.
   *
   * <p>If the file already exists, its contents are loaded into an initially mutable {@link
   * Properties} instance. When the file is absent, an empty properties set is created and the file
   * will be materialized on the first successful write. The constructor prepares a daemon thread
   * named after the target file; the thread starts lazily when a write is first required. Callers
   * should retain the returned instance and eventually invoke {@link #close()} to stop the worker
   * and surface any deferred I/O failures.
   *
   * @param f backing file that receives serialized property snapshots; must be readable if it
   *     already exists and writable for future writes; never {@code null}
   * @throws IOException if loading the existing file fails
   */
  public AsyncPersistentProps(File f) throws IOException {
    this.f = f;
    p = new Properties();
    if (f.exists()) {
      try (FileInputStream in = new FileInputStream(f)) {
        p.load(in);
      }
    }
    writerThread = new Thread(this, "Props Writer :" + f.getName());
    writerThread.setDaemon(true);
  }

  /**
   * Returns the live {@link Properties} instance managed by this wrapper.
   *
   * <p>Changes to the returned object are tracked automatically; callers can mutate it directly or
   * via helper methods on this class. The returned instance is shared across all callers and should
   * not be stored beyond the lifecycle of this wrapper.
   *
   * @return mutable properties object whose changes will be persisted by the background writer
   */
  public Properties getProperties() {
    return p;
  }

  /**
   * Provides the backing file that receives serialized properties.
   *
   * <p>The file reference is stable for the lifetime of the instance. Callers should avoid
   * modifying the file directly while the writer thread is active to prevent inconsistent state on
   * the next write cycle.
   *
   * @return absolute or relative file path used for persistence; never {@code null}
   */
  public File getFile() {
    return f;
  }

  /**
   * Stores or replaces a property value and schedules an asynchronous write.
   *
   * <p>Marking the properties as changed signals the writer thread to persist the updated snapshot.
   * The call returns immediately after updating the in-memory map; it does not wait for disk I/O.
   *
   * @param key non-null property name; empty strings are permitted but discouraged for readability
   * @param value non-null property value to associate with the key
   * @return previous value mapped to the key or {@code null} when none existed
   * @throws IllegalStateException if the instance has been closed or encountered an earlier I/O
   *     failure
   */
  public synchronized Object setProperty(String key, String value) {
    checkState();

    startWriterThreadIfNeeded();
    Object result = p.setProperty(key, value);
    changed = true;
    this.notifyAll();
    return result;
  }

  /**
   * Removes the mapping for the specified key and records the change.
   *
   * <p>When a value is actually removed the writer thread is notified so that the next snapshot
   * reflects the deletion. Invocations that find no existing entry leave the persisted state
   * unchanged and do not trigger a write.
   *
   * @param key key to remove; may be any {@link Object} accepted by {@link Properties}
   * @return removed value or {@code null} if no mapping was present
   * @throws IllegalStateException if the writer has failed or been closed
   */
  public synchronized Object remove(Object key) {
    checkState();

    Object result = p.remove(key);
    if (result != null) {
      startWriterThreadIfNeeded();
      changed = true;
      this.notifyAll();
    }
    return result;
  }

  /**
   * Clears all properties and triggers a new persistence cycle.
   *
   * <p>After this call the in-memory {@link Properties} is empty until new entries are added. The
   * background writer will rewrite the file to reflect the cleared state.
   *
   * @throws IllegalStateException if the instance can no longer accept mutations
   */
  public synchronized void clear() {
    checkState();

    startWriterThreadIfNeeded();
    p.clear();
    changed = true;
    this.notifyAll();
  }

  /**
   * Retrieves the value associated with the given key from the live properties map.
   *
   * <p>The method does not block on pending writes; it returns the current in-memory view, which
   * may include changes that have not yet been flushed to disk.
   *
   * @param key non-null property name to resolve
   * @return value currently mapped to the key or {@code null} when absent
   */
  public synchronized String getProperty(String key) {
    return p.getProperty(key);
  }

  /**
   * Blocks until outstanding changes have either been written to disk or a write failure occurs.
   *
   * <p>Callers use this as a durability barrier when they need confirmation that prior mutations
   * are reflected on disk. If the writer thread hits an {@link IOException}, this method propagates
   * that error and clears the stored exception so subsequent calls can proceed. Interrupting the
   * calling thread results in an {@link InterruptedIOException} with the interrupt flag restored.
   *
   * @throws IOException if the background writer encountered an I/O failure during the last write
   * @throws InterruptedIOException if the waiting thread was interrupted before completion
   */
  public synchronized void flush() throws IOException {
    while (!closed && (changed || writing)) {
      try {
        this.wait();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new InterruptedIOException(e.getMessage());
      }
    }

    if (ioe != null) {
      /* this code avoids throw {} finally {} for the sake of GCJ 3.0 */
      IOException ex = ioe;
      ioe = null;
      throw ex;
    }
  }

  /**
   * Stops the writer thread after ensuring all queued changes are persisted.
   *
   * <p>This call waits for any in-progress write via {@link #flush()}, marks the instance as
   * closed, and releases any threads waiting on state changes. Further mutation attempts will fail
   * fast with {@link IllegalStateException}. Closing is idempotent with respect to writer exit and
   * may surface the last recorded {@link IOException} from a previous write.
   *
   * @throws IOException if the most recent persistence attempt ended in failure
   */
  public synchronized void close() throws IOException {
    flush(); // This will toss the exception if set.
    closed = true;
    this.notifyAll();
  }

  private synchronized void fail(IOException e) {
    closed = true;
    ioe = e;
    this.notifyAll();
  }

  private void checkState() {
    if (ioe != null) {
      throw new IllegalStateException(ioe.getMessage());
    } else if (closed) {
      throw new IllegalStateException("Sorry, we're closed");
    }
  }

  private void startWriterThreadIfNeeded() {
    if (!writerThreadStarted) {
      writerThread.start();
      writerThreadStarted = true;
    }
  }

  /**
   * Executes the background write loop that persists property snapshots to disk.
   *
   * <p>The loop waits for change notifications, serializes the current {@link Properties} content
   * into a byte array to avoid holding locks during I/O, atomically rewrites the target file, and
   * then signals waiting threads. Any {@link IOException} terminates the loop and marks the
   * instance as failed so callers learn of the error on their next interaction.
   */
  @Override
  public void run() {
    while (true) {
      try {
        byte[] b;
        synchronized (this) {
          waitForChange();
          if (closed) {
            return;
          }
          // snapshot the Properties into a byte[]
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          p.store(baos, null);
          b = baos.toByteArray();
          changed = false;
          writing = true;
        }

        // Write the snapshot to disk.
        if (f.exists()) {
          Files.deleteIfExists(f.toPath());
        }
        try (FileOutputStream fos = new FileOutputStream(f)) {
          fos.write(b);
          fos.flush();
        }

        // Notify that we're done writing.
        synchronized (this) {
          writing = false;
          this.notifyAll();
        }
      } catch (IOException e) {
        fail(e);
      }
    }
  }

  private synchronized void waitForChange() throws InterruptedIOException {
    while (!closed && !changed) {
      try {
        this.wait();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new InterruptedIOException(e.getMessage());
      }
    }
  }
}
