package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Narrow runtime support seam for the FCP GET/fetch path.
 *
 * <p>The adapter owns the detached fetch configuration and opaque execution handle types. Bridge
 * implementations translate those adapter-owned values to the live daemon fetch runtime.
 */
public interface FcpFetchRuntimeSupport {

  /** Returns detached defaults for a new persistent GET request. */
  ClientGetFetchConfig defaultPersistentFetchConfig();

  /** Encodes detached fetch configuration using the runtime's canonical fetch-context format. */
  void encodeFetchConfig(ClientGetFetchConfig fetchConfig, DataOutputStream dos) throws IOException;

  /** Decodes detached fetch configuration from the runtime's canonical fetch-context format. */
  ClientGetFetchConfig decodeFetchConfig(DataInputStream dis)
      throws IOException, StorageFormatException;

  /** Opens a checksummed persistence block using the runtime-backed temporary bucket services. */
  DataInputStream openChecksummed(DataInputStream dis, ChecksumChecker checker, long maxLength)
      throws IOException, StorageFormatException;

  /** Restores a persistent bucket from an already opened checksummed block. */
  Bucket restorePersistentBucket(DataInputStream dis)
      throws IOException, StorageFormatException, ResumeFailedException;

  /** Returns the transfer-access policy used for disk-return planning. */
  TransferAccessPort transferAccess();

  /** Creates the live GET execution hidden behind the adapter-owned execution handle. */
  ClientGetExecution createExecution(ClientGetExecutionSpec executionSpec) throws IOException;
}
