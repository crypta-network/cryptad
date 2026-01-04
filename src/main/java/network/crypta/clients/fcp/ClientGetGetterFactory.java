package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.ResumeFailedException;

/**
 * Creates {@link ClientGetter} instances for {@link ClientGet}, including optional BinaryBlob
 * support.
 *
 * <p>The factory keeps the {@link BinaryBlob} and {@link BinaryBlobWriter} dependencies out of
 * {@link ClientGet} so the request class can focus on lifecycle and persistence responsibilities
 * without exceeding Sonar coupling limits (rule {@code java:S6539}).
 */
final class ClientGetGetterFactory {
  private ClientGetGetterFactory() {}

  static String binaryBlobMimeType() {
    return BinaryBlob.MIME_TYPE;
  }

  private static final class CallbackAdapter
      implements ClientGetCallback, PersistentClientCallback, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    private final ClientGet request;

    private CallbackAdapter(ClientGet request) {
      this.request = request;
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      request.onSuccess(result, state);
    }

    @Override
    public void onFailure(FetchException e, ClientGetter state) {
      request.onFailure(e, state);
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      request.onResume(context);
    }

    @Override
    public RequestClient getRequestClient() {
      return request.getRequestClient();
    }

    @Override
    public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
      request.getClientDetail(dos, checker);
    }
  }

  static DataOutputStream checksummedWriter(DataOutputStream target, ChecksumChecker checker)
      throws IOException {
    return new DataOutputStream(checker.checksumWriterWithLength(target, new ArrayBucketFactory()));
  }

  static Bucket diskReturnBucket(File file) {
    return new FileBucket(file, false, true, false, false);
  }

  static Bucket diskBucket(File file, boolean readOnly) {
    return new FileBucket(file, readOnly, false, false, false);
  }

  static ExpectedHashes readExpectedHashes(DataInputStream dis, String identifier, boolean global)
      throws IOException {
    HashResult[] hashes = HashResult.readHashes(dis);
    if (hashes == null || hashes.length == 0) {
      return null;
    }
    return new ExpectedHashes(hashes, identifier, global);
  }

  static void writeExpectedHashes(DataOutputStream dos, ExpectedHashes expectedHashes)
      throws IOException {
    HashResult.write(expectedHashes == null ? null : expectedHashes.hashes, dos);
  }

  static ClientGetter createGetter(
      ClientGet request,
      FreenetURI uri,
      FetchContext fetchContext,
      short priorityClass,
      Bucket returnBucket,
      Bucket initialMetadata,
      String extensionCheck,
      boolean discardData,
      boolean binaryBlob,
      boolean persistenceForever,
      NodeClientCore core)
      throws IOException {
    ClientGetCallback callback = new CallbackAdapter(request);
    Bucket blobBucket = returnBucket;
    if (binaryBlob) {
      if (blobBucket == null) {
        Objects.requireNonNull(core, "core");
        //noinspection resource
        blobBucket =
            core.getClientContext()
                .getBucketFactory(persistenceForever)
                .makeBucket(fetchContext.getMaxOutputLength());
      }
      return new ClientGetter(
          callback,
          uri,
          fetchContext,
          priorityClass,
          new NullBucket(),
          new BinaryBlobWriter(blobBucket),
          false,
          initialMetadata,
          extensionCheck);
    }
    if (discardData) {
      returnBucket = new NullBucket();
    }
    return new ClientGetter(
        callback,
        uri,
        fetchContext,
        priorityClass,
        returnBucket,
        null,
        false,
        initialMetadata,
        extensionCheck);
  }
}
