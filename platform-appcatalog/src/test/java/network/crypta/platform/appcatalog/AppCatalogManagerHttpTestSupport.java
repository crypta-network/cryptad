package network.crypta.platform.appcatalog;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/** HTTP and stream test doubles shared by catalog-manager transport tests. */
final class AppCatalogManagerHttpTestSupport {
  private AppCatalogManagerHttpTestSupport() {}

  static final class CloseRecordingInputStream extends ByteArrayInputStream {
    private boolean closed;

    CloseRecordingInputStream() {
      super(new byte[0]);
    }

    @Override
    public void close() {
      closed = true;
    }

    boolean closed() {
      return closed;
    }
  }

  static final class FixedResponseHttpClient extends HttpClient {
    private final HttpResponse<InputStream> response;
    private final IOException sendFailure;

    FixedResponseHttpClient(HttpResponse<InputStream> response) {
      this.response = response;
      sendFailure = null;
    }

    FixedResponseHttpClient(IOException sendFailure) {
      response = null;
      this.sendFailure = sendFailure;
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
      return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
      return Optional.empty();
    }

    @Override
    public Redirect followRedirects() {
      return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
      return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
      try {
        return SSLContext.getDefault();
      } catch (NoSuchAlgorithmException exception) {
        throw new IllegalStateException(exception);
      }
    }

    @Override
    public SSLParameters sslParameters() {
      return new SSLParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
      return Optional.empty();
    }

    @Override
    public Version version() {
      return Version.HTTP_1_1;
    }

    @Override
    public Optional<Executor> executor() {
      return Optional.empty();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> HttpResponse<T> send(
        HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException {
      if (sendFailure != null) {
        throw sendFailure;
      }
      return (HttpResponse<T>) response;
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
      return CompletableFuture.failedFuture(new UnsupportedOperationException());
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
        HttpRequest request,
        HttpResponse.BodyHandler<T> responseBodyHandler,
        HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
      return CompletableFuture.failedFuture(new UnsupportedOperationException());
    }
  }

  record InputStreamResponse(int statusCode, InputStream body, HttpHeaders headers)
      implements HttpResponse<InputStream> {
    InputStreamResponse(int statusCode, InputStream body) {
      this(statusCode, body, HttpHeaders.of(Collections.emptyMap(), (_, _) -> true));
    }

    static InputStreamResponse withContentLength(InputStream body, String value) {
      return new InputStreamResponse(
          200, body, HttpHeaders.of(Map.of("content-length", List.of(value)), (_, _) -> true));
    }

    @Override
    public HttpRequest request() {
      return HttpRequest.newBuilder(uri()).GET().build();
    }

    @Override
    public Optional<HttpResponse<InputStream>> previousResponse() {
      return Optional.empty();
    }

    @Override
    public Optional<SSLSession> sslSession() {
      return Optional.empty();
    }

    @Override
    public URI uri() {
      return URI.create("http://localhost/test");
    }

    @Override
    public HttpClient.Version version() {
      return HttpClient.Version.HTTP_1_1;
    }
  }
}
