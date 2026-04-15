package network.crypta.clients.fcp;

import java.io.File;

final class ClientGetTestProfiles {
  private ClientGetTestProfiles() {}

  static void setBinaryBlob(ClientGet request, boolean value) {
    request.setRequestProfile(request.requestProfile().withBinaryBlob(value));
  }

  static void setFetchConfig(ClientGet request, ClientGetFetchConfig value) {
    request.setRequestProfile(request.requestProfile().withFetchConfig(value));
  }

  static void setReturnType(ClientGet request, ClientGet.ReturnType value) {
    request.setRequestProfile(request.requestProfile().withReturnType(value));
  }

  static void setRuntimeFetchSupport(ClientGet request, FcpFetchRuntimeSupport value) {
    request.setRequestProfile(request.requestProfile().withRuntimeFetchSupport(value));
  }

  static void setTargetFile(ClientGet request, File value) {
    request.setRequestProfile(request.requestProfile().withTargetFile(value));
  }
}
