package network.crypta.fs;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class AppEnvTest {

  @Test
  public void dockerEnvOverride_isTrue() {
    Map<String, String> env = new HashMap<>();
    env.put("CRYPTAD_DOCKER", "1");
    AppEnv ae = new AppEnv(env, "Linux", "tester", p -> null);
    assertTrue(ae.isDocker());
  }

  @Test
  public void nonLinux_isDockerFalse() {
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Mac OS X", "tester", Path::toString);
    assertFalse(ae.isDocker());
  }
}
