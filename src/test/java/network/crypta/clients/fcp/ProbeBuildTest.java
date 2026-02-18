package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ProbeBuildTest {

  @Test
  @DisplayName("constructor with identifier stores identifier and build fields")
  void constructor_whenIdentifierProvided_setsFields() {
    String identifier = "probe-123";
    int build = 9876;

    ProbeBuild response = new ProbeBuild(identifier, build);
    SimpleFieldSet fields = response.getFieldSet();

    assertEquals(identifier, fields.get(FCPMessage.IDENTIFIER));
    assertEquals(build, fields.getInt(FCPMessage.BUILD, -1));
  }

  @Test
  @DisplayName("constructor without identifier omits IDENTIFIER while retaining build")
  void constructor_whenIdentifierNull_omitsIdentifier() {
    int build = 101;

    ProbeBuild response = new ProbeBuild(null, build);
    SimpleFieldSet fields = response.getFieldSet();

    assertNull(fields.get(FCPMessage.IDENTIFIER));
    assertEquals(build, fields.getInt(FCPMessage.BUILD, -1));
  }

  @Test
  @DisplayName("getName always returns ProbeBuild")
  void getName_whenCalled_returnsProbeBuild() {
    ProbeBuild response = new ProbeBuild("abc", 1);

    assertEquals("ProbeBuild", response.getName());
  }
}
