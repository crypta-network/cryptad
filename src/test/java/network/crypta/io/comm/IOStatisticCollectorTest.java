package network.crypta.io.comm;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class IOStatisticCollectorTest {

  private IOStatisticCollector collector;

  @BeforeEach
  void setUp() {
    collector = new IOStatisticCollector();
  }

  @AfterEach
  void tearDown() {
    // no-op; placeholder for symmetry and future extensions
  }

  @Test
  @DisplayName("getTotalIO_whenNoReports_expectZeroesAndOrderOutThenIn")
  void getTotalIO_whenNoReports_expectZeroesAndOrderOutThenIn() {
    long[] totals = collector.getTotalIO();
    assertArrayEquals(new long[] {0L, 0L}, totals, "Expected [out,in] to both be zero");
  }

  @ParameterizedTest
  @DisplayName("reportSentBytes_whenRemotePositive_addsToOutOnly")
  @CsvSource({"8.8.8.8, 1500", "2001:4860:4860::8888, 2048"})
  void reportSentBytes_whenRemotePositive_addsToOutOnly(String ip, int bytes) throws Exception {
    InetAddress addr = literal(ip);

    collector.reportSentBytes(addr, bytes);

    long[] totals = collector.getTotalIO();
    assertArrayEquals(new long[] {bytes, 0L}, totals, "Only outgoing should increase");
  }

  @ParameterizedTest
  @DisplayName("reportReceivedBytes_whenRemotePositive_addsToInOnly")
  @CsvSource({"1.1.1.1, 777", "2606:4700:4700::1111, 4096"})
  void reportReceivedBytes_whenRemotePositive_addsToInOnly(String ip, int bytes) throws Exception {
    InetAddress addr = literal(ip);

    collector.reportReceivedBytes(addr, bytes);

    long[] totals = collector.getTotalIO();
    assertArrayEquals(new long[] {0L, bytes}, totals, "Only incoming should increase");
  }

  @ParameterizedTest
  @DisplayName("reportMethods_whenZeroOrNegativeBytes_ignored")
  @CsvSource({"0", "-1", "-1024"})
  void reportMethods_whenZeroOrNegativeBytes_ignored(int bytes) throws Exception {
    InetAddress remote = literal("9.9.9.9");

    collector.reportSentBytes(remote, bytes);
    collector.reportReceivedBytes(remote, bytes);

    assertArrayEquals(new long[] {0L, 0L}, collector.getTotalIO());
  }

  @ParameterizedTest
  @DisplayName("reportMethods_whenLocalAddresses_ignored")
  @MethodSource("localAddresses")
  void reportMethods_whenLocalAddresses_ignored(String ip) throws Exception {
    InetAddress local = literal(ip);

    collector.reportSentBytes(local, 1000);
    collector.reportReceivedBytes(local, 2000);

    assertArrayEquals(new long[] {0L, 0L}, collector.getTotalIO());
  }

  static List<String> localAddresses() {
    List<String> ips = new ArrayList<>();
    // Loopback (IPv4 and IPv6)
    ips.add("127.0.0.1");
    ips.add("::1");
    // Link-local (IPv4 and IPv6)
    ips.add("169.254.1.1");
    ips.add("fe80::1");
    // Site/unique-local via IPUtil: RFC1918 IPv4 + IPv6 ULA
    ips.add("10.0.0.1");
    ips.add("192.168.1.2");
    ips.add("172.16.0.33");
    ips.add("fd00::1");
    return ips;
  }

  @Test
  @DisplayName("getTotalIO_whenArrayMutated_doesNotAffectInternalState")
  void getTotalIO_whenArrayMutated_doesNotAffectInternalState() throws Exception {
    InetAddress remote = literal("8.8.4.4");
    collector.reportSentBytes(remote, 10);
    collector.reportReceivedBytes(remote, 20);

    long[] first = collector.getTotalIO();
    // Mutate caller's copy and re-read
    first[0] = 0L;
    first[1] = 0L;

    long[] second = collector.getTotalIO();
    assertArrayEquals(new long[] {10L, 20L}, second, "Internal state must be encapsulated");
  }

  @Test
  @DisplayName("reportMethods_whenNullAddress_expectNullPointerException")
  void reportMethods_whenNullAddress_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> collector.reportSentBytes(null, 100));
    assertThrows(NullPointerException.class, () -> collector.reportReceivedBytes(null, 100));
  }

  @Test
  @DisplayName("concurrency_reportSentBytes_multipleThreads_correctTotal")
  void concurrency_reportSentBytes_multipleThreads_correctTotal() throws Exception {
    InetAddress remote = literal("1.2.3.4");
    int threads = 4;
    int incrementsPerThread = 1_000;
    int bytesPerIncrement = 1;

    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    try (var exec = Executors.newFixedThreadPool(threads)) {
      for (int t = 0; t < threads; t++) {
        exec.execute(
            () -> {
              try {
                start.await();
                for (int i = 0; i < incrementsPerThread; i++) {
                  collector.reportSentBytes(remote, bytesPerIncrement);
                }
              } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
              } finally {
                done.countDown();
              }
            });
      }
      start.countDown();
      boolean completed = done.await(10, TimeUnit.SECONDS);
      assertTrue(completed, "Timed out waiting for sender workers to finish");
    }

    long expectedOut = (long) threads * incrementsPerThread * bytesPerIncrement;
    assertArrayEquals(new long[] {expectedOut, 0L}, collector.getTotalIO());
  }

  @Test
  @DisplayName("concurrency_reportReceivedBytes_multipleThreads_correctTotal")
  void concurrency_reportReceivedBytes_multipleThreads_correctTotal() throws Exception {
    InetAddress remote = literal("4.3.2.1");
    int threads = 3;
    int incrementsPerThread = 2_000;
    int bytesPerIncrement = 2;

    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(threads);
    try (var exec = Executors.newFixedThreadPool(threads)) {
      for (int t = 0; t < threads; t++) {
        exec.execute(
            () -> {
              try {
                start.await();
                for (int i = 0; i < incrementsPerThread; i++) {
                  collector.reportReceivedBytes(remote, bytesPerIncrement);
                }
              } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
              } finally {
                done.countDown();
              }
            });
      }
      start.countDown();
      boolean completed = done.await(10, TimeUnit.SECONDS);
      assertTrue(completed, "Timed out waiting for receiver workers to finish");
    }

    long expectedIn = (long) threads * incrementsPerThread * bytesPerIncrement;
    assertArrayEquals(new long[] {0L, expectedIn}, collector.getTotalIO());
  }

  private static InetAddress literal(String host) throws Exception {
    return InetAddress.getAllByName(host)[0];
  }
}
