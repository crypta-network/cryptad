package network.crypta.support.math;

import java.io.Serial;
import network.crypta.support.Fields;

/*
 ** Originally, we maintained the below functionality as a fork of the above
 ** code, in the contrib repo. Eventually this was refactored into this class,
 ** and now we instead depend on upstream mantissa.
 **
 ** There are three milestone commits:
 **
 ** O: 35a37bfad5b42dead835c9f1fb8b0972e730dab2, the earliest version we have in git, imported from svn
 ** A: 5d16406e4a20c9e6bd9685bf9a8480a13c8acbaf, the latest version we made edits to
 ** X: aea5c9d491b8de90b3457c0561938ea2ed14ec1d, representing a pristine 7.2 source
 **
 ** You may view the diffs using something like:
 **
 **  $ git diff -w [S] [T] -- java{,-test}/org/spaceroots/mantissa/random/
 **
 ** As of fred commit e89a2f63e819e8c088a14eaa3c809770db822956, this class, and
 ** its associated test, re-implements the diff between X-A, by extending
 ** o.s.m.r.MersenneTwister. Above that, it is also runtime-compatible with any
 ** version (O, A, X) of it.
 **
 ** This should provide a smooth upgrade path:
 **
 ** # Move users to this class, still running contrib-26 at version A
 ** # Move contrib to version X (legacy-27).
 */

/**
 * * This is a wrapper around {@link org.spaceroots.mantissa.random.MersenneTwister} which adds *
 * additional {@code setSeed()} methods. Instances are synchronized unless created through * {@link
 * #createUnsynchronized}. * * @author infinity0
 */
public class MersenneTwister extends MersenneTwisterBase {

  @Serial private static final long serialVersionUID = 6555069655883958609L;

  /** Creates a new random number generator using the current time as the seed. */
  public MersenneTwister() {
    super();
  }

  /** Creates a new random number generator using a single int seed. */
  public MersenneTwister(int seed) {
    super(seed);
  }

  /** Creates a new random number generator using an int array seed. */
  public MersenneTwister(int[] seed) {
    super(seed);
  }

  /** Creates a new random number generator using a single long seed. */
  public MersenneTwister(long seed) {
    super(seed);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void setSeed(int seed) {
    super.setSeed(seed);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void setSeed(int[] seed) {
    super.setSeed(seed);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void setSeed(long seed) {
    super.setSeed(seed);
  }

  /**
   * * Reinitialize the generator as if just built with the given byte array seed. *
   *
   * <p>The state of the generator is exactly the same as a new * generator built with the same
   * seed.
   *
   * @param seed the initial seed (8-bit byte array), if null * the seed of the generator will be
   *     related to the current time
   */
  public void setSeed(byte[] seed) {
    synchronized (this) {
      super.setSeed(Fields.bytesToInts(seed, 0, seed.length));
    }
  }

  /** {@inheritDoc} */
  @Override
  protected synchronized int next(int bits) {
    return super.next(bits);
  }

  /**
   * Creates a new random number generator using a random seed from the provided source. Note that
   * this is significantly slower than the unsynchronized (hence not thread-safe) variant that can
   * be obtained from {@link #createUnsynchronized}.
   */
  public static MersenneTwister createSynchronized(byte[] seed) {
    return new MersenneTwister(Fields.bytesToInts(seed));
  }

  /**
   * Creates a new random number generator using a byte array seed. The returned generator is not
   * synchronized and is therefore NOT thread-safe.
   */
  public static MersenneTwister createUnsynchronized(byte[] seed) {
    return new Unsynchronized(seed);
  }

  @SuppressWarnings({"UnsynchronizedOverridesSynchronized", "java:S3551"})
  private static final class Unsynchronized extends MersenneTwister {
    // Random's constructor invokes setSeed(long) before this subclass finishes initialization.
    // Keep that early call on the constructor-safeguarded path, then switch to lock-free seeding.
    private final boolean initialized;

    private Unsynchronized(byte[] seed) {
      super(Fields.bytesToInts(seed));
      initialized = true;
    }

    @Override
    protected int next(int bits) {
      return unsynchronizedNext(bits);
    }

    @Override
    public void setSeed(int seed) {
      unsynchronizedSetSeed(seed);
    }

    @Override
    public void setSeed(int[] seed) {
      unsynchronizedSetSeed(seed);
    }

    @Override
    public void setSeed(long seed) {
      if (!initialized) {
        super.setSeed(seed);
        return;
      }
      unsynchronizedSetSeed(seed);
    }

    @Override
    public void setSeed(byte[] seed) {
      unsynchronizedSetSeed(seed);
    }
  }

  final int unsynchronizedNext(int bits) {
    return super.next(bits);
  }

  final void unsynchronizedSetSeed(int seed) {
    super.setSeed(seed);
  }

  final void unsynchronizedSetSeed(int[] seed) {
    super.setSeed(seed);
  }

  final void unsynchronizedSetSeed(long seed) {
    super.setSeed(new int[] {(int) (seed >>> 32), (int) (seed & 0xffffffffL)});
  }

  final void unsynchronizedSetSeed(byte[] seed) {
    super.setSeed(Fields.bytesToInts(seed));
  }
}

/**
 * Package-private base class to avoid class-name shadowing with the upstream
 * org.spaceroots.mantissa.random.MersenneTwister while preserving behavior and API.
 */
class MersenneTwisterBase extends org.spaceroots.mantissa.random.MersenneTwister {
  @Serial private static final long serialVersionUID = 1L;

  MersenneTwisterBase() {
    super();
  }

  MersenneTwisterBase(int seed) {
    super(seed);
  }

  MersenneTwisterBase(int[] seed) {
    super(seed);
  }

  MersenneTwisterBase(long seed) {
    super(seed);
  }
}
