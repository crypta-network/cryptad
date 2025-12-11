package org.spaceroots.mantissa.random;

import java.io.Serial;
import java.util.Random;

/**
 * This class implements a powerful pseudo-random number generator developed by Makoto Matsumoto and
 * Takuji Nishimura during 1996-1997.
 *
 * <p>This implementation behaves like a drop‑in replacement for {@link java.util.Random} with
 * significantly better statistical properties for simulation, sampling, and randomized algorithms
 * that are sensitive to correlation artifacts. The generator maintains an internal 624‑element
 * state vector and produces 32‑bit values in batches; the public {@code nextInt()}, {@code
 * nextLong()}, and other {@code Random} methods all delegate to {@link #next(int)} to obtain the
 * requested number of bits. Calling any {@code setSeed} method fully resets that internal state so
 * that two instances seeded identically will produce the same sequence of values.
 *
 * <p>Instances are mutable and not intended to be shared across threads without external
 * synchronization. The core generation path in {@link #next(int)} does not synchronize, so callers
 * that access a single instance concurrently must provide their own locking to preserve sequence
 * determinism and avoid races during state refresh.
 *
 * <p>This generator features an extremely long period (2<sup>19937</sup>-1) and 623-dimensional
 * equidistribution up to 32 bits accuracy. The home page for this generator is located at <a
 * href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html">
 * http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html</a>.
 *
 * <p>This generator is described in a paper by Makoto Matsumoto and Takuji Nishimura in 1998: <a
 * href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf">Mersenne Twister: A
 * 623-Dimensionally Equidistributed Uniform Pseudo-Random Number Generator</a>, ACM Transactions on
 * Modeling and Computer Simulation, Vol. 8, No. 1, January 1998, pp 3--30
 *
 * <p>The class is implemented as a specialization of the standard <code>java.util.Random</code>
 * class. This allows to use it in algorithms expecting a standard random generator, and hence
 * benefit from a better generator without code change.
 *
 * <p>This class is mainly a Java port of the 2002-01-26 version of the generator written in C by
 * Makoto Matsumoto and Takuji Nishimura. The following license text is reproduced from the original
 * C implementation:
 *
 * <pre>{@code
 * Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
 * All rights reserved.
 * }</pre>
 *
 * <p>Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * <ol>
 *   <li>Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *   <li>Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *   <li>The names of its contributors may not be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 * </ol>
 *
 * <p><strong>THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.</strong>
 *
 * @author Makoto Matsumoto and Takuji Nishimura (C version), Luc Maisonobe (Java port)
 * @version $Id: MersenneTwister.java 1666 2005-12-15 16:37:55Z luc $
 */
public class MersenneTwister extends Random {

  /**
   * Creates a new random number generator.
   *
   * <p>The instance is initialized using the current time as the seed. This constructor is a
   * convenience for typical use when a non‑deterministic seed is acceptable, such as in interactive
   * applications or ad‑hoc sampling. The generated sequence is otherwise identical to an instance
   * created with {@link #MersenneTwister(long)} using the same millisecond timestamp value.
   *
   * <p>Because the seed is derived from wall‑clock time, two instances created in rapid succession
   * may share the same starting state and thus produce identical outputs. If you require distinct
   * streams, prefer explicit seeding or incorporate additional entropy externally.
   */
  public MersenneTwister() {
    mt = new int[N];
    setSeed(System.currentTimeMillis());
  }

  /**
   * Creates a new random number generator using a single int seed.
   *
   * <p>This constructor produces a deterministic generator state from a 32‑bit seed value. The
   * resulting sequence is fully repeatable and can be used for tests or simulations where
   * reproducibility matters. The seed is expanded into the full internal state using the standard
   * Mersenne Twister initialization routine.
   *
   * @param seed initial 32‑bit seed value that deterministically defines the output sequence
   */
  public MersenneTwister(int seed) {
    mt = new int[N];
    setSeed(seed);
  }

  /**
   * Creates a new random number generator using an int array seed.
   *
   * <p>This constructor allows seeding from multiple 32‑bit values, matching the reference C
   * implementation’s array initialization algorithm. Providing a longer or more variable seed array
   * can help separate streams that might otherwise collide when using single‑word seeds.
   *
   * <p>If {@code seed} is {@code null}, the generator falls back to seeding from the current time,
   * equivalent to {@link #MersenneTwister()}.
   *
   * @param seed array of 32‑bit seed values used to initialize the full state; may be {@code null}
   */
  public MersenneTwister(int[] seed) {
    mt = new int[N];
    setSeed(seed);
  }

  /**
   * Creates a new random number generator using a single long seed.
   *
   * <p>This constructor seeds the generator with a 64‑bit value. The seed is split into two 32‑bit
   * words and then expanded into the internal state vector. Two instances constructed with the same
   * {@code seed} will generate identical sequences of values across all {@code Random} methods.
   *
   * @param seed initial 64‑bit seed value that deterministically defines the output sequence
   */
  public MersenneTwister(long seed) {
    mt = new int[N];
    setSeed(seed);
  }

  /**
   * Reinitialize the generator as if just built with the given int seed.
   *
   * <p>The state of the generator is exactly the same as a new generator built with the same seed.
   * This method resets all internal counters and rewrites the state vector using the standard
   * initialization recurrence from the reference implementation. After calling this method, the
   * next value returned by any {@code Random} method corresponds to the first value in the sequence
   * for that seed.
   *
   * @param seed initial 32‑bit seed value used to rebuild the internal state vector
   */
  public void setSeed(int seed) {
    // we use a long masked by 0xffffffffL as a poor man unsigned int
    long longMT = seed;
    mt[0] = (int) longMT;
    for (mti = 1; mti < N; ++mti) {
      // See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier.
      // initializer from the 2002-01-09 C version by Makoto Matsumoto
      longMT = (1812433253L * (longMT ^ (longMT >> 30)) + mti) & 0xffffffffL;
      mt[mti] = (int) longMT;
    }
  }

  /**
   * Reinitialize the generator as if just built with the given int array seed.
   *
   * <p>The state of the generator is exactly the same as a new generator built with the same seed
   * array. The method first performs the single‑word initialization, then mixes each seed element
   * into the state using the same two‑phase non‑linear recurrence as the original C code.
   *
   * <p>If {@code seed} is {@code null}, the generator is reseeded from the current time, which
   * makes the resulting sequence non‑deterministic.
   *
   * @param seed array of 32‑bit seed values used to rebuild internal state; may be {@code null}
   */
  public void setSeed(int[] seed) {

    if (seed == null) {
      setSeed(System.currentTimeMillis());
      return;
    }

    initializeWithSeedArray(seed);
  }

  /**
   * Reinitialize the generator as if just built with the given long seed.
   *
   * <p>The state of the generator is exactly the same as a new generator built with the same seed.
   * The 64‑bit input is split into two 32‑bit values, which are then used to perform array seeding.
   * This override is synchronized to preserve the {@link Random} contract during construction and
   * seeding, but generation itself is not synchronized.
   *
   * @param seed initial 64‑bit seed value used to rebuild internal state; higher bits contribute
   *     independently of lower bits
   */
  @Override
  public synchronized void setSeed(long seed) {
    if (mt == null) {
      // this is probably a spurious call from base class constructor,
      // we do nothing and wait for the setSeed in our own
      // constructors after array allocation
      return;
    }
    setSeed(new int[] {(int) (seed >>> 32), (int) (seed & 0xffffffffL)});
  }

  /**
   * Generate next pseudorandom number.
   *
   * <p>This method is the core generation algorithm. As per {@link Random Random } contract, it is
   * used by all the public generation methods for the various primitive types {@link
   * Random#nextBoolean nextBoolean}, {@link Random#nextBytes nextBytes}, {@link Random#nextDouble
   * nextDouble}, {@link Random#nextFloat nextFloat}, {@link Random#nextGaussian nextGaussian},
   * {@link Random#nextInt() nextInt} and {@link Random#nextLong nextLong}.
   *
   * <p>The implementation refreshes the internal state vector in blocks of {@link #N} words. When
   * the current block is exhausted, a new block is generated using the standard twist transform,
   * then tempered to improve equidistribution. The returned value contains the requested number of
   * high‑order bits from the next 32‑bit output word.
   *
   * @param bits number of high‑order random bits to produce, between 1 and 32 as required by {@link
   *     Random}'s contract
   * @return next pseudorandom value containing {@code bits} high‑order bits from the generator
   */
  @Override
  protected int next(int bits) {

    int y;

    if (mti >= N) { // generate N words at one time
      int mtNext = mt[0];
      for (int k = 0; k < N - M; ++k) {
        int mtCurr = mtNext;
        mtNext = mt[k + 1];
        y = (mtCurr & 0x80000000) | (mtNext & 0x7fffffff);
        mt[k] = mt[k + M] ^ (y >>> 1) ^ MAG01[y & 0x1];
      }
      for (int k = N - M; k < N - 1; ++k) {
        int mtCurr = mtNext;
        mtNext = mt[k + 1];
        y = (mtCurr & 0x80000000) | (mtNext & 0x7fffffff);
        mt[k] = mt[k + (M - N)] ^ (y >>> 1) ^ MAG01[y & 0x1];
      }
      y = (mtNext & 0x80000000) | (mt[0] & 0x7fffffff);
      mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ MAG01[y & 0x1];

      mti = 0;
    }

    y = mt[mti++];

    // tempering
    y ^= (y >>> 11);
    y ^= (y << 7) & 0x9d2c5680;
    y ^= (y << 15) & 0xefc60000;
    y ^= (y >>> 18);

    return y >>> (32 - bits);
  }

  private static final int N = 624;
  private static final int M = 397;
  private static final int[] MAG01 = {0x0, 0x9908b0df};

  /** State vector holding the most recent batch of generated 32‑bit values. */
  private final int[] mt;

  /**
   * Index of the next value to read from {@link #mt}.
   *
   * <p>When this index reaches {@link #N}, the generator refreshes the whole state vector before
   * producing additional output.
   */
  private int mti;

  @Serial private static final long serialVersionUID = 7666069655872848609L;

  private void initializeWithSeedArray(int[] seed) {
    setSeed(19650218);

    int i = 1;
    int j = 0;
    int max = Math.max(N, seed.length);
    for (int k = max; k != 0; k--) {
      long l0 = toUnsignedLong(mt[i]);
      long l1 = toUnsignedLong(mt[i - 1]);
      long l = (l0 ^ ((l1 ^ (l1 >> 30)) * 1664525L)) + seed[j] + j; // non linear
      mt[i] = (int) (l & 0xffffffffL);
      i++;
      j++;
      if (i >= N) {
        mt[0] = mt[N - 1];
        i = 1;
      }
      if (j >= seed.length) {
        j = 0;
      }
    }

    for (int k = N - 1; k != 0; k--) {
      long l0 = toUnsignedLong(mt[i]);
      long l1 = toUnsignedLong(mt[i - 1]);
      long l = (l0 ^ ((l1 ^ (l1 >> 30)) * 1566083941L)) - i; // non linear
      mt[i] = (int) (l & 0xffffffffL);
      i++;
      if (i >= N) {
        mt[0] = mt[N - 1];
        i = 1;
      }
    }

    mt[0] = 0x80000000; // MSB is 1; assuring non-zero initial array
  }

  private static long toUnsignedLong(int value) {
    return value & 0xffffffffL;
  }
}
