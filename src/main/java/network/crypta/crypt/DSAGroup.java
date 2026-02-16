package network.crypta.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.math.BigInteger;
import network.crypta.node.FSParseException;
import network.crypta.support.Base64;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;

/**
 * Immutable container for DSA group parameters.
 *
 * <p>The group consists of the prime modulus {@code p}, the subgroup order {@code q}, and a
 * generator {@code g}. Instances are value based and thread‑safe; all fields are immutable once
 * constructed. Callers are responsible for supplying valid parameters suitable for DSA — this type
 * only enforces that {@code p}, {@code q}, and {@code g} are positive integers.
 *
 * <p>A canonical 2048‑bit group is exposed as {@link Global#DSAgroupBigA}. Methods in this class
 * return that shared instance when the provided parameters match, to reduce allocations.
 */
public final class DSAGroup extends CryptoKey {
  @Serial private static final long serialVersionUID = -1;

  private final BigInteger p;
  private final BigInteger q;
  private final BigInteger g;

  /**
   * Create a group from explicit parameters.
   *
   * <p>This constructor does not validate primality or subgroup relationships. It verifies only
   * that all values are strictly positive. Use {@link Global#DSAgroupBigA} when the canonical
   * 2048‑bit group is desired.
   *
   * @param p prime modulus; must be positive
   * @param q subgroup order; must be positive
   * @param g generator; must be positive
   * @throws IllegalArgumentException if any parameter is non‑positive
   */
  public DSAGroup(BigInteger p, BigInteger q, BigInteger g) {
    this.p = p;
    this.q = q;
    this.g = g;
    if (p.signum() != 1 || q.signum() != 1 || g.signum() != 1) throw new IllegalArgumentException();
  }

  private DSAGroup(DSAGroup group) {
    this.p = new BigInteger(1, group.p.toByteArray());
    this.q = new BigInteger(1, group.q.toByteArray());
    this.g = new BigInteger(1, group.g.toByteArray());
  }

  /**
   * No‑arg constructor for Java serialization frameworks.
   *
   * <p>Not intended for direct use. Regular code should build instances via {@link
   * #DSAGroup(BigInteger, BigInteger, BigInteger)} or parse with {@link #readKey(InputStream)}.
   */
  DSAGroup() {
    p = null;
    q = null;
    g = null;
  }

  /**
   * Parse a group from a stream of MPI‑encoded integers.
   *
   * <p>The method expects {@code p}, {@code q}, and {@code g} in that order, each encoded as an MPI
   * (see {@link Util#readMPI(InputStream)}). When the parsed values match the canonical group, the
   * shared {@link Global#DSAgroupBigA} instance is returned.
   *
   * @param i input positioned at the first MPI; not closed
   * @return a {@code DSAGroup} (possibly {@link Global#DSAgroupBigA}) as a {@link CryptoKey}
   * @throws IOException if the stream cannot be read
   * @throws CryptFormatException if the values are syntactically valid but form an invalid group
   */
  public static CryptoKey readKey(InputStream i) throws IOException, CryptFormatException {
    BigInteger p;
    BigInteger q;
    BigInteger g;
    p = Util.readMPI(i);
    q = Util.readMPI(i);
    g = Util.readMPI(i);
    try {
      DSAGroup group = new DSAGroup(p, q, g);
      if (group.equals(Global.DSAgroupBigA)) {
        return Global.DSAgroupBigA;
      } else {
        return group;
      }
    } catch (IllegalArgumentException e) {
      throw (CryptFormatException) new CryptFormatException("Invalid group: " + e).initCause(e);
    }
  }

  /**
   * Short identifier describing this key family.
   *
   * <p>The format is {@code "DSA.g-<p-bit-length>"}, for example {@code "DSA.g-2048"}.
   *
   * @return a non‑empty identifier suitable for logs and UIs
   */
  @Override
  public String keyType() {
    return "DSA.g-" + p.bitLength();
  }

  /**
   * Return the prime modulus.
   *
   * @return positive {@link BigInteger} representing {@code p}
   */
  public BigInteger getP() {
    return p;
  }

  /**
   * Return the subgroup order.
   *
   * @return positive {@link BigInteger} representing {@code q}
   */
  public BigInteger getQ() {
    return q;
  }

  /**
   * Return the generator for the subgroup of order {@code q}.
   *
   * @return positive {@link BigInteger} representing {@code g}
   */
  public BigInteger getG() {
    return g;
  }

  /**
   * Compute a display fingerprint derived from {@code p}, {@code q}, and {@code g}.
   *
   * <p>See {@link CryptoKey#fingerprint()} for guidance on stability and usage.
   *
   * @return byte array containing the fingerprint
   */
  @Override
  public byte[] fingerprint() {
    BigInteger[] fp = new BigInteger[3];
    fp[0] = p;
    fp[1] = q;
    fp[2] = g;
    return fingerprint(fp);
  }

  /**
   * Encode the group as concatenated MPIs.
   *
   * <p>The return value is {@code MPI(p) || MPI(q) || MPI(g)}. It is suitable for persistence in
   * formats that understand the corresponding reader.
   *
   * @return the concatenated MPI encodings of {@code p}, {@code q}, and {@code g}
   */
  @Override
  public byte[] asBytes() {
    byte[] pb = Util.mpiBytes(p);
    byte[] qb = Util.mpiBytes(q);
    byte[] gb = Util.mpiBytes(g);
    byte[] tb = new byte[pb.length + qb.length + gb.length];
    System.arraycopy(pb, 0, tb, 0, pb.length);
    System.arraycopy(qb, 0, tb, pb.length, qb.length);
    System.arraycopy(gb, 0, tb, pb.length + qb.length, gb.length);
    return tb;
  }

  /** Value‑based equality on {@code p}, {@code q}, and {@code g}. */
  @Override
  public boolean equals(Object o) {
    if (this == o) { // Fast path for identity.
      return true;
    }
    return (o instanceof DSAGroup dsag) && p.equals(dsag.p) && q.equals(dsag.q) && g.equals(dsag.g);
  }

  /**
   * Convenience overload for value‑based equality.
   *
   * @param o other group; may be {@code null}
   * @return {@code true} when all three parameters are equal
   */
  @SuppressWarnings("NonOverridingEquals")
  public boolean equals(DSAGroup o) {
    if (o == null) {
      return false;
    }
    return p.equals(o.p) && q.equals(o.q) && g.equals(o.g);
  }

  /** Hash code consistent with {@link #equals(Object)}. */
  @Override
  public int hashCode() {
    return p.hashCode() ^ q.hashCode() ^ g.hashCode();
  }

  /**
   * Render the group into a {@link SimpleFieldSet}.
   *
   * <p>Keys are {@code p}, {@code q}, and {@code g}. Values are Base64 encodings of the
   * two's‑complement byte representation returned by {@link BigInteger#toByteArray()}.
   *
   * @return field set containing the three parameters
   */
  public SimpleFieldSet asFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("p", Base64.encode(p.toByteArray()));
    fs.putSingle("q", Base64.encode(q.toByteArray()));
    fs.putSingle("g", Base64.encode(g.toByteArray()));
    return fs;
  }

  /**
   * Create a group from a {@link SimpleFieldSet}.
   *
   * <p>The field set must contain Base64‑encoded entries {@code p}, {@code q}, and {@code g} whose
   * decoded values are interpreted as positive big‑endian integers. When the parameters match the
   * canonical group, {@link Global#DSAgroupBigA} is returned.
   *
   * @param fs source field set
   * @return a new {@code DSAGroup}, or the canonical shared instance when applicable
   * @throws IllegalBase64Exception if any field fails Base64 decoding
   * @throws FSParseException if a required field is missing
   * @throws IllegalArgumentException if a decoded value is non‑positive
   */
  public static DSAGroup create(SimpleFieldSet fs) throws IllegalBase64Exception, FSParseException {
    String myP = fs.get("p");
    String myQ = fs.get("q");
    String myG = fs.get("g");
    if (myP == null || myQ == null || myG == null)
      throw new FSParseException("The given SFS doesn't contain required fields!");
    BigInteger p = new BigInteger(1, Base64.decode(myP));
    BigInteger q = new BigInteger(1, Base64.decode(myQ));
    BigInteger g = new BigInteger(1, Base64.decode(myG));
    DSAGroup dg = new DSAGroup(p, q, g);
    if (dg.equals(Global.DSAgroupBigA)) return Global.DSAgroupBigA;
    return dg;
  }

  /**
   * Compact identifier string. Canonical groups are named explicitly.
   *
   * <p>Returns {@code "Global.DSAgroupBigA"} for the canonical group; otherwise defers to {@link
   * CryptoKey#toString()} which includes the key type and a shortened fingerprint.
   */
  @Override
  public String toString() {
    if (Global.DSAgroupBigA.equals(this)) return "Global.DSAgroupBigA";
    else return super.toString();
  }

  /**
   * Verbose description including full parameter values.
   *
   * <p>Returns {@code "Global.DSAgroupBigA"} for the canonical group; otherwise renders all three
   * parameters as hexadecimal via {@link HexUtil#biToHex(BigInteger)}.
   *
   * @return human‑readable string with the complete parameter set
   */
  @Override
  public String toLongString() {
    if (Global.DSAgroupBigA.equals(this)) return "Global.DSAgroupBigA";
    return "p=" + HexUtil.biToHex(p) + ", q=" + HexUtil.biToHex(q) + ", g=" + HexUtil.biToHex(g);
  }

  /**
   * Return an equivalent group instance.
   *
   * <p>For {@link Global#DSAgroupBigA} this method returns the shared instance. For other groups it
   * returns a new object containing the same values.
   *
   * @return {@code this} if canonical; otherwise a new, equivalent {@code DSAGroup}
   */
  public DSAGroup cloneKey() {
    if (Global.DSAgroupBigA.equals(this)) return Global.DSAgroupBigA;
    return new DSAGroup(this);
  }
}
