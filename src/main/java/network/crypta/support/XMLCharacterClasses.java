package network.crypta.support;

import java.util.regex.Matcher;

/**
 * Character-class fragments from the XML 1.0 specification (4th edition) for building regular
 * expressions.
 *
 * <p>Most constants are <em>character-class fragments</em> intended to be inserted directly between
 * square brackets of a {@link Matcher} character class (that is, between {@code '['} and {@code
 * ']'}). Example:
 *
 * <pre>{@code
 * Pattern p = Pattern.compile("^[" + XMLCharacterClasses.NAME + "]*$");
 * boolean ok = p.matcher(candidate).matches();
 * }</pre>
 *
 * <p><strong>Note:</strong> {@link #NAME} is a composite string that deliberately embeds a closing
 * and reopening bracket sequence ({@code "]["}) so the expanded pattern enforces the XML {@code
 * Name} production as two character classes: one for the first character and another for subsequent
 * characters (e.g., {@code ^[<NameStart>_ : ][<NameChar>]*$}). Do not add extra brackets around
 * {@link #NAME}; use it as in the example above.
 *
 * <p>Thread-safety: this class is immutable and stateless. All fields are constants; there are no
 * side effects.
 *
 * <p>Specification notes:
 *
 * <ul>
 *   <li>Ranges reflect XML 1.0 (4th ed.) productions referenced in each comment; they are not
 *       automatically synchronized with later editions.
 *   <li>Unicode escapes use Java string syntax (for example, {@code \u0300}).
 * </ul>
 *
 * <p>Design note: This used to be an interface of constants. It is now a final utility class to
 * avoid the constants-in-interface anti‑pattern.
 */
public final class XMLCharacterClasses {

  // Utility class: prevent instantiation.
  private XMLCharacterClasses() {}

  /**
   * Characters that may extend XML names.
   *
   * <p>Matches the XML 1.0 production <em>Extender</em> ([89]). These code points may appear in a
   * name after the first character, according to the specification.
   *
   * @see #NAME_CHAR
   */
  public static final String EXTENDER = "·ːˑ·ـๆໆ々〱-〵ゝ-ゞー-ヾ";

  /**
   * Unicode digit ranges recognized by XML.
   *
   * <p>Matches the XML 1.0 production <em>Digit</em> ([88]). Includes ASCII digits and digits from
   * multiple scripts as defined by the specification.
   *
   * @see #NAME_CHAR
   */
  public static final String DIGIT = "0-9٠-٩۰-۹०-९০-৯੦-੯૦-૯୦-୯௧-௯౦-౯೦-೯൦-൯๐-๙໐-໙༠-༩";

  /**
   * Combining mark ranges.
   *
   * <p>Matches the XML 1.0 production <em>CombiningChar</em> ([87]). These marks may follow base
   * characters within an XML name when allowed by {@link #NAME_CHAR}.
   */
  public static final String COMBINING_CHAR =
      "\u0300-\u0345\u0360-\u0361҃-֑҆-֣֡-ֹֻ-ֽֿׁ-ׂًׄ-ْٰۖ-ۜ\u06dd-۟۠-ۤۧ-۪ۨ-ۭँ-ः़ा-ौ्॑-॔ॢ-ॣঁ-ঃ়ািী-ৄে-ৈো-্ৗৢ-ৣਂ਼ਾਿੀ-ੂੇ-ੈੋ-੍ੰ-ੱઁ-ઃ઼ા-ૅે-ૉો-્ଁ-ଃ଼ା-ୃେ-ୈୋ-୍ୖ-ୗஂ-ஃா-ூெ-ைொ-்ௗఁ-ఃా-ౄె-ైొ-్ౕ-ౖಂ-ಃಾ-ೄೆ-ೈೊ-್ೕ-ೖം-ഃാ-ൃെ-ൈൊ-്ൗัิ-ฺ็-๎ັິ-ູົ-ຼ່-ໍ༘-༹༙༵༷༾༿ཱ-྄྆-ྋྐ-ྕྗྙ-ྭྱ-ྷྐྵ\u20d0-\u20dc\u20e1〪-゙゚〯";

  /**
   * CJK ideographic ranges.
   *
   * <p>Matches the XML 1.0 production <em>Ideographic</em> ([86]). Included as part of the letter
   * set used by the XML name productions.
   */
  public static final String IDEOGRAPHIC = "一-龥〇〡-〩";

  /**
   * Base letter ranges across multiple scripts.
   *
   * <p>Matches the XML 1.0 production <em>BaseChar</em> ([85]). Used to form the general notion of
   * a letter per the XML name rules.
   */
  public static final String BASE_CHAR =
      "A-Za-zÀ-ÖØ-öø-ÿĀ-ıĴ-ľŁ-ňŊ-žƀ-ǃǍ-ǰǴ-ǵǺ-ȗɐ-ʨʻ-ˁΆΈ-ΊΌΎ-ΡΣ-ώϐ-ϖϚϜϞϠϢ-ϳЁ-ЌЎ-яё-ќў-ҁҐ-ӄӇ-ӈӋ-ӌӐ-ӫӮ-ӵӸ-ӹԱ-Ֆՙա-ֆא-תװ-ײء-غف-يٱ-ڷں-ھۀ-ێې-ۓەۥ-ۦअ-हऽक़-ॡঅ-ঌএ-ঐও-নপ-রলশ-হড়-ঢ়য়-ৡৰ-ৱਅ-ਊਏ-ਐਓ-ਨਪ-ਰਲ-ਲ਼ਵ-ਸ਼ਸ-ਹਖ਼-ੜਫ਼ੲ-ੴઅ-ઋઍએ-ઑઓ-નપ-રલ-ળવ-હઽૠଅ-ଌଏ-ଐଓ-ନପ-ରଲ-ଳଶ-ହଽଡ଼-ଢ଼ୟ-ୡஅ-ஊஎ-ஐஒ-கங-சஜஞ-டண-தந-பம-வஷ-ஹఅ-ఌఎ-ఐఒ-నప-ళవ-హౠ-ౡಅ-ಌಎ-ಐಒ-ನಪ-ಳವ-ಹೞೠ-ೡഅ-ഌഎ-ഐഒ-നപ-ഹൠ-ൡก-ฮะา-ำเ-ๅກ-ຂຄງ-ຈຊຍດ-ທນ-ຟມ-ຣລວສ-ຫອ-ຮະາ-ຳຽເ-ໄཀ-ཇཉ-ཀྵႠ-Ⴥა-ჶᄀᄂ-ᄃᄅ-ᄇᄉᄋ-ᄌᄎ-ᄒᄼᄾᅀᅌᅎᅐᅔ-ᅕᅙᅟ-ᅡᅣᅥᅧᅩᅭ-ᅮᅲ-ᅳᅵᆞᆨᆫᆮ-ᆯᆷ-ᆸᆺᆼ-ᇂᇫᇰᇹḀ-ẛẠ-ỹἀ-ἕἘ-Ἕἠ-ὅὈ-Ὅὐ-ὗὙὛὝὟ-ώᾀ-ᾴᾶ-ᾼιῂ-ῄῆ-ῌῐ-ΐῖ-Ίῠ-Ῥῲ-ῴῶ-ῼΩK-Å℮ↀ-ↂぁ-ゔァ-ヺㄅ-ㄬ가-힣";

  /**
   * Union of {@link #BASE_CHAR} and {@link #IDEOGRAPHIC}.
   *
   * <p>Convenience fragment used by the XML name productions to represent a letter.
   */
  public static final String LETTER = BASE_CHAR + IDEOGRAPHIC;

  /**
   * Characters allowed after the first character in an XML name.
   *
   * <p>Matches the XML 1.0 production <em>NameChar</em> ([4]). The hyphen is placed first so it is
   * treated literally when used inside a character class.
   */
  public static final String NAME_CHAR =
      "-" + LETTER + DIGIT + "." + "_" + ":" + COMBINING_CHAR + EXTENDER;

  /**
   * Composite fragment for validating a complete XML name.
   *
   * <p>Matches the XML 1.0 production <em>Name</em> ([5]) when used as shown in the class-level
   * example. This string intentionally includes {@code "]["} to separate the first-character class
   * from the subsequent-character class.
   */
  public static final String NAME = LETTER + "_" + ":" + "][" + NAME_CHAR;
}
