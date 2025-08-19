package network.crypta.support;

import java.util.regex.Matcher;

/**
 * This class contains various character classes from the <a
 * href="http://www.w3.org/TR/REC-xml/">XML 1.0 specification, 4th edition</a>.
 *
 * <p>The constants in this class are written in a form that allows easy conclusion in a {@link
 * Matcher} pattern within square parantheses (<code>'['</code> and <code>']'</code>).
 *
 * @author David Roden &lt;bombe@freenetproject.org&gt;
 * @version $Id$
 */
public interface XMLCharacterClasses {

  /** [89] Extender. */
  String EXTENDER = "·ːˑ·ـๆໆ々〱-〵ゝ-ゞー-ヾ";

  /** [88] Letter. */
  String DIGIT = "0-9٠-٩۰-۹०-९০-৯੦-੯૦-૯୦-୯௧-௯౦-౯೦-೯൦-൯๐-๙໐-໙༠-༩";

  /** [87] CombiningChar */
  String COMBINING_CHAR =
      "\u0300-\u0345\u0360-\u0361҃-֑҆-֣֡-ֹֻ-ֽֿׁ-ׂًׄ-ْٰۖ-ۜ\u06dd-۟۠-ۤۧ-۪ۨ-ۭँ-ः़ा-ौ्॑-॔ॢ-ॣঁ-ঃ়ািী-ৄে-ৈো-্ৗৢ-ৣਂ਼ਾਿੀ-ੂੇ-ੈੋ-੍ੰ-ੱઁ-ઃ઼ા-ૅે-ૉો-્ଁ-ଃ଼ା-ୃେ-ୈୋ-୍ୖ-ୗஂ-ஃா-ூெ-ைொ-்ௗఁ-ఃా-ౄె-ైొ-్ౕ-ౖಂ-ಃಾ-ೄೆ-ೈೊ-್ೕ-ೖം-ഃാ-ൃെ-ൈൊ-്ൗัิ-ฺ็-๎ັິ-ູົ-ຼ່-ໍ༘-༹༙༵༷༾༿ཱ-྄྆-ྋྐ-ྕྗྙ-ྭྱ-ྷྐྵ\u20d0-\u20dc\u20e1〪-゙゚〯";

  /** [86] Ideographic */
  String IDEOGRAPHIC = "一-龥〇〡-〩";

  /** [85] BaseChar */
  String BASE_CHAR =
      "A-Za-zÀ-ÖØ-öø-ÿĀ-ıĴ-ľŁ-ňŊ-žƀ-ǃǍ-ǰǴ-ǵǺ-ȗɐ-ʨʻ-ˁΆΈ-ΊΌΎ-ΡΣ-ώϐ-ϖϚϜϞϠϢ-ϳЁ-ЌЎ-яё-ќў-ҁҐ-ӄӇ-ӈӋ-ӌӐ-ӫӮ-ӵӸ-ӹԱ-Ֆՙա-ֆא-תװ-ײء-غف-يٱ-ڷں-ھۀ-ێې-ۓەۥ-ۦअ-हऽक़-ॡঅ-ঌএ-ঐও-নপ-রলশ-হড়-ঢ়য়-ৡৰ-ৱਅ-ਊਏ-ਐਓ-ਨਪ-ਰਲ-ਲ਼ਵ-ਸ਼ਸ-ਹਖ਼-ੜਫ਼ੲ-ੴઅ-ઋઍએ-ઑઓ-નપ-રલ-ળવ-હઽૠଅ-ଌଏ-ଐଓ-ନପ-ରଲ-ଳଶ-ହଽଡ଼-ଢ଼ୟ-ୡஅ-ஊஎ-ஐஒ-கங-சஜஞ-டண-தந-பம-வஷ-ஹఅ-ఌఎ-ఐఒ-నప-ళవ-హౠ-ౡಅ-ಌಎ-ಐಒ-ನಪ-ಳವ-ಹೞೠ-ೡഅ-ഌഎ-ഐഒ-നപ-ഹൠ-ൡก-ฮะา-ำเ-ๅກ-ຂຄງ-ຈຊຍດ-ທນ-ຟມ-ຣລວສ-ຫອ-ຮະາ-ຳຽເ-ໄཀ-ཇཉ-ཀྵႠ-Ⴥა-ჶᄀᄂ-ᄃᄅ-ᄇᄉᄋ-ᄌᄎ-ᄒᄼᄾᅀᅌᅎᅐᅔ-ᅕᅙᅟ-ᅡᅣᅥᅧᅩᅭ-ᅮᅲ-ᅳᅵᆞᆨᆫᆮ-ᆯᆷ-ᆸᆺᆼ-ᇂᇫᇰᇹḀ-ẛẠ-ỹἀ-ἕἘ-Ἕἠ-ὅὈ-Ὅὐ-ὗὙὛὝὟ-ώᾀ-ᾴᾶ-ᾼιῂ-ῄῆ-ῌῐ-ΐῖ-Ίῠ-Ῥῲ-ῴῶ-ῼΩK-Å℮ↀ-ↂぁ-ゔァ-ヺㄅ-ㄬ가-힣";

  /** [84] Letter. */
  String LETTER = BASE_CHAR + IDEOGRAPHIC;

  /**
   * [4] NameChar - due to regex rules this must be the first expression within square parantheses
   */
  String NAME_CHAR = "-" + LETTER + DIGIT + "." + "_" + ":" + COMBINING_CHAR + EXTENDER;

  /** [5] Name. */
  String NAME = LETTER + "_" + ":" + "][" + NAME_CHAR;
}
