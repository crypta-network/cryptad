package network.crypta.clients.http.geoip;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.ref.SoftReference;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import network.crypta.clients.http.StaticToadlet;
import network.crypta.support.HTMLNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Converts IP addresses to an approximate country or region code using an on-disk GeoIP range
 * table.
 *
 * <p>This helper is used by the HTTP UI layer to turn an IP address (typically the peer address or
 * a remote client address) into a {@link Country} enum value that can be rendered as a
 * human-friendly label and, when available, a flag icon. It is intentionally lightweight: it reads
 * a compact encoded range list from a local database file, builds an in-memory search structure,
 * and then performs a binary search for lookups. Results are memoized in a small LRU-like cache to
 * avoid repeated searches for the same address.
 *
 * <p>The database file is treated as an optional, best-effort input. If the file is missing,
 * corrupted, or contains unknown country codes, lookups return {@code null} rather than failing the
 * caller. The instance keeps a soft reference to the full decoded table so the JVM may reclaim it
 * under memory pressure and the next lookup will reload it.
 *
 * <p><b>Thread-safety:</b> instances have mutable caches and are not designed for concurrent access
 * without external synchronization.
 */
public class IPConverter {
  private static final Logger LOG = LoggerFactory.getLogger(IPConverter.class);

  // Regex indicating ipranges start
  private static final String START = "##start##";
  private static final int MAX_ENTRIES = 100;

  // Local cache
  private final HashMap<Integer, Country> cache =
      new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Integer, Country> eldest) {
          return size() > MAX_ENTRIES;
        }
      };

  // Cached DB file content
  private SoftReference<Cache> fullCache;
  // Reference to singleton object
  private static IPConverter instance;
  // File containing IP ranges
  private final File dbFile;
  private boolean dbFileCorrupt;

  /**
   * Enumeration of GeoIP country/region codes used by the IP range database.
   *
   * <p>Each constant name corresponds to a two-character code embedded in the database file. The
   * associated display name is a user-facing label that can be shown in the UI and can optionally
   * be accompanied by a flag icon if a matching static resource exists.
   *
   * <p><b>Notable behaviors:</b>
   *
   * <ul>
   *   <li>Some values represent non-country concepts such as local addresses or proxies.
   *   <li>Flag availability is cached per enum constant to avoid repeated filesystem checks.
   * </ul>
   */
  public enum Country {
    /** GeoIP code {@code L0} ({@code localhost}). */
    L0("localhost"),
    /** GeoIP code {@code I0} ({@code IntraNet}). */
    I0("IntraNet"),
    /** GeoIP code {@code A1} ({@code Anonymous Proxy}). */
    A1("Anonymous Proxy"),
    /** GeoIP code {@code A2} ({@code Satellite Provider}). */
    A2("Satellite Provider"),
    /** GeoIP code {@code AP} ({@code AP Asia/Pacific Region}). */
    AP("AP Asia/Pacific Region"),
    /** GeoIP code {@code AF} ({@code AFGHANISTAN}). */
    AF("AFGHANISTAN"),
    /** GeoIP code {@code AX} ({@code ALAND ISLANDS}). */
    AX("ALAND ISLANDS"),
    /** GeoIP code {@code AL} ({@code ALBANIA}). */
    AL("ALBANIA"),
    /** GeoIP code {@code AN} ({@code NETHERLANDS ANTILLES}). */
    AN("NETHERLANDS ANTILLES"),
    /** GeoIP code {@code DZ} ({@code ALGERIA}). */
    DZ("ALGERIA"),
    /** GeoIP code {@code AS} ({@code AMERICAN SAMOA}). */
    AS("AMERICAN SAMOA"),
    /** GeoIP code {@code AD} ({@code ANDORRA}). */
    AD("ANDORRA"),
    /** GeoIP code {@code AO} ({@code ANGOLA}). */
    AO("ANGOLA"),
    /** GeoIP code {@code AI} ({@code ANGUILLA}). */
    AI("ANGUILLA"),
    /** GeoIP code {@code AQ} ({@code ANTARCTICA}). */
    AQ("ANTARCTICA"),
    /** GeoIP code {@code AG} ({@code ANTIGUA AND BARBUDA}). */
    AG("ANTIGUA AND BARBUDA"),
    /** GeoIP code {@code AR} ({@code ARGENTINA}). */
    AR("ARGENTINA"),
    /** GeoIP code {@code AM} ({@code ARMENIA}). */
    AM("ARMENIA"),
    /** GeoIP code {@code AW} ({@code ARUBA}). */
    AW("ARUBA"),
    /** GeoIP code {@code AU} ({@code AUSTRALIA}). */
    AU("AUSTRALIA"),
    /** GeoIP code {@code AT} ({@code AUSTRIA}). */
    AT("AUSTRIA"),
    /** GeoIP code {@code AZ} ({@code AZERBAIJAN}). */
    AZ("AZERBAIJAN"),
    /** GeoIP code {@code BS} ({@code BAHAMAS}). */
    BS("BAHAMAS"),
    /** GeoIP code {@code BH} ({@code BAHRAIN}). */
    BH("BAHRAIN "),
    /** GeoIP code {@code BD} ({@code BANGLADESH}). */
    BD("BANGLADESH "),
    /** GeoIP code {@code BB} ({@code BARBADOS}). */
    BB("BARBADOS "),
    /** GeoIP code {@code BY} ({@code BELARUS}). */
    BY("BELARUS "),
    /** GeoIP code {@code BE} ({@code BELGIUM}). */
    BE("BELGIUM "),
    /** GeoIP code {@code BZ} ({@code BELIZE}). */
    BZ("BELIZE "),
    /** GeoIP code {@code BJ} ({@code BENIN}). */
    BJ("BENIN "),
    /** GeoIP code {@code BM} ({@code BERMUDA}). */
    BM("BERMUDA "),
    /** GeoIP code {@code BT} ({@code BHUTAN}). */
    BT("BHUTAN "),
    /** GeoIP code {@code BO} ({@code BOLIVIA, PLURINATIONAL STATE OF}). */
    BO("BOLIVIA, PLURINATIONAL STATE OF "),
    /** GeoIP code {@code BQ} ({@code BONAIRE, SAINT EUSTATIUS AND SABA}). */
    BQ("BONAIRE, SAINT EUSTATIUS AND SABA "),
    /** GeoIP code {@code BA} ({@code BOSNIA AND HERZEGOVINA}). */
    BA("BOSNIA AND HERZEGOVINA "),
    /** GeoIP code {@code BW} ({@code BOTSWANA}). */
    BW("BOTSWANA "),
    /** GeoIP code {@code BV} ({@code BOUVET ISLAND}). */
    BV("BOUVET ISLAND "),
    /** GeoIP code {@code BR} ({@code BRAZIL}). */
    BR("BRAZIL "),
    /** GeoIP code {@code IO} ({@code BRITISH INDIAN OCEAN TERRITORY}). */
    IO("BRITISH INDIAN OCEAN TERRITORY "),
    /** GeoIP code {@code BN} ({@code BRUNEI DARUSSALAM}). */
    BN("BRUNEI DARUSSALAM "),
    /** GeoIP code {@code BG} ({@code BULGARIA}). */
    BG("BULGARIA "),
    /** GeoIP code {@code BF} ({@code BURKINA FASO}). */
    BF("BURKINA FASO "),
    /** GeoIP code {@code BI} ({@code BURUNDI}). */
    BI("BURUNDI "),
    /** GeoIP code {@code KH} ({@code CAMBODIA}). */
    KH("CAMBODIA "),
    /** GeoIP code {@code CM} ({@code CAMEROON}). */
    CM("CAMEROON "),
    /** GeoIP code {@code CA} ({@code CANADA}). */
    CA("CANADA "),
    /** GeoIP code {@code CV} ({@code CAPE VERDE}). */
    CV("CAPE VERDE "),
    /** GeoIP code {@code KY} ({@code CAYMAN ISLANDS}). */
    KY("CAYMAN ISLANDS "),
    /** GeoIP code {@code CF} ({@code CENTRAL AFRICAN REPUBLIC}). */
    CF("CENTRAL AFRICAN REPUBLIC "),
    /** GeoIP code {@code TD} ({@code CHAD}). */
    TD("CHAD "),
    /** GeoIP code {@code CL} ({@code CHILE}). */
    CL("CHILE "),
    /** GeoIP code {@code CN} ({@code CHINA}). */
    CN("CHINA "),
    /** GeoIP code {@code CX} ({@code CHRISTMAS ISLAND}). */
    CX("CHRISTMAS ISLAND "),
    /** GeoIP code {@code CC} ({@code COCOS (KEELING) ISLANDS}). */
    CC("COCOS (KEELING) ISLANDS "),
    /** GeoIP code {@code CO} ({@code COLOMBIA}). */
    CO("COLOMBIA "),
    /** GeoIP code {@code KM} ({@code COMOROS}). */
    KM("COMOROS "),
    /** GeoIP code {@code CG} ({@code CONGO}). */
    CG("CONGO "),
    /** GeoIP code {@code CD} ({@code CONGO, THE DEMOCRATIC REPUBLIC OF THE}). */
    CD("CONGO, THE DEMOCRATIC REPUBLIC OF THE "),
    /** GeoIP code {@code CK} ({@code COOK ISLANDS}). */
    CK("COOK ISLANDS "),
    /** GeoIP code {@code CR} ({@code COSTA RICA}). */
    CR("COSTA RICA "),
    /** GeoIP code {@code CI} ({@code COTE D'IVOIRE}). */
    CI("COTE D'IVOIRE "),
    /** GeoIP code {@code HR} ({@code CROATIA}). */
    HR("CROATIA "),
    /** GeoIP code {@code CU} ({@code CUBA}). */
    CU("CUBA "),
    /** GeoIP code {@code CW} ({@code CURACAO}). */
    CW("CURACAO "),
    /** GeoIP code {@code CY} ({@code CYPRUS}). */
    CY("CYPRUS "),
    /** GeoIP code {@code CZ} ({@code CZECH REPUBLIC}). */
    CZ("CZECH REPUBLIC "),
    /** GeoIP code {@code DK} ({@code DENMARK}). */
    DK("DENMARK "),
    /** GeoIP code {@code DJ} ({@code DJIBOUTI}). */
    DJ("DJIBOUTI "),
    /** GeoIP code {@code DM} ({@code DOMINICA}). */
    DM("DOMINICA "),
    /** GeoIP code {@code DO} ({@code DOMINICAN REPUBLIC}). */
    DO("DOMINICAN REPUBLIC "),
    /** GeoIP code {@code EC} ({@code ECUADOR}). */
    EC("ECUADOR "),
    /** GeoIP code {@code EG} ({@code EGYPT}). */
    EG("EGYPT "),
    /** GeoIP code {@code SV} ({@code EL SALVADOR}). */
    SV("EL SALVADOR "),
    /** GeoIP code {@code GQ} ({@code EQUATORIAL GUINEA}). */
    GQ("EQUATORIAL GUINEA "),
    /** GeoIP code {@code ER} ({@code ERITREA}). */
    ER("ERITREA "),
    /** GeoIP code {@code EE} ({@code ESTONIA}). */
    EE("ESTONIA "),
    /** GeoIP code {@code ET} ({@code ETHIOPIA}). */
    ET("ETHIOPIA "),
    /** GeoIP code {@code FK} ({@code FALKLAND ISLANDS (MALVINAS)}). */
    FK("FALKLAND ISLANDS (MALVINAS) "),
    /** GeoIP code {@code FO} ({@code FAROE ISLANDS}). */
    FO("FAROE ISLANDS "),
    /** GeoIP code {@code FJ} ({@code FIJI}). */
    FJ("FIJI "),
    /** GeoIP code {@code FI} ({@code FINLAND}). */
    FI("FINLAND "),
    /** GeoIP code {@code FR} ({@code FRANCE}). */
    FR("FRANCE "),
    /** GeoIP code {@code GF} ({@code FRENCH GUIANA}). */
    GF("FRENCH GUIANA "),
    /** GeoIP code {@code PF} ({@code FRENCH POLYNESIA}). */
    PF("FRENCH POLYNESIA "),
    /** GeoIP code {@code TF} ({@code FRENCH SOUTHERN TERRITORIES}). */
    TF("FRENCH SOUTHERN TERRITORIES "),
    /** GeoIP code {@code GA} ({@code GABON}). */
    GA("GABON "),
    /** GeoIP code {@code GM} ({@code GAMBIA}). */
    GM("GAMBIA "),
    /** GeoIP code {@code GE} ({@code GEORGIA}). */
    GE("GEORGIA "),
    /** GeoIP code {@code DE} ({@code GERMANY}). */
    DE("GERMANY "),
    /** GeoIP code {@code GH} ({@code GHANA}). */
    GH("GHANA "),
    /** GeoIP code {@code GI} ({@code GIBRALTAR}). */
    GI("GIBRALTAR "),
    /** GeoIP code {@code GR} ({@code GREECE}). */
    GR("GREECE "),
    /** GeoIP code {@code GL} ({@code GREENLAND}). */
    GL("GREENLAND "),
    /** GeoIP code {@code GD} ({@code GRENADA}). */
    GD("GRENADA "),
    /** GeoIP code {@code GP} ({@code GUADELOUPE}). */
    GP("GUADELOUPE "),
    /** GeoIP code {@code GU} ({@code GUAM}). */
    GU("GUAM "),
    /** GeoIP code {@code GT} ({@code GUATEMALA}). */
    GT("GUATEMALA "),
    /** GeoIP code {@code GG} ({@code GUERNSEY}). */
    GG("GUERNSEY "),
    /** GeoIP code {@code GN} ({@code GUINEA}). */
    GN("GUINEA "),
    /** GeoIP code {@code GW} ({@code GUINEA-BISSAU}). */
    GW("GUINEA-BISSAU "),
    /** GeoIP code {@code GY} ({@code GUYANA}). */
    GY("GUYANA "),
    /** GeoIP code {@code HT} ({@code HAITI}). */
    HT("HAITI "),
    /** GeoIP code {@code HM} ({@code HEARD ISLAND AND MCDONALD ISLANDS}). */
    HM("HEARD ISLAND AND MCDONALD ISLANDS "),
    /** GeoIP code {@code VA} ({@code HOLY SEE (VATICAN CITY STATE)}). */
    VA("HOLY SEE (VATICAN CITY STATE) "),
    /** GeoIP code {@code HN} ({@code HONDURAS}). */
    HN("HONDURAS "),
    /** GeoIP code {@code HK} ({@code HONG KONG}). */
    HK("HONG KONG "),
    /** GeoIP code {@code HU} ({@code HUNGARY}). */
    HU("HUNGARY "),
    /** GeoIP code {@code IS} ({@code ICELAND}). */
    IS("ICELAND "),
    /** GeoIP code {@code IN} ({@code INDIA}). */
    IN("INDIA "),
    /** GeoIP code {@code ID} ({@code INDONESIA}). */
    ID("INDONESIA "),
    /** GeoIP code {@code IR} ({@code IRAN, ISLAMIC REPUBLIC OF}). */
    IR("IRAN, ISLAMIC REPUBLIC OF "),
    /** GeoIP code {@code IQ} ({@code IRAQ}). */
    IQ("IRAQ "),
    /** GeoIP code {@code IE} ({@code IRELAND}). */
    IE("IRELAND "),
    /** GeoIP code {@code IM} ({@code ISLE OF MAN}). */
    IM("ISLE OF MAN "),
    /** GeoIP code {@code IL} ({@code ISRAEL}). */
    IL("ISRAEL "),
    /** GeoIP code {@code IT} ({@code ITALY}). */
    IT("ITALY "),
    /** GeoIP code {@code JM} ({@code JAMAICA}). */
    JM("JAMAICA "),
    /** GeoIP code {@code JP} ({@code JAPAN}). */
    JP("JAPAN "),
    /** GeoIP code {@code JE} ({@code JERSEY}). */
    JE("JERSEY "),
    /** GeoIP code {@code JO} ({@code JORDAN}). */
    JO("JORDAN "),
    /** GeoIP code {@code KZ} ({@code KAZAKHSTAN}). */
    KZ("KAZAKHSTAN "),
    /** GeoIP code {@code KE} ({@code KENYA}). */
    KE("KENYA "),
    /** GeoIP code {@code KI} ({@code KIRIBATI}). */
    KI("KIRIBATI "),
    /** GeoIP code {@code KP} ({@code KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF}). */
    KP("KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF "),
    /** GeoIP code {@code KR} ({@code KOREA, REPUBLIC OF}). */
    KR("KOREA, REPUBLIC OF "),
    /** GeoIP code {@code KW} ({@code KUWAIT}). */
    KW("KUWAIT "),
    /** GeoIP code {@code KG} ({@code KYRGYZSTAN}). */
    KG("KYRGYZSTAN "),
    /** GeoIP code {@code LA} ({@code LAO PEOPLE'S DEMOCRATIC REPUBLIC}). */
    LA("LAO PEOPLE'S DEMOCRATIC REPUBLIC "),
    /** GeoIP code {@code LV} ({@code LATVIA}). */
    LV("LATVIA "),
    /** GeoIP code {@code LB} ({@code LEBANON}). */
    LB("LEBANON "),
    /** GeoIP code {@code LS} ({@code LESOTHO}). */
    LS("LESOTHO "),
    /** GeoIP code {@code LR} ({@code LIBERIA}). */
    LR("LIBERIA "),
    /** GeoIP code {@code LY} ({@code LIBYAN ARAB JAMAHIRIYA}). */
    LY("LIBYAN ARAB JAMAHIRIYA "),
    /** GeoIP code {@code LI} ({@code LIECHTENSTEIN}). */
    LI("LIECHTENSTEIN "),
    /** GeoIP code {@code LT} ({@code LITHUANIA}). */
    LT("LITHUANIA "),
    /** GeoIP code {@code LU} ({@code LUXEMBOURG}). */
    LU("LUXEMBOURG "),
    /** GeoIP code {@code MO} ({@code MACAO}). */
    MO("MACAO "),
    /** GeoIP code {@code MK} ({@code MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF}). */
    MK("MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF "),
    /** GeoIP code {@code MG} ({@code MADAGASCAR}). */
    MG("MADAGASCAR "),
    /** GeoIP code {@code MW} ({@code MALAWI}). */
    MW("MALAWI "),
    /** GeoIP code {@code MY} ({@code MALAYSIA}). */
    MY("MALAYSIA "),
    /** GeoIP code {@code MV} ({@code MALDIVES}). */
    MV("MALDIVES "),
    /** GeoIP code {@code ML} ({@code MALI}). */
    ML("MALI "),
    /** GeoIP code {@code MT} ({@code MALTA}). */
    MT("MALTA "),
    /** GeoIP code {@code MH} ({@code MARSHALL ISLANDS}). */
    MH("MARSHALL ISLANDS "),
    /** GeoIP code {@code MQ} ({@code MARTINIQUE}). */
    MQ("MARTINIQUE "),
    /** GeoIP code {@code MR} ({@code MAURITANIA}). */
    MR("MAURITANIA "),
    /** GeoIP code {@code MU} ({@code MAURITIUS}). */
    MU("MAURITIUS "),
    /** GeoIP code {@code YT} ({@code MAYOTTE}). */
    YT("MAYOTTE "),
    /** GeoIP code {@code MX} ({@code MEXICO}). */
    MX("MEXICO "),
    /** GeoIP code {@code FM} ({@code MICRONESIA, FEDERATED STATES OF}). */
    FM("MICRONESIA, FEDERATED STATES OF "),
    /** GeoIP code {@code MD} ({@code MOLDOVA, REPUBLIC OF}). */
    MD("MOLDOVA, REPUBLIC OF "),
    /** GeoIP code {@code MC} ({@code MONACO}). */
    MC("MONACO "),
    /** GeoIP code {@code MN} ({@code MONGOLIA}). */
    MN("MONGOLIA "),
    /** GeoIP code {@code ME} ({@code MONTENEGRO}). */
    ME("MONTENEGRO "),
    /** GeoIP code {@code MS} ({@code MONTSERRAT}). */
    MS("MONTSERRAT "),
    /** GeoIP code {@code MA} ({@code MOROCCO}). */
    MA("MOROCCO "),
    /** GeoIP code {@code MZ} ({@code MOZAMBIQUE}). */
    MZ("MOZAMBIQUE "),
    /** GeoIP code {@code MM} ({@code MYANMAR}). */
    MM("MYANMAR "),
    /** GeoIP code {@code NA} ({@code NAMIBIA}). */
    NA("NAMIBIA "),
    /** GeoIP code {@code NR} ({@code NAURU}). */
    NR("NAURU "),
    /** GeoIP code {@code NP} ({@code NEPAL}). */
    NP("NEPAL "),
    /** GeoIP code {@code NL} ({@code NETHERLANDS}). */
    NL("NETHERLANDS "),
    /** GeoIP code {@code NC} ({@code NEW CALEDONIA}). */
    NC("NEW CALEDONIA "),
    /** GeoIP code {@code NZ} ({@code NEW ZEALAND}). */
    NZ("NEW ZEALAND "),
    /** GeoIP code {@code NI} ({@code NICARAGUA}). */
    NI("NICARAGUA "),
    /** GeoIP code {@code NE} ({@code NIGER}). */
    NE("NIGER "),
    /** GeoIP code {@code NG} ({@code NIGERIA}). */
    NG("NIGERIA "),
    /** GeoIP code {@code NU} ({@code NIUE}). */
    NU("NIUE "),
    /** GeoIP code {@code NF} ({@code NORFOLK ISLAND}). */
    NF("NORFOLK ISLAND "),
    /** GeoIP code {@code MP} ({@code NORTHERN MARIANA ISLANDS}). */
    MP("NORTHERN MARIANA ISLANDS "),
    /** GeoIP code {@code NO} ({@code NORWAY}). */
    NO("NORWAY "),
    /** GeoIP code {@code OM} ({@code OMAN}). */
    OM("OMAN "),
    /** GeoIP code {@code PK} ({@code PAKISTAN}). */
    PK("PAKISTAN "),
    /** GeoIP code {@code PW} ({@code PALAU}). */
    PW("PALAU "),
    /** GeoIP code {@code PS} ({@code PALESTINIAN TERRITORY, OCCUPIED}). */
    PS("PALESTINIAN TERRITORY, OCCUPIED "),
    /** GeoIP code {@code PA} ({@code PANAMA}). */
    PA("PANAMA "),
    /** GeoIP code {@code PG} ({@code PAPUA NEW GUINEA}). */
    PG("PAPUA NEW GUINEA "),
    /** GeoIP code {@code PY} ({@code PARAGUAY}). */
    PY("PARAGUAY "),
    /** GeoIP code {@code PE} ({@code PERU}). */
    PE("PERU "),
    /** GeoIP code {@code PH} ({@code PHILIPPINES}). */
    PH("PHILIPPINES "),
    /** GeoIP code {@code PN} ({@code PITCAIRN}). */
    PN("PITCAIRN "),
    /** GeoIP code {@code PL} ({@code POLAND}). */
    PL("POLAND "),
    /** GeoIP code {@code PT} ({@code PORTUGAL}). */
    PT("PORTUGAL "),
    /** GeoIP code {@code PR} ({@code PUERTO RICO}). */
    PR("PUERTO RICO "),
    /** GeoIP code {@code QA} ({@code QATAR}). */
    QA("QATAR "),
    /** GeoIP code {@code RE} ({@code REUNION}). */
    RE("REUNION "),
    /** GeoIP code {@code RO} ({@code ROMANIA}). */
    RO("ROMANIA "),
    /** GeoIP code {@code RU} ({@code RUSSIAN FEDERATION}). */
    RU("RUSSIAN FEDERATION "),
    /** GeoIP code {@code RW} ({@code RWANDA}). */
    RW("RWANDA "),
    /** GeoIP code {@code BL} ({@code SAINT BARTHELEMY}). */
    BL("SAINT BARTHELEMY "),
    /** GeoIP code {@code SH} ({@code SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA}). */
    SH("SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA "),
    /** GeoIP code {@code KN} ({@code SAINT KITTS AND NEVIS}). */
    KN("SAINT KITTS AND NEVIS "),
    /** GeoIP code {@code LC} ({@code SAINT LUCIA}). */
    LC("SAINT LUCIA "),
    /** GeoIP code {@code MF} ({@code SAINT MARTIN (FRENCH PART)}). */
    MF("SAINT MARTIN (FRENCH PART) "),
    /** GeoIP code {@code PM} ({@code SAINT PIERRE AND MIQUELON}). */
    PM("SAINT PIERRE AND MIQUELON "),
    /** GeoIP code {@code VC} ({@code SAINT VINCENT AND THE GRENADINES}). */
    VC("SAINT VINCENT AND THE GRENADINES "),
    /** GeoIP code {@code WS} ({@code SAMOA}). */
    WS("SAMOA "),
    /** GeoIP code {@code SM} ({@code SAN MARINO}). */
    SM("SAN MARINO "),
    /** GeoIP code {@code ST} ({@code SAO TOME AND PRINCIPE}). */
    ST("SAO TOME AND PRINCIPE "),
    /** GeoIP code {@code SA} ({@code SAUDI ARABIA}). */
    SA("SAUDI ARABIA "),
    /** GeoIP code {@code SN} ({@code SENEGAL}). */
    SN("SENEGAL "),
    /** GeoIP code {@code RS} ({@code SERBIA}). */
    RS("SERBIA "),
    /** GeoIP code {@code SC} ({@code SEYCHELLES}). */
    SC("SEYCHELLES "),
    /** GeoIP code {@code SL} ({@code SIERRA LEONE}). */
    SL("SIERRA LEONE "),
    /** GeoIP code {@code SG} ({@code SINGAPORE}). */
    SG("SINGAPORE "),
    /** GeoIP code {@code SX} ({@code SINT MAARTEN (DUTCH PART)}). */
    SX("SINT MAARTEN (DUTCH PART) "),
    /** GeoIP code {@code SK} ({@code SLOVAKIA}). */
    SK("SLOVAKIA "),
    /** GeoIP code {@code SI} ({@code SLOVENIA}). */
    SI("SLOVENIA "),
    /** GeoIP code {@code SB} ({@code SOLOMON ISLANDS}). */
    SB("SOLOMON ISLANDS "),
    /** GeoIP code {@code SO} ({@code SOMALIA}). */
    SO("SOMALIA "),
    /** GeoIP code {@code ZA} ({@code SOUTH AFRICA}). */
    ZA("SOUTH AFRICA "),
    /** GeoIP code {@code GS} ({@code SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS}). */
    GS("SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS "),
    /** GeoIP code {@code SS} ({@code SOUTH SUDAN}). */
    SS("SOUTH SUDAN"),
    /** GeoIP code {@code ES} ({@code SPAIN}). */
    ES("SPAIN "),
    /** GeoIP code {@code LK} ({@code SRI LANKA}). */
    LK("SRI LANKA "),
    /** GeoIP code {@code SD} ({@code SUDAN}). */
    SD("SUDAN "),
    /** GeoIP code {@code SR} ({@code SURINAME}). */
    SR("SURINAME "),
    /** GeoIP code {@code SJ} ({@code SVALBARD AND JAN MAYEN}). */
    SJ("SVALBARD AND JAN MAYEN "),
    /** GeoIP code {@code SZ} ({@code SWAZILAND}). */
    SZ("SWAZILAND "),
    /** GeoIP code {@code SE} ({@code SWEDEN}). */
    SE("SWEDEN "),
    /** GeoIP code {@code CH} ({@code SWITZERLAND}). */
    CH("SWITZERLAND "),
    /** GeoIP code {@code SY} ({@code SYRIAN ARAB REPUBLIC}). */
    SY("SYRIAN ARAB REPUBLIC "),
    /** GeoIP code {@code TW} ({@code TAIWAN, PROVINCE OF CHINA}). */
    TW("TAIWAN, PROVINCE OF CHINA "),
    /** GeoIP code {@code TJ} ({@code TAJIKISTAN}). */
    TJ("TAJIKISTAN "),
    /** GeoIP code {@code TZ} ({@code TANZANIA, UNITED REPUBLIC OF}). */
    TZ("TANZANIA, UNITED REPUBLIC OF "),
    /** GeoIP code {@code TH} ({@code THAILAND}). */
    TH("THAILAND "),
    /** GeoIP code {@code TL} ({@code TIMOR-LESTE}). */
    TL("TIMOR-LESTE "),
    /** GeoIP code {@code TG} ({@code TOGO}). */
    TG("TOGO "),
    /** GeoIP code {@code TK} ({@code TOKELAU}). */
    TK("TOKELAU "),
    /** GeoIP code {@code TO} ({@code TONGA}). */
    TO("TONGA "),
    /** GeoIP code {@code TT} ({@code TRINIDAD AND TOBAGO}). */
    TT("TRINIDAD AND TOBAGO "),
    /** GeoIP code {@code TN} ({@code TUNISIA}). */
    TN("TUNISIA "),
    /** GeoIP code {@code TR} ({@code TURKEY}). */
    TR("TURKEY "),
    /** GeoIP code {@code TM} ({@code TURKMENISTAN}). */
    TM("TURKMENISTAN "),
    /** GeoIP code {@code TC} ({@code TURKS AND CAICOS ISLANDS}). */
    TC("TURKS AND CAICOS ISLANDS "),
    /** GeoIP code {@code TV} ({@code TUVALU}). */
    TV("TUVALU "),
    /** GeoIP code {@code UG} ({@code UGANDA}). */
    UG("UGANDA "),
    /** GeoIP code {@code UA} ({@code UKRAINE}). */
    UA("UKRAINE "),
    /** GeoIP code {@code AE} ({@code UNITED ARAB EMIRATES}). */
    AE("UNITED ARAB EMIRATES "),
    /** GeoIP code {@code GB} ({@code UNITED KINGDOM}). */
    GB("UNITED KINGDOM "),
    /** GeoIP code {@code US} ({@code UNITED STATES}). */
    US("UNITED STATES "),
    /** GeoIP code {@code UM} ({@code UNITED STATES MINOR OUTLYING ISLANDS}). */
    UM("UNITED STATES MINOR OUTLYING ISLANDS "),
    /** GeoIP code {@code UY} ({@code URUGUAY}). */
    UY("URUGUAY "),
    /** GeoIP code {@code UZ} ({@code UZBEKISTAN}). */
    UZ("UZBEKISTAN "),
    /** GeoIP code {@code VU} ({@code VANUATU}). */
    VU("VANUATU "),
    /** GeoIP code {@code VE} ({@code VENEZUELA, BOLIVARIAN REPUBLIC OF}). */
    VE("VENEZUELA, BOLIVARIAN REPUBLIC OF "),
    /** GeoIP code {@code VN} ({@code VIET NAM}). */
    VN("VIET NAM "),
    /** GeoIP code {@code VG} ({@code VIRGIN ISLANDS, BRITISH}). */
    VG("VIRGIN ISLANDS, BRITISH "),
    /** GeoIP code {@code VI} ({@code VIRGIN ISLANDS, U.S.}). */
    VI("VIRGIN ISLANDS, U.S. "),
    /** GeoIP code {@code WF} ({@code WALLIS AND FUTUNA}). */
    WF("WALLIS AND FUTUNA "),
    /** GeoIP code {@code EH} ({@code WESTERN SAHARA}). */
    EH("WESTERN SAHARA "),
    /** GeoIP code {@code YE} ({@code YEMEN}). */
    YE("YEMEN "),
    /** GeoIP code {@code ZM} ({@code ZAMBIA}). */
    ZM("ZAMBIA "),
    /** GeoIP code {@code ZW} ({@code ZIMBABWE}). */
    ZW("ZIMBABWE "),
    /** GeoIP code {@code ZZ} ({@code NA}). */
    ZZ("NA"),
    /** GeoIP code {@code EU} ({@code European Union}). */
    EU("European Union");
    private final String name;
    private static final ConcurrentHashMap<Country, Boolean> FLAG_CACHE = new ConcurrentHashMap<>();

    Country(String name) {
      this.name = name;
    }

    /**
     * Returns the display name for this country/region code.
     *
     * <p>This value is intended for UI display and comes from the database-provided mapping used by
     * {@link IPConverter}. It is not guaranteed to match any specific external naming standard and
     * should not be used as a stable identifier; use {@link #name()} when a stable code is needed.
     *
     * @return human-readable label for this entry, suitable for UI rendering.
     */
    public String getName() {
      return name;
    }

    /**
     * Adds an {@code <img>} element for this entry's flag icon, when available.
     *
     * <p>The icon is resolved relative to the static files root (see {@link StaticToadlet}) and the
     * presence check is cached per enum constant. If no icon exists, this method performs no
     * modification to {@code parent}.
     *
     * @param parent HTML node to append an icon element to; must be non-null and mutable.
     */
    public void renderFlagIcon(HTMLNode parent) {
      String flagPath = getFlagIconPath();
      if (flagPath != null)
        parent.addChild(
            "img",
            new String[] {"src", "class", "title"},
            new String[] {StaticToadlet.ROOT_URL + flagPath, "flag", getName()});
    }

    /**
     * Returns whether a flag icon exists for this country/region code.
     *
     * <p>This method is a convenience wrapper around {@link #getFlagIconPath()}. The result is
     * cached and will not reflect filesystem changes after the first check in the current process.
     *
     * @return {@code true} if a static flag icon file exists; {@code false} otherwise.
     */
    public boolean hasFlagIcon() {
      return getFlagIconPath() != null;
    }

    /** Does not check whether it exists. Relative to the top of static files. */
    private String flagIconPath() {
      return "icon/flags/" + toString().toLowerCase(Locale.ROOT) + ".png";
    }

    /**
     * Returns the static path for this entry's flag icon, or {@code null} when unavailable.
     *
     * <p>The returned value is a relative path under the static files root (for example, {@code
     * icon/flags/us.png}). The method caches both the existence check and the result.
     *
     * @return relative static path to the flag icon, or {@code null} if none exists.
     */
    public String getFlagIconPath() {
      String flagPath = flagIconPath();
      boolean hasFlag =
          FLAG_CACHE.computeIfAbsent(this, country -> StaticToadlet.haveFile(flagPath));
      return hasFlag ? flagPath : null;
    }
  }

  private static final Map<Short, Country> COUNTRIES_BY_CODE;

  static {
    Map<Short, Country> byCode = new HashMap<>();
    for (Country country : Country.values()) {
      short encoded = encodeCountryCode(country.name());
      if (byCode.put(encoded, country) != null) {
        throw new IllegalStateException("Duplicate country code: " + country.name());
      }
    }
    COUNTRIES_BY_CODE = Map.copyOf(byCode);
  }

  // Base85 Decoding table
  private static final char[] base85 = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z', '.', ',', ';', '\'', '"', '`', '<', '>', '{', '}', '[', ']', '=', '+',
    '-', '~', '*', '@', '#', '%', '$', '&', '!', '?'
  };
  private static final int BASE = base85.length;
  // XXX this is actually base86, not base85!
  private static final byte[] base85inv = new byte[128 - 32];

  static {
    Arrays.fill(base85inv, (byte) -1);
    for (int i = 0; i < base85.length; i++) {
      base85inv[base85[i] - 32] = (byte) i;
    }
  }

  /**
   * Constructs a new {@link IPConverter} bound to a specific GeoIP database file.
   *
   * <p>The file is treated as an optional input: callers may create an instance before the file is
   * present, and lookups will return {@code null} until a readable and parseable database exists.
   *
   * @param dbFile file containing the encoded IP range table; must not be {@code null}.
   */
  private IPConverter(File dbFile) {
    this.dbFile = dbFile;
  }

  /**
   * Returns a singleton {@link IPConverter} instance for the provided database file.
   *
   * <p>If the current singleton is {@code null} or was created for a different {@code file}, a new
   * instance is created and replaces the previous singleton reference.
   *
   * <p><b>Thread-safety:</b> this method is not synchronized. Concurrent callers may observe races
   * when swapping the singleton; all created instances should be functionally equivalent for a
   * given file path.
   *
   * @param file database file that should back the singleton instance; must not be {@code null}.
   * @return singleton instance configured to read from {@code file}.
   */
  public static IPConverter getInstance(File file) {
    if (instance == null || !instance.getDBFile().equals(file)) {
      instance = new IPConverter(file);
    }
    return instance;
  }

  private static short countryCodeOrUnknown(String code) {
    try {
      short encoded = encodeCountryCode(code);
      if (COUNTRIES_BY_CODE.containsKey(encoded)) {
        return encoded;
      }
    } catch (IllegalArgumentException _) {
      // fall through to log and return unknown
    }
    // Does not invalidate the whole file, just means the country list is out of date.
    LOG.error("Country not in list: {}", code);
    return (short) -1;
  }

  private static short encodeCountryCode(String code) {
    if (code == null || code.length() != 2) {
      throw new IllegalArgumentException("Invalid country code: " + code);
    }
    return (short) ((code.charAt(0) << 8) | code.charAt(1));
  }

  /**
   * Reads and decodes the GeoIP range table from {@link #dbFile}.
   *
   * <p>This method scans the file until it finds the {@link #START} marker, decodes the compact
   * range representation into two parallel arrays, and returns them wrapped in a {@link Cache}. Any
   * read or parse failure is handled internally and results in a {@code null} return value.
   *
   * @return decoded cache, or {@code null} when the file is missing or cannot be parsed.
   */
  private Cache readRanges() {
    try (RandomAccessFile raf = new RandomAccessFile(dbFile, "r")) {
      String line;
      do {
        line = raf.readLine();
      } while (!line.startsWith(START));
      // Remove ##start##
      line = line.substring(START.length());
      // Count of entries (each being 7 Bytes)
      int size = line.length() / 7;
      // Arrays to form a Cache
      short[] codes = new short[size];
      int[] ips = new int[size];
      // Read ips and add it to ip table
      for (int i = 0, offset = 0; i < size; i++, offset += 7) {
        // Code
        String code = line.substring(offset, offset + 2);
        // Ip
        String ipcode = line.substring(offset + 2, offset + 7);
        long ip = decodeBase85(ipcode.getBytes(StandardCharsets.ISO_8859_1));
        codes[i] = countryCodeOrUnknown(code);
        ips[i] = (int) ip;
      }
      return new Cache(codes, ips);
    } catch (FileNotFoundException e) {
      // Not downloaded yet
      LOG.warn("Database file not found.", e);
    } catch (IOException e) {
      LOG.error(e.getMessage());
    } catch (IPConverterParseException e) {
      LOG.error("IP-to-country database file is corrupt: {}", e, e);
      // Don't try again until next restart.
      dbFileCorrupt = true;
    }
    return null;
  }

  /**
   * Converts an IPv4 address from dotted-decimal notation to a numeric value.
   *
   * <p>The returned value is the 32-bit IPv4 address interpreted as an unsigned integer and stored
   * in the low 32 bits of the returned {@code long}. Each octet is parsed as a decimal integer and
   * reduced modulo 256 to obtain a byte value.
   *
   * @param ip IPv4 address in dotted-decimal form (for example, {@code 192.0.2.1}).
   * @return numeric value for the address, suitable for {@link #locateIP(long)} lookups.
   * @throws NumberFormatException If the string is not an IP address.
   */
  public long ip2num(String ip) {
    String[] split = IPV4_SPLITTER.split(ip);
    if (split.length != 4) throw new NumberFormatException();
    long num = 0;
    long coef = (256 << 16);
    for (String s : split) {
      long modulo = Integer.parseInt(s) % 256;
      num += (modulo * coef);
      coef >>= 8;
    }
    return num;
  }

  /**
   * Locates the {@link Country} for an IPv4 address provided as a string.
   *
   * <p>This is a convenience overload that parses the dotted-decimal IPv4 string and then performs
   * a lookup against the current in-memory cache. If the database file cannot be loaded or the
   * input string is not a valid IPv4 address, this method returns {@code null}.
   *
   * <p>This method does not perform network I/O; it reads only from the on-disk database file when
   * the decoded table is not currently cached in memory.
   *
   * @param ip IPv4 address in dotted-decimal form; may be {@code null}.
   * @return matched country/region, or {@code null} if unknown or unavailable.
   */
  public Country locateIP(String ip) {
    if (ip == null) return null;
    long longip;
    try {
      longip = ip2num(ip);
    } catch (NumberFormatException _) {
      return null; // Not an IP address.
    }
    return locateIP(longip);
  }

  /**
   * Locates the {@link Country} for an IP address provided as raw bytes.
   *
   * <p>This overload accepts either an IPv4 address (4 bytes) or an IPv6 address (16 bytes). For a
   * subset of IPv6 transition mechanisms (for example, 6to4 and Teredo), it attempts to derive an
   * embedded IPv4 address and then performs an IPv4 lookup. Other IPv6 addresses are not currently
   * handled and result in {@code null}.
   *
   * @param ip raw address bytes in network byte order; may be {@code null}.
   * @return matched country/region, or {@code null} if unsupported, unknown, or unavailable.
   */
  public Country locateIP(byte[] ip) {
    if (ip == null) return null;
    if (ip.length == 16) {
      /* Convert some special IPv6 addresses to IPv4 */
      if (ip[0] == (byte) 0x20 && ip[1] == (byte) 0x02) {
        // 2002::/16, 6to4 tunnels
        ip = Arrays.copyOfRange(ip, 2, 6);
      } else if ((ip[0] == (byte) 0
          && ip[1] == (byte) 0
          && ip[2] == (byte) 0
          && ip[3] == (byte) 0
          && ip[4] == (byte) 0
          && ip[5] == (byte) 0
          && ip[6] == (byte) 0
          && ip[7] == (byte) 0
          && ip[8] == (byte) 0
          && ip[9] == (byte) 0
          && ip[10] == (byte) 0
          && ip[11] == (byte) 0)) {
        // ::/96, deprecated IPv4-compatible IPv6
        ip = Arrays.copyOfRange(ip, 12, 16);
      } else if ((ip[0] == (byte) 0x20
          && ip[1] == (byte) 0x01
          && ip[2] == (byte) 0x00
          && ip[3] == (byte) 0x00)) {
        // 2001:0::/32, Teredo tunnels
        //  4..8  = server adderss
        //  9..10 = flags
        // 10..11 = client port (inverted)
        // 12..16 = client address (inverted)
        ip = Arrays.copyOfRange(ip, 12, 16);
        ip[0] ^= (byte) 0xff; // deinvert
        ip[1] ^= (byte) 0xff;
        ip[2] ^= (byte) 0xff;
        ip[3] ^= (byte) 0xff;
      }
      /* we cannot handle other IPv6 addresses (yet) */
    }
    if (ip.length != 4) return null;
    long longip =
        (((ip[0] << 24) & 0xff000000L)
            | ((ip[1] << 16) & 0x00ff0000L)
            | ((ip[2] << 8) & 0x0000ff00L)
            | (ip[3] & 0x000000ffL));
    return locateIP(longip);
  }

  private Country locateIP(long longip) {
    // Check cache first
    Country cached = cache.get((int) longip);
    if (cached != null) {
      return cached;
    }
    Cache memCache = getCache();
    if (memCache == null) return null;
    int[] ips = memCache.getIps();
    short[] codes = memCache.getCodes();
    // Binary search
    int start = 0;
    int last = ips.length - 1;
    int mid;
    while ((mid = (last - start) / 2) > 0) {
      int midpos = mid + start;
      long midip = ips[midpos] & 0xffffffffL;
      if (longip >= midip) {
        last = midpos;
      } else {
        start = midpos;
      }
    }
    short countryCode = codes[last];
    if (countryCode < 0) return null;
    Country country = COUNTRIES_BY_CODE.get(countryCode);
    if (country == null) return null;
    cache.put((int) longip, country);
    return country;
  }

  /**
   * Returns the decoded GeoIP range table, loading it if necessary.
   *
   * <p>The decoded range table is stored behind a {@link SoftReference}. This allows the JVM to
   * reclaim the arrays under memory pressure, trading memory for occasional reload cost. If the
   * database file has previously been marked as corrupt in this process, this method returns {@code
   * null} without retrying.
   *
   * @return decoded range table cache, or {@code null} if unavailable.
   */
  private Cache getCache() {
    Cache memCache = null;
    synchronized (IPConverter.class) {
      if (fullCache != null) memCache = fullCache.get();
      if (memCache == null) {
        if (dbFileCorrupt) return null;
        memCache = readRanges();
        fullCache = new SoftReference<>(memCache);
      }
    }
    return memCache;
  }

  /**
   * Decodes a 5-byte base-N encoded value into a numeric address boundary.
   *
   * <p>The GeoIP range table stores compact address boundaries using an alphabet defined by {@link
   * #base85}. This method validates the input against {@link #base85inv} and computes the
   * corresponding value as an unsigned integer stored in the returned {@code long}.
   *
   * @param code encoded bytes; must contain exactly 5 ASCII characters from the supported alphabet.
   * @return decoded numeric value suitable for comparison with {@code longip}.
   * @throws IPConverterParseException if {@code code} is the wrong length or contains invalid
   *     bytes.
   */
  private long decodeBase85(byte[] code) throws IPConverterParseException {
    long result = 0;
    if (code.length != 5) throw new IPConverterParseException();
    for (byte b : code) {
      if (b < (byte) 32 || base85inv[b - 32] < (byte) 0) throw new IPConverterParseException();
      result = (result * BASE) + base85inv[b - 32];
    }
    return result;
  }

  /**
   * Returns the database file containing encoded IP ranges.
   *
   * <p>This accessor is primarily used to decide whether the singleton instance should be replaced
   * by {@link #getInstance(File)}.
   *
   * @return file backing this converter instance.
   */
  File getDBFile() {
    return this.dbFile;
  }
}
