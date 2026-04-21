from urllib.parse import urlparse
import ipaddress

SUSPICIOUS_URLS = [
"verify","secure","account","admin","update",
"bank","telegram","daftar","free","bonus","claim",
"pendaftaran","cpns","pppk", "alert", "cashback",
"gift", "reward", "voucher", "diskon", "promo", "hadiah", "gratis",
"install", "urgent", "warning", "risk", "suspicious", "slot", "gacor", "zeus"
]

LOOKALIKE_BRANDS = [
"google",
"paypal",
"facebook",
"instagram",
"microsoft",
"apple",
"amazon",
"twitter",
"linkedin",
"whatsapp",
"tiktok",
"github",
"openai",
"netflix",
"spotify",
"zoom",
"dropbox",
"bca",
"bri",
"mandiri",
"ovo","gopay","dana","linkaja",
"shopee","tokopedia","bukalapak","lazada"
]

REPLACEMENTS = {
"0":"o",
"1":"l",
"3":"e",
"5":"s",
"@":"a",
"!":"i"

}

SHORTENERS = [
"bit.ly",
"tinyurl.com",
"t.co",
"rb.gy",
"cutt.ly",
"ow.ly",
"is.gd",
"buff.ly",
]


def has_ip(hostname):

    try:
        ipaddress.ip_address(hostname)
        return 1

    except:
        return 0


def normalize_lookalike(text):

    out=text.lower()

    for a,b in REPLACEMENTS.items():
        out=out.replace(a,b)

    return out


def has_homoglyph_brand(host):

    n=normalize_lookalike(host)

    for brand in LOOKALIKE_BRANDS:

        if brand in n and brand not in host.lower():
            return 1

    return 0



def extract_features(url):

    try:

        if not isinstance(url,str):
            url=str(url)

        url=url.strip()

        if "://" not in url:
            url="http://" + url

        parsed_url=urlparse(url)

        host=parsed_url.hostname or ""

        path=parsed_url.path or ""

        query=parsed_url.query or ""

        full=url.lower()

        return {

            "url_length": min(len(full), 150),

            "hostname_length":len(host),

            "path_length": min(len(path), 80),

            "query_length":len(query),

            "count_dot":full.count("."),

            "count_hyphen":full.count("-"),

            "count_at":full.count("@"),

            "count_question":full.count("?"),

            "count_equal":full.count("="),

            "count_digit":
            sum(c.isdigit() for c in full),

            "has_homoglyph_brand":
            has_homoglyph_brand(host),

            "has_punycode":
            1 if "xn--" in host else 0,

            "is_shortener":
            1 if host in SHORTENERS else 0,

            "has_https":
            1 if parsed_url.scheme=="https"
            else 0,

            "has_ip":
            has_ip(host),

            "suspicious_words_count":
            sum(
             1 for w in SUSPICIOUS_URLS
             if w in full
            )
        }

    except Exception:

        return {

            "url_length":0,

            "hostname_length":0,

            "path_length":0,

            "query_length":0,

            "count_dot":0,

            "count_hyphen":0,

            "count_at":0,

            "count_question":0,

            "count_equal":0,

            "count_digit":0,

            "has_homoglyph_brand":0,

            "has_punycode":0,

            "is_shortener":0,

            "has_https":0,

            "has_ip":0,

            "suspicious_words_count":0
        }