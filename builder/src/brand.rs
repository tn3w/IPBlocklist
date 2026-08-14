use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

const FORMS: &str = "inc incorporated llc ltd ltda limited gmbh mbh ag kgaa ohg ev eg \
    sa sab saa sau sal saog sac sas sarl srl spa nv bv cv asa aps oyj kft zrt nyrt doo \
    sro ooo zao pao pjsc jsc ojsc llp plc pte pteltd pty corp corporation company \
    holding holdings group uab sia tov oao pt sdn bhd coltd coltda eireli ead ood eood \
    sti ltdsti spzoo";
const TAILS: &str = "de me epp co as ab ad dd bt lc lp se sl slu sp z oo zoo oy ao esp \
    kg network networks net telecom telecoms telecommunication telecommunications \
    telecomunicaciones comunicaciones communication communications hosting solutions \
    services service technologies technology tech systems system data datacenter \
    datacentre cloud internet online isp international global enterprises enterprise \
    backbone provider providers of and";
const LEAD_WORDS: &str = "the llc ltd gmbh sarl ooo zao pao ao oao jsc ojsc pjsc uab \
    sia tov pt pp ps ip spolka";
const TLDS: [&str; 4] = [".com", ".net", ".org", ".io"];

fn words(list: &'static str) -> HashSet<&'static str> {
    list.split_whitespace().collect()
}

fn tail() -> &'static HashSet<&'static str> {
    static TAIL: OnceLock<HashSet<&'static str>> = OnceLock::new();
    TAIL.get_or_init(|| {
        let mut set = words(FORMS);
        set.extend(words(TAILS));
        set.insert("");
        set
    })
}

fn lead() -> &'static HashSet<&'static str> {
    static LEAD: OnceLock<HashSet<&'static str>> = OnceLock::new();
    LEAD.get_or_init(|| words(LEAD_WORDS))
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}

fn trading() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"(?i)^.*\b(?:trading as|d/b/a|dba)\b\s*")
}

fn alias() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"\(.*?\)|,.*|\s+-\s+.*")
}

fn numbered() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"^(?i:AS\d+)$")
}

fn handle_tail() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"-(AS|AP|US|UK|DE|FR|IN|CN|JP|EU|NET|COM|ORG)$")
}

fn network_tail() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    regex(&CELL, r"(NET|COM|TEL|WEB|LINE)$")
}

fn bare(word: &str) -> String {
    word.to_lowercase()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect()
}

fn shouting(word: &str) -> bool {
    word.chars().any(char::is_uppercase) && !word.chars().any(char::is_lowercase)
}

fn titled(word: &str) -> String {
    let mut characters = word.chars();
    match characters.next() {
        None => String::new(),
        Some(first) => {
            first.to_uppercase().collect::<String>()
                + &characters.as_str().to_lowercase()
        }
    }
}

/// Shouted words stop shouting, `GOOGLE` reading as `Google` and `IBM` as `IBM`.
fn cased(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let loud = word.chars().count() > 4
                && word.chars().all(char::is_alphabetic)
                && shouting(word);
            if loud { titled(word) } else { word.to_string() }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Aliases, legal forms and the words every network shares, all stripped.
fn from_company(company: &str) -> String {
    let plain = alias().replace_all(&trading().replace(company, ""), "").into_owned();
    let mut tokens: Vec<&str> = plain
        .split_whitespace()
        .map(|word| word.trim_matches(['"', '\'']))
        .filter(|token| !token.is_empty())
        .collect();

    while tokens.len() > 1 && tail().contains(bare(tokens[tokens.len() - 1]).as_str()) {
        tokens.pop();
    }
    while !tokens.is_empty() && {
        let first = bare(tokens[0]);
        first.is_empty() || lead().contains(first.as_str())
    } {
        tokens.remove(0);
    }

    let name = tokens.join(" ");
    if bare(&name).is_empty() {
        return String::new();
    }

    let lower = name.to_lowercase();
    let cut = TLDS.iter().find(|tld| lower.ends_with(**tld)).map_or(0, |tld| tld.len());
    cased(&name[..name.len() - cut])
}

/// The first word of a registry handle, its country and network tails gone.
fn from_handle(handle: &str) -> String {
    let head = handle.split_whitespace().next().unwrap_or("");
    let head = handle_tail().replace(head, "").into_owned();
    if numbered().is_match(&head) {
        return String::new();
    }

    let head = match head.chars().count() > 4 && shouting(&head) {
        true => network_tail().replace(&head, "").into_owned(),
        false => head,
    };
    cased(&head)
}

/// The name a network goes by: its handle where the company only spells it out.
pub fn brand(handle: &str, company: &str) -> String {
    let legal = from_company(company);
    let short = from_handle(handle);
    if legal.is_empty() || short.is_empty() {
        return if legal.is_empty() { short } else { legal };
    }
    if legal.eq_ignore_ascii_case(&short) {
        return if shouting(&short) { legal } else { short };
    }

    let prefix = format!("{} ", short.to_lowercase());
    match legal.to_lowercase().starts_with(&prefix) {
        true => short,
        false => legal,
    }
}

#[cfg(test)]
mod tests {
    use super::brand;

    #[test]
    fn handles_and_companies_become_brands() {
        for (handle, company, expected) in [
            ("CLOUDFLARENET", "Cloudflare, Inc.", "Cloudflare"),
            ("XTOM-AS-JP", "xTom Limited", "xTom"),
            ("M247", "M247 Europe SRL", "M247"),
            ("AS41564", "Orion Network Limited", "Orion"),
            ("ProtonVPN", "Proton AG", "Proton"),
            ("CDNEXT", "Datacamp Limited", "Datacamp"),
            ("GTELECOM-AS-AP", "Gtelecom Pty Ltd", "Gtelecom"),
            ("CDN77", "", "CDN77"),
        ] {
            assert_eq!(brand(handle, company), expected, "{handle}/{company}");
        }
    }
}
