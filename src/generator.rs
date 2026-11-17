//! Bitwarden's generator: random passwords, passphrases from the EFF long
//! word list, and usernames. The rules (character sets, minimums, what
//! "avoid ambiguous" leaves out) follow Bitwarden's clients, so a password
//! made here looks like one made there.
//!
//! Every choice is uniform, from the operating system's random source.

use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// The EFF long word list (CC BY 3.0, eff.org), as Bitwarden uses it:
/// 7776 lines of `dice<TAB>word`.
const WORD_LIST: &str = include_str!("../data/eff_large_wordlist.txt");

fn words() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&str>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| {
        WORD_LIST
            .lines()
            .filter_map(|line| line.split('\t').nth(1))
            .collect()
    })
}

fn word(rng: &mut impl Rng) -> &'static str {
    words().choose(rng).expect("the list isn't empty")
}

pub const LENGTH: std::ops::RangeInclusive<u32> = 5..=128;
/// A ticked class always gets at least one character.
pub const MINIMUM: std::ops::RangeInclusive<u32> = 1..=9;
pub const WORDS: std::ops::RangeInclusive<u32> = 3..=20;

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
pub const SPECIAL: &str = "!@#$%^&*";
/// Left out with "avoid ambiguous characters".
const AMBIGUOUS: &str = "IOl01";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: u32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub special: bool,
    pub min_digits: u32,
    pub min_special: u32,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 14,
            uppercase: true,
            lowercase: true,
            digits: true,
            special: false,
            min_digits: 1,
            min_special: 1,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: u32,
    /// One character, or none.
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernameKind {
    #[default]
    RandomWord,
    /// `name+random@example.com`
    PlusAddressed,
    /// `random@example.com`, for a domain that takes any address.
    CatchAll,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UsernameOptions {
    pub kind: UsernameKind,
    pub capitalize: bool,
    pub include_number: bool,
    /// The address to add `+random` to. Empty: the account's email.
    pub email: String,
    pub domain: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Password,
    Passphrase,
    Username,
}

/// What the generator was last set to; kept in the settings. Never a
/// generated value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    pub kind: Kind,
    pub password: PasswordOptions,
    pub passphrase: PassphraseOptions,
    pub username: UsernameOptions,
}

pub fn password(options: &PasswordOptions) -> String {
    password_with(options, &mut rand::rngs::OsRng)
}

pub fn passphrase(options: &PassphraseOptions) -> String {
    passphrase_with(options, &mut rand::rngs::OsRng)
}

/// `account_email` stands in for an empty `options.email`.
pub fn username(options: &UsernameOptions, account_email: &str) -> Result<String, String> {
    username_with(options, account_email, &mut rand::rngs::OsRng)
}

fn set(chars: &str, avoid_ambiguous: bool) -> Vec<char> {
    chars
        .chars()
        .filter(|c| !(avoid_ambiguous && AMBIGUOUS.contains(*c)))
        .collect()
}

fn password_with(options: &PasswordOptions, rng: &mut impl Rng) -> String {
    let mut options = options.clone();
    // With nothing ticked, Bitwarden falls back to lower case.
    if !(options.uppercase || options.lowercase || options.digits || options.special) {
        options.lowercase = true;
    }
    let avoid = options.avoid_ambiguous;
    let mut classes: Vec<(Vec<char>, u32)> = Vec::new();
    if options.uppercase {
        classes.push((set(UPPER, avoid), 1));
    }
    if options.lowercase {
        classes.push((set(LOWER, avoid), 1));
    }
    if options.digits {
        classes.push((
            set(DIGITS, avoid),
            options.min_digits.clamp(*MINIMUM.start(), *MINIMUM.end()),
        ));
    }
    if options.special {
        classes.push((
            set(SPECIAL, avoid),
            options.min_special.clamp(*MINIMUM.start(), *MINIMUM.end()),
        ));
    }
    let all: Vec<char> = classes
        .iter()
        .flat_map(|(chars, _)| chars.clone())
        .collect();
    let required: u32 = classes.iter().map(|(_, min)| min).sum();
    // The minimums win over a shorter length, as in Bitwarden.
    let length = options
        .length
        .clamp(*LENGTH.start(), *LENGTH.end())
        .max(required);
    let mut slots: Vec<&[char]> = Vec::with_capacity(length as usize);
    for (chars, min) in &classes {
        slots.extend(std::iter::repeat_n(chars.as_slice(), *min as usize));
    }
    while slots.len() < length as usize {
        slots.push(&all);
    }
    slots.shuffle(rng);
    slots
        .into_iter()
        .map(|chars| *chars.choose(rng).expect("never empty"))
        .collect()
}

fn capitalized(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn passphrase_with(options: &PassphraseOptions, rng: &mut impl Rng) -> String {
    let count = options.words.clamp(*WORDS.start(), *WORDS.end()) as usize;
    let mut picked: Vec<String> = (0..count)
        .map(|_| {
            let word = word(rng);
            if options.capitalize {
                capitalized(word)
            } else {
                word.to_string()
            }
        })
        .collect();
    if options.include_number {
        let at = rng.gen_range(0..count);
        picked[at].push(char::from(b'0' + rng.gen_range(0..10u8)));
    }
    let separator: String = options.separator.chars().take(1).collect();
    picked.join(&separator)
}

/// Eight lower-case letters and digits, as Bitwarden's email usernames use.
fn random_tag(rng: &mut impl Rng) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    (0..8)
        .map(|_| *chars.choose(rng).expect("never empty"))
        .collect()
}

fn username_with(
    options: &UsernameOptions,
    account_email: &str,
    rng: &mut impl Rng,
) -> Result<String, String> {
    match options.kind {
        UsernameKind::RandomWord => {
            let mut name = word(rng).to_string();
            if options.capitalize {
                name = capitalized(&name);
            }
            if options.include_number {
                name.push_str(&format!("{:04}", rng.gen_range(0..10_000)));
            }
            Ok(name)
        }
        UsernameKind::PlusAddressed => {
            let email = match options.email.trim() {
                "" => account_email.trim(),
                email => email,
            };
            let (local, domain) = email
                .rsplit_once('@')
                .filter(|(local, domain)| !local.is_empty() && !domain.is_empty())
                .ok_or("Enter an email address to add to.")?;
            // An address that is already plus-addressed gets a new tag.
            let local = local.split('+').next().unwrap_or(local);
            Ok(format!("{local}+{}@{domain}", random_tag(rng)))
        }
        UsernameKind::CatchAll => {
            let domain = options.domain.trim().trim_start_matches('@');
            if domain.is_empty() || !domain.contains('.') {
                return Err("Enter the catch-all domain.".into());
            }
            Ok(format!("{}@{domain}", random_tag(rng)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn count(text: &str, chars: &str) -> usize {
        text.chars().filter(|c| chars.contains(*c)).count()
    }

    #[test]
    fn word_list_is_the_eff_long_list() {
        assert_eq!(words().len(), 7776);
        assert_eq!(words().first(), Some(&"abacus"));
        assert_eq!(words().last(), Some(&"zoom"));
    }

    #[test]
    fn passwords_keep_their_rules() {
        let mut rng = StdRng::seed_from_u64(7);
        let options = PasswordOptions {
            length: 20,
            special: true,
            min_digits: 3,
            min_special: 2,
            avoid_ambiguous: true,
            ..Default::default()
        };
        for _ in 0..500 {
            let password = password_with(&options, &mut rng);
            assert_eq!(password.chars().count(), 20);
            assert!(count(&password, DIGITS) >= 3, "{password}");
            assert!(count(&password, SPECIAL) >= 2, "{password}");
            assert!(count(&password, UPPER) >= 1, "{password}");
            assert!(count(&password, LOWER) >= 1, "{password}");
            assert_eq!(count(&password, AMBIGUOUS), 0, "{password}");
        }
    }

    #[test]
    fn password_edge_cases() {
        let mut rng = StdRng::seed_from_u64(1);
        // Nothing ticked: lower case.
        let none = PasswordOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            special: false,
            ..Default::default()
        };
        let password = password_with(&none, &mut rng);
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
        // Minimums longer than the length stretch it.
        let tight = PasswordOptions {
            length: 5,
            special: true,
            min_digits: 9,
            min_special: 9,
            ..Default::default()
        };
        assert_eq!(password_with(&tight, &mut rng).len(), 20);
        // Out-of-range lengths are clamped.
        let long = PasswordOptions {
            length: 1000,
            ..Default::default()
        };
        assert_eq!(password_with(&long, &mut rng).len(), 128);
    }

    #[test]
    fn every_character_turns_up() {
        // A crude check that no character of the set is unreachable.
        let mut rng = StdRng::seed_from_u64(3);
        let options = PasswordOptions {
            length: 128,
            special: true,
            ..Default::default()
        };
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..50 {
            seen.extend(password_with(&options, &mut rng).chars());
        }
        assert_eq!(seen.len(), 26 + 26 + 10 + SPECIAL.len());
    }

    #[test]
    fn passphrases() {
        let mut rng = StdRng::seed_from_u64(9);
        let options = PassphraseOptions {
            words: 4,
            separator: "_x".into(),
            capitalize: true,
            include_number: true,
        };
        let phrase = passphrase_with(&options, &mut rng);
        let parts: Vec<&str> = phrase.split('_').collect();
        assert_eq!(parts.len(), 4, "{phrase}");
        assert!(parts
            .iter()
            .all(|p| p.starts_with(|c: char| c.is_ascii_uppercase())));
        assert_eq!(count(&phrase, DIGITS), 1, "{phrase}");
        let plain = passphrase_with(
            &PassphraseOptions {
                separator: String::new(),
                ..Default::default()
            },
            &mut rng,
        );
        assert!(plain.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn usernames() {
        let mut rng = StdRng::seed_from_u64(5);
        let word = username_with(
            &UsernameOptions {
                capitalize: true,
                include_number: true,
                ..Default::default()
            },
            "",
            &mut rng,
        )
        .unwrap();
        assert!(word.starts_with(|c: char| c.is_ascii_uppercase()));
        assert_eq!(count(&word, DIGITS), 4, "{word}");

        let plus = UsernameOptions {
            kind: UsernameKind::PlusAddressed,
            ..Default::default()
        };
        let address = username_with(&plus, "me+old@example.com", &mut rng).unwrap();
        assert!(address.starts_with("me+") && address.ends_with("@example.com"));
        assert_eq!(address.len(), "me+@example.com".len() + 8);
        assert!(username_with(&plus, "", &mut rng).is_err());

        let catch_all = UsernameOptions {
            kind: UsernameKind::CatchAll,
            domain: "@example.com".into(),
            ..Default::default()
        };
        let address = username_with(&catch_all, "", &mut rng).unwrap();
        assert!(address.ends_with("@example.com") && address.len() == 8 + 12);
    }
}
