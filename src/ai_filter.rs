use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy)]
pub enum FilterStage {
    Prompt,
    Output,
}

#[derive(Debug, Clone)]
pub struct FilterDecision {
    #[allow(dead_code)]
    pub blocked: bool,
    pub reason: String,
    #[allow(dead_code)]
    pub stage: FilterStage,
    pub text_sha256_hex: String,
}

pub trait ContentFilter: Send + Sync + 'static {
    fn check(&self, stage: FilterStage, text: &str) -> Option<FilterDecision>;
}

fn sha256_hex(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tet-safe-mode:v1");
    h.update([0u8]);
    h.update(text.as_bytes());
    hex::encode(h.finalize())
}

fn normalize(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Baseline: heuristic keyword filter.
/// - Intentionally conservative (operator protection).
/// - Designed to be replaced by ML filters (e.g. Llama Guard) without changing call sites.
#[derive(Default)]
pub struct KeywordHeuristicFilter;

impl KeywordHeuristicFilter {
    fn hit_any<'a>(hay: &str, needles: &'a [&'a str]) -> Option<&'a str> {
        needles.iter().copied().find(|n| hay.contains(*n))
    }
}

impl ContentFilter for KeywordHeuristicFilter {
    fn check(&self, stage: FilterStage, text: &str) -> Option<FilterDecision> {
        let t = normalize(text);
        if t.trim().is_empty() {
            return None;
        }

        // NOTE: This is a baseline. Expect false positives. Phase 4.2 will add ML-based policy.
        const ILLEGAL: &[&str] = &[
            "how to make a bomb",
            "build a bomb",
            "make a bomb",
            "explosive",
            "detonator",
            "pipe bomb",
            "terrorist",
            "isis",
            "al qaeda",
            "child porn",
            "csam",
            "kill yourself",
            "suicide",
            "buy cocaine",
            "buy meth",
            "make meth",
            "heroin",
        ];

        const WEAPONS: &[&str] = &[
            "ghost gun",
            "homemade gun",
            "3d print a gun",
            "3d-printed gun",
            "untraceable firearm",
            "silencer",
            "suppressor",
        ];

        const MALWARE: &[&str] = &[
            "ransomware",
            "keylogger",
            "steal passwords",
            "credential stealer",
            "malware",
            "phishing kit",
            "ddos",
            "botnet",
            "exploit",
            "sql injection",
            "xss payload",
        ];

        if let Some(hit) = Self::hit_any(&t, ILLEGAL) {
            return Some(FilterDecision {
                blocked: true,
                reason: format!("illegal_content_keyword:{hit}"),
                stage,
                text_sha256_hex: sha256_hex(text),
            });
        }
        if let Some(hit) = Self::hit_any(&t, WEAPONS) {
            return Some(FilterDecision {
                blocked: true,
                reason: format!("weapon_keyword:{hit}"),
                stage,
                text_sha256_hex: sha256_hex(text),
            });
        }
        if let Some(hit) = Self::hit_any(&t, MALWARE) {
            return Some(FilterDecision {
                blocked: true,
                reason: format!("malware_keyword:{hit}"),
                stage,
                text_sha256_hex: sha256_hex(text),
            });
        }
        None
    }
}

pub fn default_filter() -> impl ContentFilter {
    KeywordHeuristicFilter
}
