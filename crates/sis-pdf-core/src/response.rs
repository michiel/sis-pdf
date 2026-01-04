use crate::behavior::ThreatPattern;
use crate::yara::YaraRule;

pub struct ResponseGenerator;

impl ResponseGenerator {
    pub fn generate_yara_variants(&self, threat: &ThreatPattern) -> Vec<YaraRule> {
        let mut rules = Vec::new();
        let tags = threat.kinds.clone();
        let strings = threat
            .kinds
            .iter()
            .enumerate()
            .map(|(i, k)| (format!("$k{}", i + 1), crate::yara::escape_yara_string(k)))
            .collect::<Vec<_>>();
        rules.push(YaraRule {
            name: format!("SISPDF_RESP_{}", threat.id.replace(':', "_")),
            tags,
            strings,
            condition: "any of them".into(),
            namespace: Some("sis_pdf".into()),
            meta: vec![("summary".into(), threat.summary.clone())],
        });
        rules
    }

    pub fn create_vaccine_pdf(&self, _pattern: &ThreatPattern) -> Option<Vec<u8>> {
        None
    }
}
