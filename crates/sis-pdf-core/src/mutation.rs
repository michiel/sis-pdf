#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MutatedPDF {
    pub bytes: Vec<u8>,
    pub note: String,
}

pub struct MutationTester;

impl MutationTester {
    pub fn mutate_malware(&self, pdf: &[u8]) -> Vec<MutatedPDF> {
        let mut out = Vec::new();
        let mut appended = pdf.to_vec();
        appended.extend_from_slice(b"\n%mutation\n");
        out.push(MutatedPDF { bytes: appended, note: "append_comment".into() });

        let mut dup_eof = pdf.to_vec();
        dup_eof.extend_from_slice(b"\n%%EOF\n");
        out.push(MutatedPDF { bytes: dup_eof, note: "duplicate_eof".into() });

        let mut insert_null = pdf.to_vec();
        insert_null.push(0);
        out.push(MutatedPDF { bytes: insert_null, note: "append_null".into() });
        out
    }

    pub fn test_detection_coverage(
        &self,
        original: &[u8],
        mutants: &[MutatedPDF],
    ) -> (usize, usize) {
        let total = mutants.len();
        let unchanged = mutants.iter().filter(|m| m.bytes.starts_with(original)).count();
        (total, unchanged)
    }
}
