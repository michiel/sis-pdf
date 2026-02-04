use std::path::Path;

use anyhow::{anyhow, Result};
use tokenizers::models::bpe::BPE;
use tokenizers::Tokenizer;

pub struct TokenizerWrapper {
    tokenizer: Tokenizer,
    max_length: usize,
}

pub struct TokenizedBatch {
    pub input_ids: Vec<i64>,
    pub attention_mask: Vec<i64>,
    pub token_type_ids: Vec<i64>,
    pub batch: usize,
    pub seq_len: usize,
}

impl TokenizerWrapper {
    pub fn from_path(path: &Path, max_length: usize) -> Result<Self> {
        let tokenizer = if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if path.file_name().and_then(|s| s.to_str()) == Some("vocab.json") {
                load_bpe_from_vocab(path)?
            } else {
                Tokenizer::from_file(path)
                    .map_err(|e| anyhow!("failed to load tokenizer {}: {}", path.display(), e))?
            }
        } else {
            return Err(anyhow!(
                "unsupported tokenizer path {} (expected tokenizer.json or vocab.json)",
                path.display()
            ));
        };
        Ok(Self { tokenizer, max_length })
    }

    pub fn max_length(&self) -> usize {
        self.max_length
    }

    pub fn encode_batch(&self, texts: &[String]) -> Result<TokenizedBatch> {
        let encodings = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| anyhow!("tokenization failed: {}", e))?;
        let batch = encodings.len();
        let seq_len = self.max_length;
        let mut input_ids = Vec::with_capacity(batch * seq_len);
        let mut attention_mask = Vec::with_capacity(batch * seq_len);
        let mut token_type_ids = Vec::with_capacity(batch * seq_len);

        for encoding in encodings {
            let ids = encoding.get_ids();
            let mask = encoding.get_attention_mask();
            let types = encoding.get_type_ids();
            for i in 0..seq_len {
                let id = *ids.get(i).unwrap_or(&0) as i64;
                let m = *mask.get(i).unwrap_or(&0) as i64;
                let t = *types.get(i).unwrap_or(&0) as i64;
                input_ids.push(id);
                attention_mask.push(m);
                token_type_ids.push(t);
            }
        }

        Ok(TokenizedBatch { input_ids, attention_mask, token_type_ids, batch, seq_len })
    }
}

fn load_bpe_from_vocab(path: &Path) -> Result<Tokenizer> {
    let vocab = path.to_str().ok_or_else(|| anyhow!("tokenizer path is not valid UTF-8"))?;
    let merges =
        path.parent().ok_or_else(|| anyhow!("tokenizer path missing parent"))?.join("merges.txt");
    let merges = merges.to_str().ok_or_else(|| anyhow!("merges path is not valid UTF-8"))?;
    let model = BPE::from_file(vocab, merges)
        .build()
        .map_err(|e| anyhow!("failed to build BPE tokenizer: {}", e))?;
    Ok(Tokenizer::new(model))
}
