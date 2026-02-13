use anyhow::Result;
use lopdf::{Document, Object};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Cursor;

const MAX_RECORDED_REMOVALS: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripOptions {
    pub strip_actions: bool,
    pub strip_javascript: bool,
    pub strip_xfa: bool,
    pub strip_rich_media: bool,
    pub strip_embedded_files: bool,
}

impl Default for StripOptions {
    fn default() -> Self {
        Self {
            strip_actions: true,
            strip_javascript: true,
            strip_xfa: true,
            strip_rich_media: true,
            strip_embedded_files: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripRecord {
    pub object_ref: String,
    pub path: String,
    pub key: String,
    pub class: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripReport {
    pub output_degraded: bool,
    pub removed_total: usize,
    pub removed_by_class: BTreeMap<String, usize>,
    pub removals_truncated: bool,
    pub removals: Vec<StripRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripResult {
    pub sanitised_bytes: Vec<u8>,
    pub report: StripReport,
}

#[derive(Debug, Default)]
struct StripStats {
    removed_total: usize,
    removed_by_class: BTreeMap<String, usize>,
    removals: Vec<StripRecord>,
    removals_truncated: bool,
}

pub fn strip_active_content(input: &[u8], options: &StripOptions) -> Result<StripResult> {
    let mut doc = Document::load_from(Cursor::new(input))?;
    let mut stats = StripStats::default();

    let object_ids: Vec<(u32, u16)> = doc.objects.keys().copied().collect();
    for object_id in object_ids {
        if let Some(object) = doc.objects.get_mut(&object_id) {
            sanitise_object(
                object,
                options,
                &mut stats,
                &format!("{} {}", object_id.0, object_id.1),
                "root",
            );
        }
    }

    let mut sanitised_bytes = Vec::new();
    doc.save_to(&mut sanitised_bytes)?;

    Ok(StripResult {
        sanitised_bytes,
        report: StripReport {
            output_degraded: true,
            removed_total: stats.removed_total,
            removed_by_class: stats.removed_by_class,
            removals_truncated: stats.removals_truncated,
            removals: stats.removals,
        },
    })
}

fn sanitise_object(
    object: &mut Object,
    options: &StripOptions,
    stats: &mut StripStats,
    object_ref: &str,
    path: &str,
) {
    match object {
        Object::Array(items) => {
            for (idx, item) in items.iter_mut().enumerate() {
                let child_path = format!("{path}[{idx}]");
                sanitise_object(item, options, stats, object_ref, &child_path);
            }
        }
        Object::Dictionary(dict) => {
            sanitise_dictionary(dict, options, stats, object_ref, path);
        }
        Object::Stream(stream) => {
            let dict_path = format!("{path}.stream.dict");
            sanitise_dictionary(&mut stream.dict, options, stats, object_ref, &dict_path);
        }
        _ => {}
    }
}

fn sanitise_dictionary(
    dict: &mut lopdf::Dictionary,
    options: &StripOptions,
    stats: &mut StripStats,
    object_ref: &str,
    path: &str,
) {
    for rule in strip_rules(options) {
        if dict.remove(rule.key).is_some() {
            record_removal(stats, object_ref, path, rule.key, rule.class, rule.note);
        }
    }

    let keys: Vec<Vec<u8>> = dict.iter().map(|(key, _)| key.to_vec()).collect();
    for key in keys {
        if let Ok(value) = dict.get_mut(&key) {
            let key_name = String::from_utf8_lossy(&key).to_string();
            let child_path = format!("{path}/{}", key_name);
            sanitise_object(value, options, stats, object_ref, &child_path);
        }
    }
}

fn record_removal(
    stats: &mut StripStats,
    object_ref: &str,
    path: &str,
    key: &[u8],
    class: &'static str,
    note: &'static str,
) {
    stats.removed_total += 1;
    *stats.removed_by_class.entry(class.to_string()).or_insert(0) += 1;
    if stats.removals.len() >= MAX_RECORDED_REMOVALS {
        stats.removals_truncated = true;
        return;
    }
    stats.removals.push(StripRecord {
        object_ref: object_ref.to_string(),
        path: path.to_string(),
        key: format!("/{}", String::from_utf8_lossy(key)),
        class: class.to_string(),
        note: note.to_string(),
    });
}

struct StripRule {
    key: &'static [u8],
    class: &'static str,
    note: &'static str,
}

fn strip_rules(options: &StripOptions) -> Vec<StripRule> {
    let mut rules = Vec::new();
    if options.strip_actions {
        rules.extend([
            StripRule { key: b"A", class: "action", note: "Interactive action removed" },
            StripRule { key: b"AA", class: "action", note: "Additional action removed" },
            StripRule {
                key: b"OpenAction",
                class: "action",
                note: "Automatic open action removed",
            },
            StripRule { key: b"Next", class: "action", note: "Action chaining removed" },
        ]);
    }
    if options.strip_javascript {
        rules.extend([
            StripRule { key: b"JS", class: "javascript", note: "JavaScript payload removed" },
            StripRule {
                key: b"JavaScript",
                class: "javascript",
                note: "JavaScript name-tree entry removed",
            },
        ]);
    }
    if options.strip_xfa {
        rules.push(StripRule { key: b"XFA", class: "xfa", note: "XFA payload removed" });
    }
    if options.strip_rich_media {
        rules.extend([
            StripRule {
                key: b"RichMedia",
                class: "rich_media",
                note: "Rich media payload removed",
            },
            StripRule {
                key: b"RichMediaSettings",
                class: "rich_media",
                note: "Rich media settings removed",
            },
            StripRule {
                key: b"RichMediaContent",
                class: "rich_media",
                note: "Rich media content removed",
            },
        ]);
    }
    if options.strip_embedded_files {
        rules.extend([
            StripRule {
                key: b"EmbeddedFiles",
                class: "embedded_file",
                note: "Embedded file tree removed",
            },
            StripRule { key: b"EF", class: "embedded_file", note: "Embedded file pointer removed" },
            StripRule { key: b"RF", class: "embedded_file", note: "Related file pointer removed" },
        ]);
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Object, Stream};
    use std::io::Cursor;

    fn build_active_document_bytes() -> Vec<u8> {
        let mut doc = Document::with_version("1.7");
        let root_id = doc.new_object_id();
        let action_id = doc.new_object_id();
        let js_name_tree_id = doc.new_object_id();
        let file_spec_id = doc.new_object_id();
        let embedded_files_id = doc.new_object_id();
        let names_id = doc.new_object_id();
        let acroform_id = doc.new_object_id();
        let rich_media_id = doc.new_object_id();

        doc.objects.insert(
            root_id,
            Object::Dictionary(dictionary! {
                "Type" => "Catalog",
                "OpenAction" => Object::Reference(action_id),
                "Names" => Object::Reference(names_id),
                "AcroForm" => Object::Reference(acroform_id),
                "RichMedia" => Object::Reference(rich_media_id),
            }),
        );
        doc.objects.insert(
            action_id,
            Object::Dictionary(dictionary! {
                "S" => "JavaScript",
                "JS" => Object::string_literal("app.alert('x');"),
                "Next" => Object::Array(vec![Object::Reference(js_name_tree_id)]),
            }),
        );
        doc.objects.insert(
            js_name_tree_id,
            Object::Dictionary(dictionary! {
                "S" => "JavaScript",
                "JS" => Object::string_literal("app.alert('y');"),
            }),
        );
        doc.objects.insert(
            file_spec_id,
            Object::Dictionary(dictionary! {
                "Type" => "Filespec",
                "F" => Object::string_literal("hello.ps1"),
                "EF" => Object::Dictionary(dictionary! { "F" => Object::Reference(js_name_tree_id) }),
            }),
        );
        doc.objects.insert(
            embedded_files_id,
            Object::Dictionary(dictionary! {
                "Names" => Object::Array(vec![Object::string_literal("hello.ps1"), Object::Reference(file_spec_id)]),
            }),
        );
        doc.objects.insert(
            names_id,
            Object::Dictionary(dictionary! {
                "JavaScript" => Object::Reference(js_name_tree_id),
                "EmbeddedFiles" => Object::Reference(embedded_files_id),
            }),
        );
        doc.objects.insert(
            acroform_id,
            Object::Dictionary(dictionary! {
                "XFA" => Object::Reference(js_name_tree_id),
            }),
        );
        doc.objects.insert(
            rich_media_id,
            Object::Stream(Stream::new(
                dictionary! { "RichMediaSettings" => Object::Null },
                vec![1, 2, 3],
            )),
        );
        doc.trailer.set("Root", Object::Reference(root_id));
        let mut bytes = Vec::new();
        let save_result = doc.save_to(&mut bytes);
        assert!(save_result.is_ok(), "failed to build fixture: {save_result:?}");
        bytes
    }

    #[test]
    fn strip_active_content_removes_dangerous_entries() {
        let input = build_active_document_bytes();
        let result = strip_active_content(&input, &StripOptions::default()).expect("strip result");
        let stripped =
            Document::load_from(Cursor::new(&result.sanitised_bytes)).expect("load stripped");

        let root_ref = stripped
            .trailer
            .get(b"Root")
            .expect("root in trailer")
            .as_reference()
            .expect("root ref");
        let root =
            stripped.get_object(root_ref).expect("root object").as_dict().expect("root dict");
        assert!(!root.has(b"OpenAction"), "OpenAction should be removed");
        assert!(!root.has(b"RichMedia"), "RichMedia should be removed");

        let mut has_js_key = false;
        let mut has_next_key = false;
        let mut has_javascript_tree = false;
        let mut has_embedded_files_tree = false;
        for object in stripped.objects.values() {
            if let Ok(dict) = object.as_dict() {
                has_js_key |= dict.has(b"JS");
                has_next_key |= dict.has(b"Next");
                has_javascript_tree |= dict.has(b"JavaScript");
                has_embedded_files_tree |= dict.has(b"EmbeddedFiles");
            }
        }
        assert!(!has_js_key, "JS payload should be removed");
        assert!(!has_next_key, "Next action chain should be removed");
        assert!(!has_javascript_tree, "JavaScript name tree should be removed");
        assert!(!has_embedded_files_tree, "EmbeddedFiles name tree should be removed");
    }

    #[test]
    fn strip_active_content_report_has_expected_classes() {
        let input = build_active_document_bytes();
        let result = strip_active_content(&input, &StripOptions::default()).expect("strip result");

        assert!(result.report.output_degraded, "output should be marked degraded");
        assert!(result.report.removed_total > 0, "removals should be tracked");
        for class in ["action", "javascript", "xfa", "rich_media", "embedded_file"] {
            assert!(
                result.report.removed_by_class.contains_key(class),
                "expected class {class} in report"
            );
        }
    }
}
