use super::{QueryResult, ScalarValue};
use serde_json::Value;
use std::fmt::Write;

const TABLE_PRIORITIES: &[&str] = &[
    "kind",
    "severity",
    "impact",
    "confidence",
    "title",
    "name",
    "label",
    "path",
    "objects",
    "reference",
    "action",
];

pub fn format_readable_result(result: &QueryResult, compact: bool) -> String {
    match result {
        QueryResult::Scalar(ScalarValue::String(s)) => s.clone(),
        QueryResult::Scalar(ScalarValue::Number(n)) => n.to_string(),
        QueryResult::Scalar(ScalarValue::Boolean(b)) => {
            if compact {
                if *b { "true" } else { "false" }.to_string()
            } else if *b {
                "yes".to_string()
            } else {
                "no".to_string()
            }
        }
        QueryResult::List(items) => format_list(items),
        QueryResult::Structure(value) => format_structure(value),
        QueryResult::Error(err) => err.message.clone(),
    }
}

fn format_list(items: &[String]) -> String {
    if items.is_empty() {
        return "(no entries)".into();
    }
    if let Some(table) = build_colon_table(items) {
        return table;
    }
    let mut output = String::new();
    for (idx, item) in items.iter().enumerate() {
        writeln!(output, "{:>2}. {}", idx + 1, item).ok();
    }
    output.trim_end().to_string()
}

fn build_colon_table(items: &[String]) -> Option<String> {
    let mut rows = Vec::new();
    for line in items.iter() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim();
            let value = line[idx + 1..].trim();
            if key.is_empty() {
                return None;
            }
            rows.push((key.to_string(), value.to_string()));
        } else {
            return None;
        }
    }
    if rows.is_empty() {
        return None;
    }

    let width_key =
        rows.iter().map(|(k, _)| k.len()).max().unwrap_or_else(|| "Field".len()).max("Field".len());
    let width_value = rows
        .iter()
        .map(|(_, v)| v.len())
        .max()
        .unwrap_or_else(|| "Details".len())
        .max("Details".len());

    let mut table = String::new();
    writeln!(
        table,
        "{:<width_key$} | {:<width_value$}",
        "Field",
        "Details",
        width_key = width_key,
        width_value = width_value
    )
    .ok();
    writeln!(
        table,
        "{:-<width_key$}-+-{:-<width_value$}",
        "",
        "",
        width_key = width_key,
        width_value = width_value
    )
    .ok();
    for (key, value) in rows {
        writeln!(table, "{:<width_key$} | {value}", key, width_key = width_key).ok();
    }
    Some(table.trim_end().to_string())
}

fn format_structure(value: &Value) -> String {
    match value {
        Value::Array(arr) if arr.iter().all(|item| item.is_object()) => {
            if let Some(table) = build_object_table(arr) {
                return table;
            }
            render_array(arr, 0)
        }
        Value::Array(arr) => render_array(arr, 0),
        Value::Object(map) => render_object(map, 0),
        other => value_summary(other),
    }
}

fn build_object_table(entries: &[Value]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let mut columns = Vec::new();
    for key in TABLE_PRIORITIES {
        if columns.len() >= 5 {
            break;
        }
        if entries.iter().any(|entry| entry.get(*key).is_some()) {
            columns.push((*key).to_string());
        }
    }
    if columns.is_empty() {
        if let Some(first) = entries.first() {
            if let Some(map) = first.as_object() {
                for key in map.keys().take(5) {
                    columns.push(key.clone());
                }
            }
        }
    }
    if columns.is_empty() {
        return None;
    }

    let mut widths = columns.iter().map(|col| col.len()).collect::<Vec<_>>();
    let mut rows = Vec::new();
    for entry in entries.iter() {
        let object = entry.as_object()?;
        let mut row = Vec::new();
        for (idx, col) in columns.iter().enumerate() {
            let text = object
                .get(col)
                .map(|value| value_summary_for_column(col, value))
                .unwrap_or_else(|| "-".into());
            widths[idx] = widths[idx].max(text.len());
            row.push(text);
        }
        rows.push(row);
    }

    let mut table = String::new();
    for (idx, col) in columns.iter().enumerate() {
        if idx > 0 {
            table.push_str(" | ");
        }
        write!(table, "{col:<width$}", width = widths[idx]).ok();
    }
    table.push('\n');
    for (idx, width) in widths.iter().enumerate() {
        if idx > 0 {
            table.push_str("-+-");
        }
        table.push_str(&"-".repeat(*width));
    }
    table.push('\n');
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            if idx > 0 {
                table.push_str(" | ");
            }
            write!(table, "{cell:<width$}", width = widths[idx]).ok();
        }
        table.push('\n');
    }
    Some(table.trim_end().to_string())
}

fn render_array(arr: &[Value], indent: usize) -> String {
    let mut output = String::new();
    for (idx, value) in arr.iter().enumerate() {
        let indent_str = "  ".repeat(indent);
        writeln!(
            output,
            "{indent}[{idx}] -> {summary}",
            indent = indent_str,
            idx = idx,
            summary = value_summary(value)
        )
        .ok();
        if let Some(map) = value.as_object() {
            output.push_str(&render_object(map, indent + 1));
        } else if let Some(inner) = value.as_array() {
            output.push_str(&render_array(inner, indent + 1));
        }
    }
    output
}

fn render_object(map: &serde_json::Map<String, Value>, indent: usize) -> String {
    let mut output = String::new();
    let indent_str = "  ".repeat(indent);
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (key, value) in entries {
        writeln!(
            output,
            "{indent}{key} -> {summary}",
            indent = indent_str,
            key = key,
            summary = value_summary(value)
        )
        .ok();
        if let Some(child) = value.as_object() {
            output.push_str(&render_object(child, indent + 1));
        } else if let Some(array) = value.as_array() {
            output.push_str(&render_array(array, indent + 1));
        }
    }
    output
}

fn value_summary(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => format!("array({})", arr.len()),
        Value::Object(obj) => format!("object({})", obj.len()),
    }
}

fn value_summary_for_column(column: &str, value: &Value) -> String {
    if column == "objects" {
        if let Value::Array(arr) = value {
            let ids: Vec<_> =
                arr.iter().filter_map(|item| item.as_str()).map(format_object_ref).collect();
            if !ids.is_empty() {
                return ids.join(" ");
            }
        }
        if let Value::String(s) = value {
            return format_object_ref(s);
        }
    }
    value_summary(value)
}

fn format_object_ref(input: &str) -> String {
    if let Some((obj, gen)) = parse_obj_gen(input) {
        return format!("[{} {}]", obj, gen);
    }
    format!("[{}]", input.trim())
}

fn parse_obj_gen(input: &str) -> Option<(u32, u16)> {
    let cleaned = input.trim().trim_end_matches("obj").trim_end_matches("R").trim();
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    if tokens.len() >= 2 {
        if let (Ok(obj), Ok(gen)) = (tokens[0].parse::<u32>(), tokens[1].parse::<u16>()) {
            return Some((obj, gen));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn colon_list_table() {
        let lines = vec!["Object 1: /Pages".into(), "Object 2: /Catalog".into()];
        let table = format_list(&lines);
        assert!(table.contains("Object 1"));
        assert!(table.contains("/Catalog"));
    }

    #[test]
    fn object_array_table() {
        let arr = json!([
            {"kind": "embedded", "severity": "High"},
            {"kind": "js", "severity": "Medium"},
        ]);
        let output = format_structure(&arr);
        assert!(output.contains("kind"));
        assert!(output.contains("severity"));
    }

    #[test]
    fn object_tree() {
        let value = json!({
            "catalog": {"pages": 4, "open_action": "object 13 0"},
            "metadata": "present",
        });
        let output = format_structure(&value);
        assert!(output.contains("catalog"));
        assert!(output.contains("pages"));
        assert!(output.contains("metadata"));
    }

    #[test]
    fn object_column_arrays_show_ids() {
        let arr = json!([
            {"kind": "open_action_present", "objects": ["2 0"]},
            {"kind": "js_present", "objects": ["6 0", "7 0"]}
        ]);
        let table = build_object_table(arr.as_array().unwrap()).unwrap();
        assert!(table.contains("[2 0]"));
        assert!(table.contains("[6 0] [7 0]"));
    }
}
