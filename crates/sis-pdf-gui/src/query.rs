use crate::analysis::AnalysisResult;

/// Parsed query command.
#[derive(Debug, PartialEq)]
pub enum Query {
    // Structural metadata
    Pages,
    Objects,
    FileSize,
    Version,
    Encrypted,

    // Document info
    Creator,
    Producer,
    Title,
    Author,
    Created,
    Modified,

    // Findings
    Findings,
    FindingsCount,
    FindingsBySeverity(String),
    FindingsByKind(String),

    // Chains
    Chains,
    ChainsCount,

    // Object queries
    Object { obj: u32, gen: u16 },
    ObjectsList,
    ObjectsWith(String),

    // References
    Ref { obj: u32, gen: u16 },

    // Stream
    Stream { obj: u32, gen: u16 },

    // Filtered finding queries
    JavaScript,
    Urls,
    Embedded,

    // XRef
    Xref,
    XrefCount,
    XrefSections,

    // GUI navigation
    Goto { obj: u32, gen: u16 },

    // Graph commands (M3)
    GraphFocus { obj: u32, gen: u16 },
    HighlightChain { index: usize },

    // Help
    Help,
}

/// Output from executing a query.
#[derive(Debug)]
pub enum QueryOutput {
    Text(String),
    Table { headers: Vec<String>, rows: Vec<Vec<String>> },
    Navigation { obj: u32, gen: u16 },
    Error(String),
}

/// Parse a query string into a Query enum.
pub fn parse_query(input: &str) -> Result<Query, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("Empty query".to_string());
    }

    let parts: Vec<&str> = input.splitn(3, ' ').collect();
    let cmd = parts[0].to_lowercase();

    match cmd.as_str() {
        "pages" => Ok(Query::Pages),
        "objects" => Ok(Query::Objects),
        "objects.list" => Ok(Query::ObjectsList),
        "objects.with" => {
            let obj_type = parts.get(1).ok_or("objects.with requires a type argument")?;
            Ok(Query::ObjectsWith(obj_type.to_string()))
        }
        "filesize" => Ok(Query::FileSize),
        "version" => Ok(Query::Version),
        "encrypted" => Ok(Query::Encrypted),

        "creator" => Ok(Query::Creator),
        "producer" => Ok(Query::Producer),
        "title" => Ok(Query::Title),
        "author" => Ok(Query::Author),
        "created" => Ok(Query::Created),
        "modified" => Ok(Query::Modified),

        "findings" => Ok(Query::Findings),
        "findings.count" => Ok(Query::FindingsCount),
        "findings.critical" => Ok(Query::FindingsBySeverity("Critical".to_string())),
        "findings.high" => Ok(Query::FindingsBySeverity("High".to_string())),
        "findings.medium" => Ok(Query::FindingsBySeverity("Medium".to_string())),
        "findings.low" => Ok(Query::FindingsBySeverity("Low".to_string())),
        "findings.info" => Ok(Query::FindingsBySeverity("Info".to_string())),
        "findings.kind" => {
            let kind = parts.get(1).ok_or("findings.kind requires a kind argument")?;
            Ok(Query::FindingsByKind(kind.to_string()))
        }

        "chains" => Ok(Query::Chains),
        "chains.count" => Ok(Query::ChainsCount),

        "object" | "obj" => {
            let obj_num = parts
                .get(1)
                .ok_or("object requires an object number")?
                .parse::<u32>()
                .map_err(|_| "Invalid object number")?;
            let gen = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            Ok(Query::Object { obj: obj_num, gen })
        }

        "ref" => {
            let obj_num = parts
                .get(1)
                .ok_or("ref requires an object number")?
                .parse::<u32>()
                .map_err(|_| "Invalid object number")?;
            let gen = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            Ok(Query::Ref { obj: obj_num, gen })
        }

        "stream" => {
            let obj_num = parts
                .get(1)
                .ok_or("stream requires an object number")?
                .parse::<u32>()
                .map_err(|_| "Invalid object number")?;
            let gen = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            Ok(Query::Stream { obj: obj_num, gen })
        }

        "javascript" | "js" => Ok(Query::JavaScript),
        "urls" => Ok(Query::Urls),
        "embedded" => Ok(Query::Embedded),

        "xref" => Ok(Query::Xref),
        "xref.count" => Ok(Query::XrefCount),
        "xref.sections" => Ok(Query::XrefSections),

        "goto" | "go" => {
            let obj_num = parts
                .get(1)
                .ok_or("goto requires an object number")?
                .parse::<u32>()
                .map_err(|_| "Invalid object number")?;
            let gen = parts.get(2).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            Ok(Query::Goto { obj: obj_num, gen })
        }

        "graph" => {
            let sub = parts.get(1).map(|s| s.to_lowercase());
            match sub.as_deref() {
                Some("focus") => {
                    // "graph focus <num> [gen]" — third part may be "num gen" or just "num"
                    let rest = parts.get(2).ok_or("graph focus requires an object number")?;
                    let rest_parts: Vec<&str> = rest.split_whitespace().collect();
                    let obj_num = rest_parts
                        .first()
                        .ok_or("graph focus requires an object number")?
                        .parse::<u32>()
                        .map_err(|_| "Invalid object number")?;
                    let gen = rest_parts.get(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
                    Ok(Query::GraphFocus { obj: obj_num, gen })
                }
                _ => Err("Unknown graph subcommand. Try: graph focus <num> [gen]".to_string()),
            }
        }

        "highlight" => {
            let arg = parts.get(1).ok_or("highlight requires an argument like chain:<index>")?;
            if let Some(rest) = arg.strip_prefix("chain:") {
                let index = rest.parse::<usize>().map_err(|_| "Invalid chain index")?;
                Ok(Query::HighlightChain { index })
            } else {
                Err("Unknown highlight target. Try: highlight chain:<index>".to_string())
            }
        }

        "help" | "?" => Ok(Query::Help),

        _ => Err(format!("Unknown query: {}", cmd)),
    }
}

/// Execute a parsed query against the analysis result.
pub fn execute_query(query: &Query, result: &AnalysisResult) -> QueryOutput {
    match query {
        Query::Pages => {
            let page_count =
                result.object_data.objects.iter().filter(|o| o.obj_type == "page").count();
            QueryOutput::Text(format!("{} pages", page_count))
        }

        Query::Objects => {
            let count = result.object_data.objects.len();
            QueryOutput::Text(format!("{} objects", count))
        }

        Query::ObjectsList => {
            let headers =
                vec!["Obj".to_string(), "Gen".to_string(), "Type".to_string(), "Roles".to_string()];
            let rows: Vec<Vec<String>> = result
                .object_data
                .objects
                .iter()
                .map(|o| {
                    vec![
                        o.obj.to_string(),
                        o.gen.to_string(),
                        o.obj_type.clone(),
                        o.roles.join(", "),
                    ]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::ObjectsWith(obj_type) => {
            let lower = obj_type.to_lowercase();
            let headers =
                vec!["Obj".to_string(), "Gen".to_string(), "Type".to_string(), "Roles".to_string()];
            let rows: Vec<Vec<String>> = result
                .object_data
                .objects
                .iter()
                .filter(|o| o.obj_type.to_lowercase().contains(&lower))
                .map(|o| {
                    vec![
                        o.obj.to_string(),
                        o.gen.to_string(),
                        o.obj_type.clone(),
                        o.roles.join(", "),
                    ]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::FileSize => QueryOutput::Text(format!("{} bytes", result.file_size)),

        Query::Version => {
            // Extract PDF version from the raw bytes header
            let version = if result.bytes.len() >= 8 && result.bytes.starts_with(b"%PDF-") {
                let end = result.bytes[5..].iter().position(|&b| b == b'\n' || b == b'\r');
                let end = end.map(|e| 5 + e).unwrap_or(8.min(result.bytes.len()));
                String::from_utf8_lossy(&result.bytes[5..end]).to_string()
            } else {
                "unknown".to_string()
            };
            QueryOutput::Text(format!("PDF {}", version))
        }

        Query::Encrypted => {
            let encrypted = result
                .object_data
                .objects
                .iter()
                .any(|o| o.dict_entries.iter().any(|(k, _)| k == "/Encrypt"));
            QueryOutput::Text(if encrypted { "yes" } else { "no" }.to_string())
        }

        Query::Creator
        | Query::Producer
        | Query::Title
        | Query::Author
        | Query::Created
        | Query::Modified => execute_info_query(query, result),

        Query::Findings => {
            let headers = vec![
                "ID".to_string(),
                "Severity".to_string(),
                "Kind".to_string(),
                "Title".to_string(),
            ];
            let rows: Vec<Vec<String>> = result
                .report
                .findings
                .iter()
                .map(|f| {
                    vec![f.id.clone(), format!("{:?}", f.severity), f.kind.clone(), f.title.clone()]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::FindingsCount => QueryOutput::Text(format!("{}", result.report.findings.len())),

        Query::FindingsBySeverity(sev) => {
            let sev_lower = sev.to_lowercase();
            let headers = vec![
                "ID".to_string(),
                "Severity".to_string(),
                "Kind".to_string(),
                "Title".to_string(),
            ];
            let rows: Vec<Vec<String>> = result
                .report
                .findings
                .iter()
                .filter(|f| format!("{:?}", f.severity).to_lowercase() == sev_lower)
                .map(|f| {
                    vec![f.id.clone(), format!("{:?}", f.severity), f.kind.clone(), f.title.clone()]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::FindingsByKind(kind) => {
            let kind_lower = kind.to_lowercase();
            let headers = vec![
                "ID".to_string(),
                "Severity".to_string(),
                "Kind".to_string(),
                "Title".to_string(),
            ];
            let rows: Vec<Vec<String>> = result
                .report
                .findings
                .iter()
                .filter(|f| f.kind.to_lowercase().contains(&kind_lower))
                .map(|f| {
                    vec![f.id.clone(), format!("{:?}", f.severity), f.kind.clone(), f.title.clone()]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::Chains => {
            let headers = vec![
                "Index".to_string(),
                "Score".to_string(),
                "Path".to_string(),
                "Trigger".to_string(),
            ];
            let rows: Vec<Vec<String>> = result
                .report
                .chains
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    vec![
                        format!("{}", i + 1),
                        format!("{:.2}", c.score),
                        c.path.clone(),
                        c.trigger.clone().unwrap_or_default(),
                    ]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::ChainsCount => QueryOutput::Text(format!("{}", result.report.chains.len())),

        Query::Object { obj, gen } => {
            if let Some(&idx) = result.object_data.index.get(&(*obj, *gen)) {
                let o = &result.object_data.objects[idx];
                let mut lines =
                    vec![format!("Object {} {} R", o.obj, o.gen), format!("Type: {}", o.obj_type)];
                if !o.roles.is_empty() {
                    lines.push(format!("Roles: {}", o.roles.join(", ")));
                }
                if o.has_stream {
                    lines.push(format!(
                        "Stream: {} bytes, filters: {}",
                        o.stream_length.unwrap_or(0),
                        if o.stream_filters.is_empty() {
                            "none".to_string()
                        } else {
                            o.stream_filters.join(", ")
                        }
                    ));
                }
                if !o.dict_entries.is_empty() {
                    lines.push(format!("Dictionary: {} entries", o.dict_entries.len()));
                    for (k, v) in &o.dict_entries {
                        let v_display =
                            if v.len() > 80 { format!("{}...", &v[..80]) } else { v.clone() };
                        lines.push(format!("  {} = {}", k, v_display));
                    }
                }
                if !o.references_from.is_empty() {
                    let refs: Vec<String> =
                        o.references_from.iter().map(|(r, g)| format!("{} {} R", r, g)).collect();
                    lines.push(format!("References: {}", refs.join(", ")));
                }
                QueryOutput::Text(lines.join("\n"))
            } else {
                QueryOutput::Error(format!("Object {} {} not found", obj, gen))
            }
        }

        Query::Ref { obj, gen } => {
            if let Some(&idx) = result.object_data.index.get(&(*obj, *gen)) {
                let o = &result.object_data.objects[idx];
                let mut lines = vec![format!("References for object {} {} R:", o.obj, o.gen)];
                if !o.references_from.is_empty() {
                    lines.push("  From:".to_string());
                    for (r, g) in &o.references_from {
                        lines.push(format!("    {} {} R", r, g));
                    }
                }
                if !o.references_to.is_empty() {
                    lines.push("  To (referenced by):".to_string());
                    for (r, g) in &o.references_to {
                        lines.push(format!("    {} {} R", r, g));
                    }
                }
                if o.references_from.is_empty() && o.references_to.is_empty() {
                    lines.push("  No references".to_string());
                }
                QueryOutput::Text(lines.join("\n"))
            } else {
                QueryOutput::Error(format!("Object {} {} not found", obj, gen))
            }
        }

        Query::Stream { obj, gen } => {
            if let Some(&idx) = result.object_data.index.get(&(*obj, *gen)) {
                let o = &result.object_data.objects[idx];
                if let Some(ref text) = o.stream_text {
                    QueryOutput::Text(text.clone())
                } else if o.stream_raw.is_some() {
                    QueryOutput::Text(format!(
                        "Binary stream ({} bytes). Use hex viewer to inspect.",
                        o.stream_length.unwrap_or(0)
                    ))
                } else if o.has_stream {
                    QueryOutput::Text("Stream could not be decoded".to_string())
                } else {
                    QueryOutput::Error(format!("Object {} {} has no stream", obj, gen))
                }
            } else {
                QueryOutput::Error(format!("Object {} {} not found", obj, gen))
            }
        }

        Query::JavaScript => {
            let headers = vec!["ID".to_string(), "Severity".to_string(), "Title".to_string()];
            let rows: Vec<Vec<String>> = result
                .report
                .findings
                .iter()
                .filter(|f| {
                    f.kind.to_lowercase().contains("javascript")
                        || f.kind.to_lowercase().contains("js_")
                })
                .map(|f| vec![f.id.clone(), format!("{:?}", f.severity), f.title.clone()])
                .collect();
            if rows.is_empty() {
                QueryOutput::Text("No JavaScript findings".to_string())
            } else {
                QueryOutput::Table { headers, rows }
            }
        }

        Query::Urls => {
            let headers = vec!["ID".to_string(), "Severity".to_string(), "Title".to_string()];
            let rows: Vec<Vec<String>> = result
                .report
                .findings
                .iter()
                .filter(|f| {
                    f.kind.to_lowercase().contains("url")
                        || f.kind.to_lowercase().contains("uri")
                        || f.kind.to_lowercase().contains("link")
                })
                .map(|f| vec![f.id.clone(), format!("{:?}", f.severity), f.title.clone()])
                .collect();
            if rows.is_empty() {
                QueryOutput::Text("No URL findings".to_string())
            } else {
                QueryOutput::Table { headers, rows }
            }
        }

        Query::Embedded => {
            let headers = vec!["ID".to_string(), "Severity".to_string(), "Title".to_string()];
            let rows: Vec<Vec<String>> = result
                .report
                .findings
                .iter()
                .filter(|f| {
                    f.kind.to_lowercase().contains("embed")
                        || f.kind.to_lowercase().contains("attachment")
                        || f.kind.to_lowercase().contains("file")
                })
                .map(|f| vec![f.id.clone(), format!("{:?}", f.severity), f.title.clone()])
                .collect();
            if rows.is_empty() {
                QueryOutput::Text("No embedded file findings".to_string())
            } else {
                QueryOutput::Table { headers, rows }
            }
        }

        Query::Xref => {
            let sections = &result.object_data.xref_sections;
            let mut lines = vec![format!("{} xref sections", sections.len())];
            for (i, sec) in sections.iter().enumerate() {
                lines.push(format!("  Section {}: {} at offset {}", i + 1, sec.kind, sec.offset));
            }
            QueryOutput::Text(lines.join("\n"))
        }

        Query::XrefCount => {
            QueryOutput::Text(format!("{}", result.object_data.xref_sections.len()))
        }

        Query::XrefSections => {
            let headers = vec![
                "Index".to_string(),
                "Kind".to_string(),
                "Offset".to_string(),
                "Trailer Size".to_string(),
                "Root".to_string(),
            ];
            let rows: Vec<Vec<String>> = result
                .object_data
                .xref_sections
                .iter()
                .enumerate()
                .map(|(i, sec)| {
                    vec![
                        format!("{}", i + 1),
                        sec.kind.clone(),
                        sec.offset.to_string(),
                        sec.trailer_size.map(|s| s.to_string()).unwrap_or_default(),
                        sec.trailer_root.clone().unwrap_or_default(),
                    ]
                })
                .collect();
            QueryOutput::Table { headers, rows }
        }

        Query::Goto { obj, gen } => QueryOutput::Navigation { obj: *obj, gen: *gen },

        Query::GraphFocus { obj, gen } => {
            if result.object_data.index.contains_key(&(*obj, *gen)) {
                QueryOutput::Text(format!("Graph focus: object {} {}", obj, gen))
            } else {
                QueryOutput::Error(format!("Object {} {} not found", obj, gen))
            }
        }

        Query::HighlightChain { index } => {
            if *index < result.report.chains.len() {
                QueryOutput::Text(format!("Highlighting chain {}", index))
            } else {
                QueryOutput::Error(format!(
                    "Chain index {} out of range (0..{})",
                    index,
                    result.report.chains.len()
                ))
            }
        }

        Query::Help => QueryOutput::Text(
            "Available queries:\n\
                 \n\
                 Metadata: pages, objects, filesize, version, encrypted\n\
                 Document: creator, producer, title, author, created, modified\n\
                 Findings: findings, findings.count, findings.critical/high/medium/low/info\n\
                           findings.kind <kind>\n\
                 Chains:   chains, chains.count\n\
                 Objects:  object <num> [gen], objects.list, objects.with <type>\n\
                 Refs:     ref <num> [gen]\n\
                 Stream:   stream <num> [gen]\n\
                 Filtered: javascript, urls, embedded\n\
                 XRef:     xref, xref.count, xref.sections\n\
                 Navigate: goto <num> [gen]\n\
                 Graph:    graph focus <num> [gen], highlight chain:<index>\n\
                 Help:     help, ?"
                .to_string(),
        ),
    }
}

/// Execute a document info query (creator, producer, etc.).
fn execute_info_query(query: &Query, result: &AnalysisResult) -> QueryOutput {
    let key = match query {
        Query::Creator => "/Creator",
        Query::Producer => "/Producer",
        Query::Title => "/Title",
        Query::Author => "/Author",
        Query::Created => "/CreationDate",
        Query::Modified => "/ModDate",
        _ => return QueryOutput::Error("Not an info query".to_string()),
    };

    // Find info dict via catalog
    let info_id = result.object_data.objects.iter().find_map(|o| {
        if o.obj_type == "catalog" {
            o.dict_entries.iter().find(|(k, _)| k == "/Info").and_then(|(_, v)| parse_obj_ref(v))
        } else {
            None
        }
    });

    if let Some(id) = info_id {
        if let Some(&idx) = result.object_data.index.get(&id) {
            let obj = &result.object_data.objects[idx];
            if let Some(val) = obj.dict_entries.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
                return QueryOutput::Text(val.clone());
            }
        }
    }

    QueryOutput::Text("not available".to_string())
}

fn parse_obj_ref(s: &str) -> Option<(u32, u16)> {
    let parts: Vec<&str> = s.trim().split_whitespace().collect();
    if parts.len() >= 2 {
        let obj = parts[0].parse::<u32>().ok()?;
        let gen = parts[1].parse::<u16>().ok()?;
        Some((obj, gen))
    } else {
        None
    }
}

/// List of all query names for autocomplete.
pub fn query_names() -> &'static [&'static str] {
    &[
        "pages",
        "objects",
        "objects.list",
        "objects.with",
        "filesize",
        "version",
        "encrypted",
        "creator",
        "producer",
        "title",
        "author",
        "created",
        "modified",
        "findings",
        "findings.count",
        "findings.critical",
        "findings.high",
        "findings.medium",
        "findings.low",
        "findings.info",
        "findings.kind",
        "chains",
        "chains.count",
        "object",
        "obj",
        "ref",
        "stream",
        "javascript",
        "js",
        "urls",
        "embedded",
        "xref",
        "xref.count",
        "xref.sections",
        "goto",
        "go",
        "graph",
        "graph focus",
        "highlight",
        "help",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_queries() {
        assert_eq!(parse_query("pages").unwrap(), Query::Pages);
        assert_eq!(parse_query("objects").unwrap(), Query::Objects);
        assert_eq!(parse_query("filesize").unwrap(), Query::FileSize);
        assert_eq!(parse_query("version").unwrap(), Query::Version);
        assert_eq!(parse_query("encrypted").unwrap(), Query::Encrypted);
        assert_eq!(parse_query("creator").unwrap(), Query::Creator);
        assert_eq!(parse_query("findings").unwrap(), Query::Findings);
        assert_eq!(parse_query("findings.count").unwrap(), Query::FindingsCount);
        assert_eq!(parse_query("chains").unwrap(), Query::Chains);
        assert_eq!(parse_query("chains.count").unwrap(), Query::ChainsCount);
        assert_eq!(parse_query("help").unwrap(), Query::Help);
    }

    #[test]
    fn parse_parametric_queries() {
        assert_eq!(parse_query("object 1").unwrap(), Query::Object { obj: 1, gen: 0 });
        assert_eq!(parse_query("object 5 0").unwrap(), Query::Object { obj: 5, gen: 0 });
        assert_eq!(parse_query("obj 8").unwrap(), Query::Object { obj: 8, gen: 0 });
        assert_eq!(parse_query("ref 5 0").unwrap(), Query::Ref { obj: 5, gen: 0 });
        assert_eq!(parse_query("stream 8").unwrap(), Query::Stream { obj: 8, gen: 0 });
        assert_eq!(parse_query("goto 3").unwrap(), Query::Goto { obj: 3, gen: 0 });
        assert_eq!(parse_query("goto 3 1").unwrap(), Query::Goto { obj: 3, gen: 1 });
    }

    #[test]
    fn parse_severity_filters() {
        assert_eq!(
            parse_query("findings.critical").unwrap(),
            Query::FindingsBySeverity("Critical".to_string())
        );
        assert_eq!(
            parse_query("findings.high").unwrap(),
            Query::FindingsBySeverity("High".to_string())
        );
    }

    #[test]
    fn parse_findings_kind() {
        assert_eq!(
            parse_query("findings.kind javascript").unwrap(),
            Query::FindingsByKind("javascript".to_string())
        );
    }

    #[test]
    fn parse_unknown_query() {
        assert!(parse_query("foobar").is_err());
    }

    #[test]
    fn parse_empty_query() {
        assert!(parse_query("").is_err());
        assert!(parse_query("   ").is_err());
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(parse_query("PAGES").unwrap(), Query::Pages);
        assert_eq!(parse_query("Objects").unwrap(), Query::Objects);
    }

    #[test]
    fn parse_graph_focus() {
        assert_eq!(parse_query("graph focus 5").unwrap(), Query::GraphFocus { obj: 5, gen: 0 });
        assert_eq!(parse_query("graph focus 5 1").unwrap(), Query::GraphFocus { obj: 5, gen: 1 });
    }

    #[test]
    fn parse_highlight_chain() {
        assert_eq!(parse_query("highlight chain:0").unwrap(), Query::HighlightChain { index: 0 });
        assert_eq!(parse_query("highlight chain:3").unwrap(), Query::HighlightChain { index: 3 });
    }

    #[test]
    fn parse_graph_unknown_subcommand() {
        assert!(parse_query("graph unknown").is_err());
    }

    #[test]
    fn parse_highlight_invalid() {
        assert!(parse_query("highlight foo").is_err());
    }
}
