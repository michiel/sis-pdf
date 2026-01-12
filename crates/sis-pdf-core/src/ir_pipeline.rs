use std::collections::HashMap;

use sis_pdf_pdf::ir::{IrOptions, PdfIrObject};
use sis_pdf_pdf::ObjectGraph;

use crate::graph_walk::ObjRef;
use crate::org::OrgGraph;

#[derive(Debug, Clone)]
pub struct IrGraphArtifacts {
    pub ir_objects: Vec<PdfIrObject>,
    pub org: OrgGraph,
    pub node_texts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IrGraphSummary {
    pub object_count: usize,
    pub line_count: usize,
    pub action_object_count: usize,
    pub payload_object_count: usize,
    pub edge_count: usize,
}

pub fn build_ir_graph(graph: &ObjectGraph<'_>, opts: &IrOptions) -> IrGraphArtifacts {
    let ir_objects = sis_pdf_pdf::ir::ir_for_graph(&graph.objects, opts);
    let org = OrgGraph::from_object_graph(graph);
    let mut ir_map: HashMap<ObjRef, &PdfIrObject> = HashMap::new();
    for obj in &ir_objects {
        let key = ObjRef {
            obj: obj.obj_ref.0,
            gen: obj.obj_ref.1,
        };
        ir_map.insert(key, obj);
    }
    let mut node_texts = Vec::new();
    for node in &org.nodes {
        if let Some(ir) = ir_map.get(node) {
            node_texts.push(render_ir_text(ir));
        } else {
            node_texts.push("<missing_object>".into());
        }
    }
    IrGraphArtifacts {
        ir_objects,
        org,
        node_texts,
    }
}

pub fn summarize_ir_graph(ir: &IrGraphArtifacts) -> IrGraphSummary {
    let mut line_count = 0usize;
    let mut action_object_count = 0usize;
    let mut payload_object_count = 0usize;
    for obj in &ir.ir_objects {
        line_count += obj.lines.len();
        let mut has_action = false;
        let mut has_payload = false;
        for line in &obj.lines {
            if line.path.ends_with("/OpenAction")
                || line.path.ends_with("/AA")
                || line.path.ends_with("/Action")
            {
                has_action = true;
            }
            if line.value_type == "stream" || line.value_type == "str" || line.value_type == "ref" {
                has_payload = true;
            }
            if line.value_type == "name"
                && (line.value == "/JavaScript"
                    || line.value == "/Launch"
                    || line.value == "/URI"
                    || line.value == "/GoToR"
                    || line.value == "/SubmitForm")
            {
                has_payload = true;
            }
        }
        if has_action {
            action_object_count += 1;
        }
        if has_payload {
            payload_object_count += 1;
        }
    }
    let edge_count = ir.org.adjacency.values().map(|v| v.len()).sum::<usize>();
    IrGraphSummary {
        object_count: ir.ir_objects.len(),
        line_count,
        action_object_count,
        payload_object_count,
        edge_count,
    }
}

fn render_ir_text(obj: &PdfIrObject) -> String {
    let mut out = String::new();
    for (idx, line) in obj.lines.iter().enumerate() {
        if !out.is_empty() {
            out.push_str(" ; ");
        }
        out.push_str("path=");
        out.push_str(&line.path);
        out.push('\t');
        out.push_str("value_type=");
        out.push_str(&line.value_type);
        out.push('\t');
        out.push_str("value=");
        out.push_str(&line.value);
        out.push('\t');
        out.push_str("obj=");
        out.push_str(&format!("{} {}", line.obj_ref.0, line.obj_ref.1));
        out.push('\t');
        out.push_str("line_index=");
        out.push_str(&idx.to_string());
    }
    if !obj.deviations.is_empty() {
        if !out.is_empty() {
            out.push_str(" ; ");
        }
        out.push_str("path=$meta\tvalue_type=deviation\tvalue=");
        out.push_str(&obj.deviations.join(","));
    }
    out
}
