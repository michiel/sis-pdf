use sis_pdf_pdf::content::{ContentOperand, ContentOp};
use sis_pdf_pdf::object::{PdfAtom, PdfDict, PdfObj, PdfStream};

use crate::scan::ScanContext;
use crate::page_tree::build_page_tree;

#[derive(Debug, Clone)]
pub struct PageContent {
    pub obj: u32,
    pub gen: u16,
    pub page_number: usize,
    pub media_box: Option<[f32; 4]>,
    pub text_points: Vec<(f32, f32)>,
    pub image_points: Vec<(f32, f32)>,
    pub invisible_text: bool,
}

pub fn build_content_index<'a>(ctx: &'a ScanContext<'a>) -> Vec<PageContent> {
    let mut out = Vec::new();
    let tree = build_page_tree(&ctx.graph);
    for page in &tree.pages {
        let entry = match ctx.graph.get_object(page.obj, page.gen) {
            Some(e) => e,
            None => continue,
        };
        let dict = match entry_dict(entry) {
            Some(d) => d,
            None => continue,
        };
        let media_box = page.media_box.or_else(|| media_box_from_dict(dict));
        let mut text_points = Vec::new();
        let mut image_points = Vec::new();
        let mut invisible_text = false;
        let contents = page_contents_streams(ctx, dict);
        for st in contents {
            if let Ok(decoded) = ctx.decoded.get_or_decode(ctx.bytes, &st) {
                let ops = sis_pdf_pdf::content::parse_content_ops(&decoded.data);
                let mut cur_text = (0.0f32, 0.0f32);
                let mut last_ctm = [1.0f32, 0.0f32, 0.0f32, 1.0f32, 0.0f32, 0.0f32];
                for op in ops {
                    apply_op(
                        &op,
                        &mut cur_text,
                        &mut last_ctm,
                        &mut text_points,
                        &mut image_points,
                        &mut invisible_text,
                        media_box,
                    );
                }
            }
        }
        out.push(PageContent {
            obj: page.obj,
            gen: page.gen,
            page_number: page.number,
            media_box,
            text_points,
            image_points,
            invisible_text,
        });
    }
    out
}

fn apply_op(
    op: &ContentOp,
    cur_text: &mut (f32, f32),
    last_ctm: &mut [f32; 6],
    text_points: &mut Vec<(f32, f32)>,
    image_points: &mut Vec<(f32, f32)>,
    invisible_text: &mut bool,
    media_box: Option<[f32; 4]>,
) {
    match op.op.as_str() {
        "Tm" => {
            if let Some((e, f)) = last_two_numbers(&op.operands) {
                cur_text.0 = e;
                cur_text.1 = f;
            }
        }
        "Td" => {
            if let Some((tx, ty)) = last_two_numbers(&op.operands) {
                cur_text.0 += tx;
                cur_text.1 += ty;
            }
        }
        "Tj" | "TJ" | "Tf" | "BT" => {
            let (x, y) = normalise_point(*cur_text, media_box);
            text_points.push((x, y));
        }
        "Tr" => {
            if let Some(v) = first_number(&op.operands) {
                if (v - 3.0).abs() < f32::EPSILON {
                    *invisible_text = true;
                }
            }
        }
        "cm" => {
            if op.operands.len() >= 6 {
                let nums = numbers_from_operands(&op.operands);
                if nums.len() >= 6 {
                    last_ctm.copy_from_slice(&nums[0..6]);
                }
            }
        }
        "Do" => {
            let (x, y) = normalise_point((last_ctm[4], last_ctm[5]), media_box);
            image_points.push((x, y));
        }
        _ => {}
    }
}

fn normalise_point(point: (f32, f32), media_box: Option<[f32; 4]>) -> (f32, f32) {
    if let Some([x0, y0, x1, y1]) = media_box {
        let w = (x1 - x0).abs();
        let h = (y1 - y0).abs();
        if w > 0.0 && h > 0.0 {
            let nx = ((point.0 - x0) / w).clamp(0.0, 1.0);
            let ny = ((point.1 - y0) / h).clamp(0.0, 1.0);
            return (nx, ny);
        }
    }
    point
}

fn entry_dict<'a>(entry: &'a sis_pdf_pdf::graph::ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
    match &entry.atom {
        PdfAtom::Dict(d) => Some(d),
        PdfAtom::Stream(st) => Some(&st.dict),
        _ => None,
    }
}

fn media_box_from_dict(dict: &PdfDict<'_>) -> Option<[f32; 4]> {
    let (_, obj) = dict.get_first(b"/MediaBox")?;
    if let PdfAtom::Array(arr) = &obj.atom {
        let mut out = [0.0f32; 4];
        let mut idx = 0usize;
        for item in arr {
            if idx >= 4 {
                break;
            }
            match &item.atom {
                PdfAtom::Int(i) => {
                    out[idx] = *i as f32;
                    idx += 1;
                }
                PdfAtom::Real(f) => {
                    out[idx] = *f as f32;
                    idx += 1;
                }
                _ => {}
            }
        }
        if idx == 4 {
            return Some(out);
        }
    }
    None
}

fn page_contents_streams<'a>(ctx: &ScanContext<'a>, dict: &PdfDict<'a>) -> Vec<PdfStream<'a>> {
    let mut out = Vec::new();
    if let Some((_, obj)) = dict.get_first(b"/Contents") {
        match &obj.atom {
            PdfAtom::Stream(st) => out.push(st.clone()),
            PdfAtom::Array(arr) => {
                for o in arr {
                    if let Some(st) = resolve_stream(ctx, o) {
                        out.push(st);
                    }
                }
            }
            _ => {
                if let Some(st) = resolve_stream(ctx, obj) {
                    out.push(st);
                }
            }
        }
    }
    out
}

fn resolve_stream<'a>(ctx: &ScanContext<'a>, obj: &PdfObj<'a>) -> Option<PdfStream<'a>> {
    match &obj.atom {
        PdfAtom::Stream(st) => Some(st.clone()),
        PdfAtom::Ref { .. } => ctx.graph.resolve_ref(obj).and_then(|e| match e.atom {
            PdfAtom::Stream(st) => Some(st),
            _ => None,
        }),
        _ => None,
    }
}

fn numbers_from_operands(ops: &[ContentOperand]) -> Vec<f32> {
    ops.iter()
        .filter_map(|o| match o {
            ContentOperand::Number(n) => Some(*n),
            _ => None,
        })
        .collect()
}

fn last_two_numbers(ops: &[ContentOperand]) -> Option<(f32, f32)> {
    let nums = numbers_from_operands(ops);
    if nums.len() >= 2 {
        let len = nums.len();
        Some((nums[len - 2], nums[len - 1]))
    } else {
        None
    }
}

fn first_number(ops: &[ContentOperand]) -> Option<f32> {
    ops.iter().find_map(|o| match o {
        ContentOperand::Number(n) => Some(*n),
        _ => None,
    })
}
