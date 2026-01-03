use crate::model::{AttackSurface, Finding};

bitflags::bitflags! {
    pub struct Needs: u32 {
        const XREF            = 0b00000001;
        const OBJECT_GRAPH    = 0b00000010;
        const STREAM_INDEX    = 0b00000100;
        const STREAM_DECODE   = 0b00001000;
        const PAGE_CONTENT    = 0b00010000;
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Cost {
    Cheap,
    Moderate,
    Expensive,
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn surface(&self) -> AttackSurface;
    fn needs(&self) -> Needs;
    fn cost(&self) -> Cost;
    fn run(&self, ctx: &crate::scan::ScanContext) -> anyhow::Result<Vec<Finding>>;
}
