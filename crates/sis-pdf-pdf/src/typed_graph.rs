/// Typed reference graph for PDF documents
///
/// This module builds a semantic graph of PDF object relationships with typed edges
/// that capture the meaning of references (OpenAction, JavaScript, URI, etc.).
use crate::classification::{ClassificationMap, PdfObjectType};
use crate::graph::{ObjEntry, ObjectGraph};
use crate::object::{PdfAtom, PdfDict, PdfObj};
use std::collections::{HashMap, HashSet};

/// Type of edge in the PDF reference graph
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeType {
    // Structural references
    /// Generic dictionary reference /Key -> obj
    DictReference { key: String },
    /// Array element reference
    ArrayElement { index: usize },

    // Semantic action references
    /// Catalog /OpenAction (document opens)
    OpenAction,
    /// Page /AA with specific event
    PageAction { event: String },
    /// Annotation /A (annotation action)
    AnnotationAction,
    /// Additional actions /AA generic
    AdditionalAction { event: String },
    /// Action /Next chain step
    NextAction,

    // JavaScript references
    /// /JS or /JavaScript payload
    JavaScriptPayload,
    /// /Names /JavaScript name tree
    JavaScriptNames,

    // External action references
    /// /URI target
    UriTarget,
    /// /Launch /F target
    LaunchTarget,
    /// /SubmitForm /F target
    SubmitFormTarget,
    /// /GoToR /F target
    GoToRTarget,

    // Content references
    /// /EmbeddedFile or /EF reference
    EmbeddedFileRef,
    /// /Font reference from page resources
    FontReference,
    /// /XObject reference from page resources
    XObjectReference,
    /// /ExtGState reference
    ExtGStateReference,

    // Form references
    /// Form field /Kids
    FormFieldKids,
    /// Form field /AA (field action)
    FormFieldAction { event: String },
    /// /XFA reference
    XfaReference,

    // Page tree references
    /// /Pages /Kids
    PagesKids,
    /// /Page /Parent
    PageParent,
    /// /Page /Contents
    PageContents,
    /// /Page /Resources
    PageResources,
    /// /Page /Annots
    PageAnnots,

    // Object stream references
    /// Object defined in ObjStm
    ObjStmReference,

    // Crypto/signature references
    /// /Encrypt dictionary reference
    EncryptRef,
    /// /Sig signature reference
    SignatureRef,

    // Media references
    /// /RichMedia reference
    RichMediaRef,
    /// /3D reference
    ThreeDRef,
    /// /Sound reference
    SoundRef,
    /// /Movie reference
    MovieRef,

    // Other references
    /// Generic reference (fallback)
    Generic,
}

impl EdgeType {
    /// Returns a string representation of the edge type
    pub fn as_str(&self) -> &str {
        match self {
            EdgeType::DictReference { .. } => "dict_reference",
            EdgeType::ArrayElement { .. } => "array_element",
            EdgeType::OpenAction => "open_action",
            EdgeType::PageAction { .. } => "page_action",
            EdgeType::AnnotationAction => "annotation_action",
            EdgeType::AdditionalAction { .. } => "additional_action",
            EdgeType::NextAction => "next_action",
            EdgeType::JavaScriptPayload => "javascript_payload",
            EdgeType::JavaScriptNames => "javascript_names",
            EdgeType::UriTarget => "uri_target",
            EdgeType::LaunchTarget => "launch_target",
            EdgeType::SubmitFormTarget => "submitform_target",
            EdgeType::GoToRTarget => "gotor_target",
            EdgeType::EmbeddedFileRef => "embedded_file",
            EdgeType::FontReference => "font_reference",
            EdgeType::XObjectReference => "xobject_reference",
            EdgeType::ExtGStateReference => "extgstate_reference",
            EdgeType::FormFieldKids => "form_field_kids",
            EdgeType::FormFieldAction { .. } => "form_field_action",
            EdgeType::XfaReference => "xfa_reference",
            EdgeType::PagesKids => "pages_kids",
            EdgeType::PageParent => "page_parent",
            EdgeType::PageContents => "page_contents",
            EdgeType::PageResources => "page_resources",
            EdgeType::PageAnnots => "page_annots",
            EdgeType::ObjStmReference => "objstm_reference",
            EdgeType::EncryptRef => "encrypt_ref",
            EdgeType::SignatureRef => "signature_ref",
            EdgeType::RichMediaRef => "richmedia_ref",
            EdgeType::ThreeDRef => "3d_ref",
            EdgeType::SoundRef => "sound_ref",
            EdgeType::MovieRef => "movie_ref",
            EdgeType::Generic => "generic",
        }
    }

    /// Returns true if this edge type is suspicious (potential attack vector)
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            EdgeType::OpenAction
                | EdgeType::PageAction { .. }
                | EdgeType::JavaScriptPayload
                | EdgeType::LaunchTarget
                | EdgeType::SubmitFormTarget
                | EdgeType::EmbeddedFileRef
        )
    }

    /// Returns true if this edge type is executable (can trigger behavior)
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            EdgeType::OpenAction
                | EdgeType::PageAction { .. }
                | EdgeType::AnnotationAction
                | EdgeType::AdditionalAction { .. }
                | EdgeType::JavaScriptPayload
                | EdgeType::FormFieldAction { .. }
                | EdgeType::NextAction
        ) || matches!(self, EdgeType::DictReference { key } if key == "/Next")
    }
}

/// A typed edge in the PDF reference graph
#[derive(Debug, Clone)]
pub struct TypedEdge {
    /// Source object (obj, gen)
    pub src: (u32, u16),
    /// Destination object (obj, gen)
    pub dst: (u32, u16),
    /// Type of edge
    pub edge_type: EdgeType,
    /// Is this edge suspicious?
    pub suspicious: bool,
    /// Weight for graph algorithms (default 1.0)
    pub weight: f32,
}

impl TypedEdge {
    /// Creates a new typed edge
    pub fn new(src: (u32, u16), dst: (u32, u16), edge_type: EdgeType) -> Self {
        let suspicious = edge_type.is_suspicious();
        Self { src, dst, edge_type, suspicious, weight: 1.0 }
    }

    /// Creates a suspicious edge
    pub fn new_suspicious(src: (u32, u16), dst: (u32, u16), edge_type: EdgeType) -> Self {
        Self { src, dst, edge_type, suspicious: true, weight: 1.0 }
    }
}

/// Typed reference graph for a PDF document
pub struct TypedGraph<'a> {
    /// Reference to the underlying object graph
    pub graph: &'a ObjectGraph<'a>,
    /// All typed edges in the document
    pub edges: Vec<TypedEdge>,
    /// Forward index: (obj, gen) -> indices into edges (outgoing)
    pub forward_index: HashMap<(u32, u16), Vec<usize>>,
    /// Reverse index: (obj, gen) -> indices into edges (incoming)
    pub reverse_index: HashMap<(u32, u16), Vec<usize>>,
}

impl<'a> TypedGraph<'a> {
    /// Builds a typed graph from an ObjectGraph
    pub fn build(graph: &'a ObjectGraph<'a>, classifications: &ClassificationMap) -> Self {
        let mut edges = Vec::new();
        let mut edge_extractor = EdgeExtractor { graph, classifications, edges: &mut edges };

        // Extract edges from all objects
        for entry in &graph.objects {
            edge_extractor.extract_edges_from_object(entry);
        }

        // Build indices
        let mut forward_index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();
        let mut reverse_index: HashMap<(u32, u16), Vec<usize>> = HashMap::new();

        for (idx, edge) in edges.iter().enumerate() {
            forward_index.entry(edge.src).or_default().push(idx);
            reverse_index.entry(edge.dst).or_default().push(idx);
        }

        Self { graph, edges, forward_index, reverse_index }
    }

    /// Returns all outgoing edges from an object
    pub fn outgoing_edges(&self, obj: u32, gen: u16) -> Vec<&TypedEdge> {
        self.forward_index
            .get(&(obj, gen))
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Returns all incoming edges to an object
    pub fn incoming_edges(&self, obj: u32, gen: u16) -> Vec<&TypedEdge> {
        self.reverse_index
            .get(&(obj, gen))
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Returns all edges of a specific type
    pub fn edges_of_type(&self, edge_type: &EdgeType) -> Vec<&TypedEdge> {
        self.edges.iter().filter(|e| &e.edge_type == edge_type).collect()
    }

    /// Returns all suspicious edges
    pub fn suspicious_edges(&self) -> Vec<&TypedEdge> {
        self.edges.iter().filter(|e| e.suspicious).collect()
    }

    /// Returns all edges matching a predicate
    pub fn filter_edges<F>(&self, predicate: F) -> Vec<&TypedEdge>
    where
        F: Fn(&TypedEdge) -> bool,
    {
        self.edges.iter().filter(|e| predicate(e)).collect()
    }

    /// Creates a PathFinder for this graph
    pub fn path_finder(&self) -> crate::path_finder::PathFinder<'_> {
        crate::path_finder::PathFinder::new(self)
    }
}

/// Edge extractor that builds typed edges from PDF objects
struct EdgeExtractor<'a, 'b> {
    graph: &'a ObjectGraph<'a>,
    classifications: &'b ClassificationMap,
    edges: &'b mut Vec<TypedEdge>,
}

impl<'a, 'b> EdgeExtractor<'a, 'b> {
    /// Extracts all edges from an object
    fn extract_edges_from_object(&mut self, entry: &ObjEntry<'a>) {
        let src = (entry.obj, entry.gen);

        match &entry.atom {
            PdfAtom::Dict(dict) => {
                self.extract_edges_from_dict(src, dict);
            }
            PdfAtom::Stream(stream) => {
                self.extract_edges_from_dict(src, &stream.dict);
            }
            PdfAtom::Array(items) => {
                self.extract_edges_from_array(src, items);
            }
            _ => {}
        }
    }

    /// Extracts edges from a dictionary
    fn extract_edges_from_dict(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // Get classification for context
        let classification = self.classifications.get(&src);
        let obj_type = classification.map(|c| c.obj_type);

        // Catalog-specific edges
        if obj_type == Some(PdfObjectType::Catalog) {
            self.extract_catalog_edges(src, dict);
        }

        // Page-specific edges
        if obj_type == Some(PdfObjectType::Page) {
            self.extract_page_edges(src, dict);
        }

        // Pages tree edges
        if obj_type == Some(PdfObjectType::Pages) {
            self.extract_pages_edges(src, dict);
        }

        // Action edges
        if obj_type == Some(PdfObjectType::Action) {
            self.extract_action_edges(src, dict);
        }

        // Annotation edges
        if obj_type == Some(PdfObjectType::Annotation) {
            self.extract_annotation_edges(src, dict);
        }

        // JavaScript edges
        self.extract_javascript_edges(src, dict);

        // Additional Actions (/AA)
        self.extract_aa_edges(src, dict, obj_type);

        // Form field edges
        self.extract_form_edges(src, dict);

        // Resource semantics (/Resources, /Font, /XObject)
        self.extract_resource_edges(src, dict);

        // Generic dictionary references (fallback)
        self.extract_generic_dict_edges(src, dict, obj_type);
    }

    /// Extracts edges from an array
    fn extract_edges_from_array(&mut self, src: (u32, u16), items: &[PdfObj<'a>]) {
        for (index, item) in items.iter().enumerate() {
            if let PdfAtom::Ref { obj, gen } = item.atom {
                let edge = TypedEdge::new(src, (obj, gen), EdgeType::ArrayElement { index });
                self.edges.push(edge);
            }
        }
    }

    /// Extracts Catalog-specific edges
    fn extract_catalog_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // /OpenAction
        if let Some((_, obj)) = dict.get_first(b"/OpenAction") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new_suspicious(src, dst, EdgeType::OpenAction);
                self.edges.push(edge);
            }
        }

        // /Pages
        if let Some((_, obj)) = dict.get_first(b"/Pages") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::PagesKids);
                self.edges.push(edge);
            }
        }

        // /Names /JavaScript
        if let Some((_, names_obj)) = dict.get_first(b"/Names") {
            let names_dict_opt = match &names_obj.atom {
                PdfAtom::Dict(d) => Some(d),
                PdfAtom::Ref { obj, gen } => {
                    self.graph.get_object(*obj, *gen).and_then(|entry| match &entry.atom {
                        PdfAtom::Dict(d) => Some(d),
                        PdfAtom::Stream(st) => Some(&st.dict),
                        _ => None,
                    })
                }
                _ => None,
            };

            if let Some(names_dict) = names_dict_opt {
                if let Some((_, js_obj)) = names_dict.get_first(b"/JavaScript") {
                    if let Some(dst) = self.resolve_ref(js_obj) {
                        let edge = TypedEdge::new_suspicious(src, dst, EdgeType::JavaScriptNames);
                        self.edges.push(edge);
                    }
                }
            }
        }

        // /Encrypt
        if let Some((_, obj)) = dict.get_first(b"/Encrypt") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::EncryptRef);
                self.edges.push(edge);
            }
        }
    }

    /// Extracts Page-specific edges
    fn extract_page_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // /Parent
        if let Some((_, obj)) = dict.get_first(b"/Parent") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::PageParent);
                self.edges.push(edge);
            }
        }

        // /Contents
        if let Some((_, obj)) = dict.get_first(b"/Contents") {
            for dst in self.collect_page_content_targets(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::PageContents);
                self.edges.push(edge);
            }
        }

        // /Resources
        if let Some((_, obj)) = dict.get_first(b"/Resources") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::PageResources);
                self.edges.push(edge);
            }
        }

        // /Annots
        if let Some((_, obj)) = dict.get_first(b"/Annots") {
            if let PdfAtom::Array(items) = &obj.atom {
                for item in items {
                    if let Some(dst) = self.resolve_ref(item) {
                        let edge = TypedEdge::new(src, dst, EdgeType::PageAnnots);
                        self.edges.push(edge);
                    }
                }
            } else if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::PageAnnots);
                self.edges.push(edge);
            }
        }
    }

    /// Extracts Pages tree edges
    fn extract_pages_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // /Kids
        if let Some((_, obj)) = dict.get_first(b"/Kids") {
            if let PdfAtom::Array(items) = &obj.atom {
                for item in items {
                    if let Some(dst) = self.resolve_ref(item) {
                        let edge = TypedEdge::new(src, dst, EdgeType::PagesKids);
                        self.edges.push(edge);
                    }
                }
            }
        }
    }

    /// Extracts Action-specific edges
    fn extract_action_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // Check action type /S
        if let Some((_, s_obj)) = dict.get_first(b"/S") {
            if let PdfAtom::Name(name) = &s_obj.atom {
                match name.decoded.as_slice() {
                    b"/JavaScript" => {
                        // Already handled by extract_javascript_edges
                    }
                    b"/URI" => {
                        if let Some((_, obj)) = dict.get_first(b"/URI") {
                            if let Some(dst) = self.resolve_ref(obj) {
                                let edge = TypedEdge::new_suspicious(src, dst, EdgeType::UriTarget);
                                self.edges.push(edge);
                            }
                        }
                    }
                    b"/Launch" => {
                        if let Some((_, obj)) = dict.get_first(b"/F") {
                            if let Some(dst) = self.resolve_ref(obj) {
                                let edge =
                                    TypedEdge::new_suspicious(src, dst, EdgeType::LaunchTarget);
                                self.edges.push(edge);
                            }
                        }
                    }
                    b"/SubmitForm" => {
                        if let Some((_, obj)) = dict.get_first(b"/F") {
                            if let Some(dst) = self.resolve_ref(obj) {
                                let edge =
                                    TypedEdge::new_suspicious(src, dst, EdgeType::SubmitFormTarget);
                                self.edges.push(edge);
                            }
                        }
                    }
                    b"/GoToR" => {
                        if let Some((_, obj)) = dict.get_first(b"/F") {
                            if let Some(dst) = self.resolve_ref(obj) {
                                let edge = TypedEdge::new(src, dst, EdgeType::GoToRTarget);
                                self.edges.push(edge);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // /Next chaining (single ref or array of refs)
        if let Some((_, next_obj)) = dict.get_first(b"/Next") {
            match &next_obj.atom {
                PdfAtom::Ref { obj, gen } => {
                    self.edges.push(TypedEdge::new(src, (*obj, *gen), EdgeType::NextAction));
                }
                PdfAtom::Array(items) => {
                    for item in items {
                        if let Some(dst) = self.resolve_ref(item) {
                            self.edges.push(TypedEdge::new(src, dst, EdgeType::NextAction));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Extracts Annotation-specific edges
    fn extract_annotation_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // /A (action)
        if let Some((_, obj)) = dict.get_first(b"/A") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::AnnotationAction);
                self.edges.push(edge);
            }
        }
    }

    /// Extracts JavaScript edges
    fn extract_javascript_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // /JS
        if let Some((_, obj)) = dict.get_first(b"/JS") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new_suspicious(src, dst, EdgeType::JavaScriptPayload);
                self.edges.push(edge);
            }
        }

        // /JavaScript
        if let Some((_, obj)) = dict.get_first(b"/JavaScript") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new_suspicious(src, dst, EdgeType::JavaScriptPayload);
                self.edges.push(edge);
            }
        }
    }

    /// Extracts Additional Actions (/AA) edges
    fn extract_aa_edges(
        &mut self,
        src: (u32, u16),
        dict: &PdfDict<'a>,
        obj_type: Option<PdfObjectType>,
    ) {
        if let Some((_, aa_obj)) = dict.get_first(b"/AA") {
            // Get AA dict - could be direct or reference
            let aa_dict_opt = match &aa_obj.atom {
                PdfAtom::Dict(d) => Some(d),
                PdfAtom::Ref { obj, gen } => {
                    self.graph.get_object(*obj, *gen).and_then(|entry| match &entry.atom {
                        PdfAtom::Dict(d) => Some(d),
                        PdfAtom::Stream(st) => Some(&st.dict),
                        _ => None,
                    })
                }
                _ => None,
            };

            if let Some(aa_dict) = aa_dict_opt {
                // Common AA events
                let events = [
                    "/O", "/C", "/WC", "/WS", "/DS", "/WP", "/DP", "/PV", "/PI", "/K", "/F", "/V",
                    "/D", "/U", "/E", "/X", "/Fo", "/Bl",
                ];
                for event in &events {
                    if let Some((_, obj)) = aa_dict.get_first(event.as_bytes()) {
                        if let Some(dst) = Self::resolve_ref_static(obj) {
                            let edge_type = if obj_type == Some(PdfObjectType::Page) {
                                EdgeType::PageAction { event: event.to_string() }
                            } else if is_form_field_dict(dict) {
                                EdgeType::FormFieldAction { event: event.to_string() }
                            } else {
                                EdgeType::AdditionalAction { event: event.to_string() }
                            };
                            let edge = TypedEdge::new_suspicious(src, dst, edge_type);
                            self.edges.push(edge);
                        }
                    }
                }
            }
        }
    }

    /// Extracts form field edges
    fn extract_form_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        // /Kids (form field children)
        if dict.get_first(b"/FT").is_some() {
            // This is a form field
            if let Some((_, obj)) = dict.get_first(b"/Kids") {
                if let PdfAtom::Array(items) = &obj.atom {
                    for item in items {
                        if let Some(dst) = self.resolve_ref(item) {
                            let edge = TypedEdge::new(src, dst, EdgeType::FormFieldKids);
                            self.edges.push(edge);
                        }
                    }
                }
            }
        }

        // /XFA
        if let Some((_, obj)) = dict.get_first(b"/XFA") {
            if let Some(dst) = self.resolve_ref(obj) {
                let edge = TypedEdge::new(src, dst, EdgeType::XfaReference);
                self.edges.push(edge);
            }
        }
    }

    /// Extracts resource-related semantic edges
    fn extract_resource_edges(&mut self, src: (u32, u16), dict: &PdfDict<'a>) {
        if let Some((_, resources_obj)) = dict.get_first(b"/Resources") {
            if let Some(dst) = self.resolve_ref(resources_obj) {
                self.edges.push(TypedEdge::new(src, dst, EdgeType::PageResources));
            }
            self.extract_resource_dict_edges(src, resources_obj);
        }
        if let Some((_, font_obj)) = dict.get_first(b"/Font") {
            self.extract_font_edges(src, font_obj);
        }
        if let Some((_, xobject_obj)) = dict.get_first(b"/XObject") {
            self.extract_xobject_edges(src, xobject_obj);
        }
    }

    fn extract_resource_dict_edges(&mut self, src: (u32, u16), obj: &PdfObj<'a>) {
        let Some(dict) = self.resolve_dict(obj) else {
            return;
        };
        if let Some((_, font_obj)) = dict.get_first(b"/Font") {
            self.extract_font_edges(src, font_obj);
        }
        if let Some((_, xobject_obj)) = dict.get_first(b"/XObject") {
            self.extract_xobject_edges(src, xobject_obj);
        }
    }

    fn extract_font_edges(&mut self, src: (u32, u16), obj: &PdfObj<'a>) {
        self.collect_reference_targets(obj).into_iter().for_each(|dst| {
            self.edges.push(TypedEdge::new(src, dst, EdgeType::FontReference));
        });
    }

    fn extract_xobject_edges(&mut self, src: (u32, u16), obj: &PdfObj<'a>) {
        self.collect_reference_targets(obj).into_iter().for_each(|dst| {
            self.edges.push(TypedEdge::new(src, dst, EdgeType::XObjectReference));
        });
    }

    fn collect_reference_targets(&self, obj: &PdfObj<'a>) -> Vec<(u32, u16)> {
        match &obj.atom {
            PdfAtom::Ref { obj, gen } => vec![(*obj, *gen)],
            PdfAtom::Array(items) => items
                .iter()
                .filter_map(|item| match item.atom {
                    PdfAtom::Ref { obj, gen } => Some((obj, gen)),
                    _ => None,
                })
                .collect(),
            PdfAtom::Dict(dict) => dict
                .entries
                .iter()
                .filter_map(|(_, value)| match value.atom {
                    PdfAtom::Ref { obj, gen } => Some((obj, gen)),
                    _ => None,
                })
                .collect(),
            _ => {
                let resolved_dict = self.resolve_dict(obj);
                resolved_dict
                    .map(|dict| {
                        dict.entries
                            .iter()
                            .filter_map(|(_, value)| match value.atom {
                                PdfAtom::Ref { obj, gen } => Some((obj, gen)),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }
        }
    }

    fn collect_page_content_targets(&self, obj: &PdfObj<'a>) -> Vec<(u32, u16)> {
        let mut targets = Vec::new();
        let mut seen = HashSet::<(u32, u16)>::new();
        match &obj.atom {
            PdfAtom::Ref { obj, gen } => {
                if seen.insert((*obj, *gen)) {
                    targets.push((*obj, *gen));
                }
            }
            PdfAtom::Array(items) => {
                for item in items {
                    if let Some(dst) = self.resolve_ref(item) {
                        if seen.insert(dst) {
                            targets.push(dst);
                        }
                    }
                }
            }
            _ => {}
        }
        targets
    }

    /// Extracts generic dictionary references
    fn extract_generic_dict_edges(
        &mut self,
        src: (u32, u16),
        dict: &PdfDict<'a>,
        obj_type: Option<PdfObjectType>,
    ) {
        // Extract all references that weren't handled by specific extractors
        for (key, value) in &dict.entries {
            if let Some(dst) = self.resolve_ref(value) {
                // Check if this edge was already added by specific extractor
                // For now, we'll skip generic edges for known keys
                let key_bytes = &key.decoded;
                // Action /Next is handled semantically as NextAction edges.
                if key_bytes == b"/Next" && obj_type == Some(PdfObjectType::Action) {
                    continue;
                }
                if !self.is_known_key(key_bytes) {
                    let edge = TypedEdge::new(
                        src,
                        dst,
                        EdgeType::DictReference {
                            key: String::from_utf8_lossy(key_bytes).to_string(),
                        },
                    );
                    self.edges.push(edge);
                }
            }
        }
    }

    /// Checks if a key is handled by specific extractors
    fn is_known_key(&self, key: &[u8]) -> bool {
        matches!(
            key,
            b"/OpenAction"
                | b"/Pages"
                | b"/Parent"
                | b"/Contents"
                | b"/Resources"
                | b"/Annots"
                | b"/Kids"
                | b"/A"
                | b"/AA"
                | b"/JS"
                | b"/JavaScript"
                | b"/F"
                | b"/XFA"
                | b"/Encrypt"
                | b"/Names"
                | b"/Next"
        )
    }

    /// Resolves a reference to (obj, gen)
    fn resolve_ref(&self, obj: &PdfObj<'a>) -> Option<(u32, u16)> {
        Self::resolve_ref_static(obj)
    }

    /// Static version of resolve_ref (no self borrow needed)
    fn resolve_ref_static(obj: &PdfObj<'a>) -> Option<(u32, u16)> {
        match obj.atom {
            PdfAtom::Ref { obj, gen } => Some((obj, gen)),
            _ => None,
        }
    }

    fn resolve_dict<'c>(&self, obj: &'c PdfObj<'a>) -> Option<&'c PdfDict<'a>> {
        match &obj.atom {
            PdfAtom::Dict(dict) => Some(dict),
            PdfAtom::Ref { obj, gen } => {
                self.graph.get_object(*obj, *gen).and_then(|entry| match &entry.atom {
                    PdfAtom::Dict(dict) => Some(dict),
                    PdfAtom::Stream(stream) => Some(&stream.dict),
                    _ => None,
                })
            }
            _ => None,
        }
    }

    /// Gets a dictionary from an object
    #[allow(dead_code)]
    fn get_dict<'c>(&self, obj: &'c PdfObj<'a>) -> Option<&'c PdfDict<'a>> {
        match &obj.atom {
            PdfAtom::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// Gets a dictionary from an object, resolving references
    #[allow(dead_code)]
    fn get_dict_resolved(&self, obj: &'a PdfObj<'a>) -> Option<&'a PdfDict<'a>> {
        match &obj.atom {
            PdfAtom::Dict(d) => Some(d),
            PdfAtom::Ref { obj: ref_obj, gen } => {
                let entry = self.graph.get_object(*ref_obj, *gen)?;
                match &entry.atom {
                    PdfAtom::Dict(d) => Some(d),
                    PdfAtom::Stream(st) => Some(&st.dict),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

fn is_form_field_dict(dict: &PdfDict<'_>) -> bool {
    dict.get_first(b"/FT").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_pdf, ParseOptions};

    fn build_pdf(objects: &[String], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = vec![0usize; size];
        for object in objects {
            let id = object
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if id < offsets.len() {
                offsets[id] = out.len();
            }
            out.extend_from_slice(object.as_bytes());
        }
        let startxref = out.len();
        out.extend_from_slice(format!("xref\n0 {}\n", size).as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets.iter().skip(1) {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n", size).as_bytes(),
        );
        out.extend_from_slice(startxref.to_string().as_bytes());
        out.extend_from_slice(b"\n%%EOF\n");
        out
    }

    fn parse_options() -> ParseOptions {
        ParseOptions {
            recover_xref: true,
            deep: false,
            strict: false,
            max_objstm_bytes: 1024 * 1024,
            max_objects: 10_000,
            max_objstm_total_bytes: 10 * 1024 * 1024,
            carve_stream_objects: false,
            max_carved_objects: 0,
            max_carved_bytes: 0,
        }
    }

    #[test]
    fn test_edge_type() {
        assert!(EdgeType::OpenAction.is_suspicious());
        assert!(EdgeType::JavaScriptPayload.is_suspicious());
        assert!(!EdgeType::PageParent.is_suspicious());

        assert!(EdgeType::OpenAction.is_executable());
        assert!(EdgeType::JavaScriptPayload.is_executable());
        assert!(EdgeType::NextAction.is_executable());
        assert!(!EdgeType::PageParent.is_executable());
    }

    #[test]
    fn test_typed_edge_creation() {
        let edge = TypedEdge::new((1, 0), (2, 0), EdgeType::OpenAction);
        assert_eq!(edge.src, (1, 0));
        assert_eq!(edge.dst, (2, 0));
        assert!(edge.suspicious); // OpenAction is suspicious
        assert_eq!(edge.weight, 1.0);
    }

    #[test]
    fn page_contents_single_ref_emits_one_edge() {
        let objects = vec![
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n".to_string(),
            "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n".to_string(),
        ];
        let bytes = build_pdf(&objects, 5);
        let graph = parse_pdf(&bytes, parse_options()).expect("parse pdf");
        let classifications = graph.classify_objects();
        let typed = TypedGraph::build(&graph, &classifications);

        let page_contents = typed
            .edges
            .iter()
            .filter(|edge| edge.src == (3, 0) && matches!(edge.edge_type, EdgeType::PageContents))
            .collect::<Vec<_>>();
        assert_eq!(page_contents.len(), 1);
        assert_eq!(page_contents[0].dst, (4, 0));
    }

    #[test]
    fn page_contents_array_emits_edges_for_all_unique_refs() {
        let objects = vec![
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents [4 0 R 5 0 R 4 0 R] >>\nendobj\n"
                .to_string(),
            "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n".to_string(),
            "5 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n".to_string(),
        ];
        let bytes = build_pdf(&objects, 6);
        let graph = parse_pdf(&bytes, parse_options()).expect("parse pdf");
        let classifications = graph.classify_objects();
        let typed = TypedGraph::build(&graph, &classifications);

        let mut targets = typed
            .edges
            .iter()
            .filter(|edge| edge.src == (3, 0) && matches!(edge.edge_type, EdgeType::PageContents))
            .map(|edge| edge.dst)
            .collect::<Vec<_>>();
        targets.sort_unstable();
        assert_eq!(targets, vec![(4, 0), (5, 0)]);
    }

    #[test]
    fn page_missing_contents_emits_no_page_contents_edge() {
        let objects = vec![
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
            "2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n".to_string(),
            "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n".to_string(),
        ];
        let bytes = build_pdf(&objects, 4);
        let graph = parse_pdf(&bytes, parse_options()).expect("parse pdf");
        let classifications = graph.classify_objects();
        let typed = TypedGraph::build(&graph, &classifications);
        let page_contents_count = typed
            .edges
            .iter()
            .filter(|edge| edge.src == (3, 0) && matches!(edge.edge_type, EdgeType::PageContents))
            .count();
        assert_eq!(page_contents_count, 0);
    }
}
