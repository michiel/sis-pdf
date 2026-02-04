/// Object classification system for PDF objects
///
/// This module provides type classification and role identification for PDF objects,
/// enabling rich semantic analysis throughout the codebase.
use crate::graph::ObjEntry;
use crate::object::{PdfAtom, PdfDict};
use std::collections::{HashMap, HashSet};

/// Classification of PDF object types based on structure and dictionary entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdfObjectType {
    /// Document catalog (root object)
    Catalog,
    /// Pages tree node
    Pages,
    /// Individual page
    Page,
    /// Action dictionary
    Action,
    /// Annotation
    Annotation,
    /// Font dictionary
    Font,
    /// Image XObject
    Image,
    /// Generic stream
    Stream,
    /// Object stream (compressed objects)
    ObjStm,
    /// Generic dictionary
    Dict,
    /// Array
    Array,
    /// Other/unknown type
    Other,
}

impl PdfObjectType {
    /// Returns a human-readable name for this object type
    pub fn as_str(&self) -> &'static str {
        match self {
            PdfObjectType::Catalog => "catalog",
            PdfObjectType::Pages => "pages",
            PdfObjectType::Page => "page",
            PdfObjectType::Action => "action",
            PdfObjectType::Annotation => "annotation",
            PdfObjectType::Font => "font",
            PdfObjectType::Image => "image",
            PdfObjectType::Stream => "stream",
            PdfObjectType::ObjStm => "objstm",
            PdfObjectType::Dict => "dict",
            PdfObjectType::Array => "array",
            PdfObjectType::Other => "other",
        }
    }

    /// Returns true if this object type is a container type
    pub fn is_container(&self) -> bool {
        matches!(
            self,
            PdfObjectType::Catalog
                | PdfObjectType::Pages
                | PdfObjectType::Page
                | PdfObjectType::ObjStm
        )
    }

    /// Returns true if this object type is an executable type (can trigger behavior)
    pub fn is_executable(&self) -> bool {
        matches!(self, PdfObjectType::Action | PdfObjectType::Annotation)
    }
}

/// Roles that a PDF object can play in attack scenarios or document structure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectRole {
    /// Contains JavaScript code
    JsContainer,
    /// Target of an action
    ActionTarget,
    /// Contains embedded file
    EmbeddedFile,
    /// Target of a URI action
    UriTarget,
    /// Form field
    FormField,
    /// Page content stream
    PageContent,
    /// Font with potential exploits
    SuspiciousFont,
    /// Launch action target
    LaunchTarget,
    /// SubmitForm target
    SubmitFormTarget,
    /// Object in object stream
    CompressedObject,
    /// Encryption-related object
    CryptoObject,
    /// Signature-related object
    SignatureObject,
    /// XFA form component
    XfaComponent,
    /// RichMedia/3D content
    MediaContent,
}

impl ObjectRole {
    /// Returns a human-readable name for this role
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectRole::JsContainer => "js_container",
            ObjectRole::ActionTarget => "action_target",
            ObjectRole::EmbeddedFile => "embedded_file",
            ObjectRole::UriTarget => "uri_target",
            ObjectRole::FormField => "form_field",
            ObjectRole::PageContent => "page_content",
            ObjectRole::SuspiciousFont => "suspicious_font",
            ObjectRole::LaunchTarget => "launch_target",
            ObjectRole::SubmitFormTarget => "submit_form_target",
            ObjectRole::CompressedObject => "compressed_object",
            ObjectRole::CryptoObject => "crypto_object",
            ObjectRole::SignatureObject => "signature_object",
            ObjectRole::XfaComponent => "xfa_component",
            ObjectRole::MediaContent => "media_content",
        }
    }

    /// Returns true if this role indicates potentially malicious behavior
    pub fn is_suspicious(&self) -> bool {
        matches!(
            self,
            ObjectRole::JsContainer
                | ObjectRole::SuspiciousFont
                | ObjectRole::LaunchTarget
                | ObjectRole::SubmitFormTarget
        )
    }
}

/// A classified PDF object with type and role information
#[derive(Debug, Clone)]
pub struct ClassifiedObject {
    pub obj: u32,
    pub gen: u16,
    pub obj_type: PdfObjectType,
    pub roles: HashSet<ObjectRole>,
}

impl ClassifiedObject {
    /// Creates a new classified object
    pub fn new(obj: u32, gen: u16, obj_type: PdfObjectType) -> Self {
        Self {
            obj,
            gen,
            obj_type,
            roles: HashSet::new(),
        }
    }

    /// Adds a role to this object
    pub fn add_role(&mut self, role: ObjectRole) {
        self.roles.insert(role);
    }

    /// Returns true if this object has the given role
    pub fn has_role(&self, role: ObjectRole) -> bool {
        self.roles.contains(&role)
    }

    /// Returns true if this object has any suspicious roles
    pub fn is_suspicious(&self) -> bool {
        self.roles.iter().any(|r| r.is_suspicious())
    }

    /// Returns true if this object is executable (can trigger behavior)
    pub fn is_executable(&self) -> bool {
        self.obj_type.is_executable()
            || self.has_role(ObjectRole::JsContainer)
            || self.has_role(ObjectRole::ActionTarget)
    }
}

/// Classifier for PDF objects
pub struct ObjectClassifier;

impl ObjectClassifier {
    /// Classifies a single PDF object based on its structure and content
    pub fn classify_object(entry: &ObjEntry<'_>) -> ClassifiedObject {
        let mut classified = match &entry.atom {
            PdfAtom::Dict(dict) => Self::classify_dict(entry.obj, entry.gen, dict),
            PdfAtom::Stream(stream) => Self::classify_stream(entry.obj, entry.gen, &stream.dict),
            PdfAtom::Array(_) => ClassifiedObject::new(entry.obj, entry.gen, PdfObjectType::Array),
            _ => ClassifiedObject::new(entry.obj, entry.gen, PdfObjectType::Other),
        };

        // Additional role detection based on content
        Self::detect_roles(entry, &mut classified);

        classified
    }

    /// Classifies a dictionary object
    fn classify_dict(obj: u32, gen: u16, dict: &PdfDict<'_>) -> ClassifiedObject {
        // Check /Type entry for explicit type
        if let Some((_, type_obj)) = dict.get_first(b"/Type") {
            if let PdfAtom::Name(name) = &type_obj.atom {
                let type_str = &name.decoded;
                let obj_type = match type_str.as_slice() {
                    b"/Catalog" => PdfObjectType::Catalog,
                    b"/Pages" => PdfObjectType::Pages,
                    b"/Page" => PdfObjectType::Page,
                    b"/Action" => PdfObjectType::Action,
                    b"/Annot" => PdfObjectType::Annotation,
                    b"/Font" => PdfObjectType::Font,
                    b"/XObject" => {
                        // Check /Subtype for Image
                        if dict.has_name(b"/Subtype", b"/Image") {
                            PdfObjectType::Image
                        } else {
                            PdfObjectType::Stream
                        }
                    }
                    b"/ObjStm" => PdfObjectType::ObjStm,
                    _ => PdfObjectType::Dict,
                };
                return ClassifiedObject::new(obj, gen, obj_type);
            }
        }

        // Check /Subtype for additional classification
        if let Some((_, subtype_obj)) = dict.get_first(b"/Subtype") {
            if let PdfAtom::Name(name) = &subtype_obj.atom {
                let subtype_str = &name.decoded;
                let obj_type = match subtype_str.as_slice() {
                    b"/Link" | b"/Widget" | b"/Popup" => PdfObjectType::Annotation,
                    b"/Image" => PdfObjectType::Image,
                    b"/Type1" | b"/TrueType" | b"/Type3" => PdfObjectType::Font,
                    _ => PdfObjectType::Dict,
                };
                return ClassifiedObject::new(obj, gen, obj_type);
            }
        }

        // Check for action by /S key
        if dict.get_first(b"/S").is_some() {
            return ClassifiedObject::new(obj, gen, PdfObjectType::Action);
        }

        // Default to generic dict
        ClassifiedObject::new(obj, gen, PdfObjectType::Dict)
    }

    /// Classifies a stream object
    fn classify_stream(obj: u32, gen: u16, dict: &PdfDict<'_>) -> ClassifiedObject {
        // Check /Type for specific stream types
        if let Some((_, type_obj)) = dict.get_first(b"/Type") {
            if let PdfAtom::Name(name) = &type_obj.atom {
                let type_str = &name.decoded;
                let obj_type = match type_str.as_slice() {
                    b"/XObject" => {
                        if dict.has_name(b"/Subtype", b"/Image") {
                            PdfObjectType::Image
                        } else {
                            PdfObjectType::Stream
                        }
                    }
                    b"/ObjStm" => PdfObjectType::ObjStm,
                    b"/EmbeddedFile" => PdfObjectType::Stream,
                    _ => PdfObjectType::Stream,
                };
                return ClassifiedObject::new(obj, gen, obj_type);
            }
        }

        // Check /Subtype
        if dict.has_name(b"/Subtype", b"/Image") {
            return ClassifiedObject::new(obj, gen, PdfObjectType::Image);
        }

        if dict.has_name(b"/Type", b"/ObjStm") {
            return ClassifiedObject::new(obj, gen, PdfObjectType::ObjStm);
        }

        // Default to generic stream
        ClassifiedObject::new(obj, gen, PdfObjectType::Stream)
    }

    /// Detects additional roles based on object content
    fn detect_roles(entry: &ObjEntry<'_>, classified: &mut ClassifiedObject) {
        if let Some(dict) = Self::get_dict(entry) {
            // JavaScript container
            if Self::has_javascript(dict) {
                classified.add_role(ObjectRole::JsContainer);
            }

            // Action target
            if dict.get_first(b"/A").is_some() || dict.get_first(b"/AA").is_some() {
                classified.add_role(ObjectRole::ActionTarget);
            }

            // Embedded file
            if dict.has_name(b"/Type", b"/EmbeddedFile")
                || dict.get_first(b"/EF").is_some()
                || dict.get_first(b"/AF").is_some()
            {
                classified.add_role(ObjectRole::EmbeddedFile);
            }

            // URI target
            if dict.has_name(b"/S", b"/URI") || dict.get_first(b"/URI").is_some() {
                classified.add_role(ObjectRole::UriTarget);
            }

            // Launch target
            if dict.has_name(b"/S", b"/Launch") {
                classified.add_role(ObjectRole::LaunchTarget);
            }

            // SubmitForm target
            if dict.has_name(b"/S", b"/SubmitForm") {
                classified.add_role(ObjectRole::SubmitFormTarget);
            }

            // Form field
            if dict.get_first(b"/FT").is_some() || dict.get_first(b"/T").is_some() {
                classified.add_role(ObjectRole::FormField);
            }

            // Crypto/signature objects
            if dict.get_first(b"/Encrypt").is_some() {
                classified.add_role(ObjectRole::CryptoObject);
            }

            if dict.has_name(b"/Type", b"/Sig") || dict.get_first(b"/ByteRange").is_some() {
                classified.add_role(ObjectRole::SignatureObject);
            }

            // XFA
            if dict.get_first(b"/XFA").is_some() {
                classified.add_role(ObjectRole::XfaComponent);
            }

            // RichMedia/3D
            if dict.get_first(b"/RichMedia").is_some()
                || dict.get_first(b"/3D").is_some()
                || dict.get_first(b"/U3D").is_some()
            {
                classified.add_role(ObjectRole::MediaContent);
            }

            // Suspicious fonts
            if classified.obj_type == PdfObjectType::Font
                && dict.get_first(b"/FontMatrix").is_some() {
                    // FontMatrix with non-numeric values is suspicious
                    if let Some((_, obj)) = dict.get_first(b"/FontMatrix") {
                        if let PdfAtom::Array(arr) = &obj.atom {
                            if arr
                                .iter()
                                .any(|o| !matches!(o.atom, PdfAtom::Int(_) | PdfAtom::Real(_)))
                            {
                                classified.add_role(ObjectRole::SuspiciousFont);
                            }
                        }
                    }
                }
        }

        // Compressed object (in ObjStm)
        // This would be detected during ObjStm expansion, could be added as metadata
    }

    /// Helper to check if a dictionary contains JavaScript
    fn has_javascript(dict: &PdfDict<'_>) -> bool {
        dict.has_name(b"/S", b"/JavaScript")
            || dict.get_first(b"/JS").is_some()
            || dict.get_first(b"/JavaScript").is_some()
    }

    /// Helper to get dictionary from entry
    fn get_dict<'a>(entry: &'a ObjEntry<'a>) -> Option<&'a PdfDict<'a>> {
        match &entry.atom {
            PdfAtom::Dict(d) => Some(d),
            PdfAtom::Stream(st) => Some(&st.dict),
            _ => None,
        }
    }
}

/// Classification map for all objects in a document
pub type ClassificationMap = HashMap<(u32, u16), ClassifiedObject>;

/// Builds a classification map for all objects in the graph
pub fn classify_all_objects(objects: &[ObjEntry<'_>]) -> ClassificationMap {
    objects
        .iter()
        .map(|entry| {
            let classified = ObjectClassifier::classify_object(entry);
            ((classified.obj, classified.gen), classified)
        })
        .collect()
}

/// Queries and statistics for classified objects
pub struct ClassificationStats {
    pub total_objects: usize,
    pub by_type: HashMap<PdfObjectType, usize>,
    pub by_role: HashMap<ObjectRole, usize>,
    pub suspicious_objects: usize,
    pub executable_objects: usize,
}

impl ClassificationStats {
    /// Computes statistics from a classification map
    pub fn from_classifications(classifications: &ClassificationMap) -> Self {
        let mut by_type: HashMap<PdfObjectType, usize> = HashMap::new();
        let mut by_role: HashMap<ObjectRole, usize> = HashMap::new();
        let mut suspicious_objects = 0;
        let mut executable_objects = 0;

        for classified in classifications.values() {
            *by_type.entry(classified.obj_type).or_insert(0) += 1;

            for role in &classified.roles {
                *by_role.entry(*role).or_insert(0) += 1;
            }

            if classified.is_suspicious() {
                suspicious_objects += 1;
            }

            if classified.is_executable() {
                executable_objects += 1;
            }
        }

        Self {
            total_objects: classifications.len(),
            by_type,
            by_role,
            suspicious_objects,
            executable_objects,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_classification() {
        assert_eq!(PdfObjectType::Catalog.as_str(), "catalog");
        assert!(PdfObjectType::Catalog.is_container());
        assert!(PdfObjectType::Action.is_executable());
        assert!(!PdfObjectType::Stream.is_executable());
    }

    #[test]
    fn test_object_role_classification() {
        assert_eq!(ObjectRole::JsContainer.as_str(), "js_container");
        assert!(ObjectRole::JsContainer.is_suspicious());
        assert!(!ObjectRole::FormField.is_suspicious());
    }

    #[test]
    fn test_classified_object() {
        let mut obj = ClassifiedObject::new(1, 0, PdfObjectType::Action);
        assert!(!obj.has_role(ObjectRole::JsContainer));

        obj.add_role(ObjectRole::JsContainer);
        assert!(obj.has_role(ObjectRole::JsContainer));
        assert!(obj.is_suspicious());
        assert!(obj.is_executable());
    }
}
