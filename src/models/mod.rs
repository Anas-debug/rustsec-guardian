use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: String,
    pub is_direct: bool,
    pub features: Vec<String>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SecurityIssue {
    pub severity: Severity,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fix_version: Option<String>,
}
