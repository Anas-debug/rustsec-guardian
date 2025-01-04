use anyhow::Result;
use cargo_metadata::Package;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{SecurityIssue, Severity};

#[derive(Debug, Serialize)]
pub struct SecurityScan {
    pub issues: Vec<SecurityIssue>,
    pub dependencies: HashMap<String, Vec<SecurityIssue>>,
}

pub struct SecurityScanner {
    patterns: Vec<(Regex, String, Severity)>,
}

impl SecurityScanner {
    pub fn new() -> Result<Self> {
        let patterns = vec![
            // Memory safety patterns
            (
                Regex::new(r"unsafe\s*\{").unwrap(),
                "Contains unsafe blocks - review for memory safety".to_string(),
                Severity::High,
            ),
            (
                Regex::new(r"std::mem::transmute").unwrap(),
                "Uses memory transmutation - potential type safety issues".to_string(),
                Severity::High,
            ),
            // FFI patterns
            (
                Regex::new(r"#!\[no_std\]").unwrap(),
                "No standard library usage - verify safety implementations".to_string(),
                Severity::Medium,
            ),
            (
                Regex::new(r"extern\s*C").unwrap(),
                "FFI usage detected - validate memory safety".to_string(),
                Severity::Medium,
            ),
            // Common vulnerability patterns
            (
                Regex::new(r"eval\s*\(").unwrap(),
                "Code evaluation detected - potential security risk".to_string(),
                Severity::Critical,
            ),
            (
                Regex::new(r"std::process::Command").unwrap(),
                "Process execution capabilities - review for command injection".to_string(),
                Severity::High,
            ),
            // File operation patterns
            (
                Regex::new(r"std::fs::(write|create|remove)").unwrap(),
                "File system modification - review for proper permissions".to_string(),
                Severity::Medium,
            ),
            // Network related patterns
            (
                Regex::new(r"TcpListener::bind").unwrap(),
                "Network listener - verify proper security controls".to_string(),
                Severity::Medium,
            ),
        ];

        Ok(Self { patterns })
    }

    pub fn scan_package(&self, package: &Package) -> Result<Vec<SecurityIssue>> {
        let mut issues = Vec::new();

        // Version checks
        self.check_version(package, &mut issues);
        
        // Dependency checks
        self.check_dependencies(package, &mut issues);
        
        // Build script checks
        self.check_build_scripts(package, &mut issues);

        // Source code analysis
        if let Some(manifest_path) = package.manifest_path.parent() {
            let src_dir = PathBuf::from(manifest_path.as_str()).join("src");
            if src_dir.exists() {
                self.scan_directory(&src_dir, &mut issues)?;
            }
        }

        Ok(issues)
    }

    fn scan_directory(&self, dir: &Path, issues: &mut Vec<SecurityIssue>) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_dir() {
                    self.scan_directory(&path, issues)?;
                } else if let Some(ext) = path.extension() {
                    if ext == "rs" {
                        self.scan_file(&path, issues)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn scan_file(&self, file: &Path, issues: &mut Vec<SecurityIssue>) -> Result<()> {
        let content = fs::read_to_string(file)?;
        
        for (pattern, description, severity) in &self.patterns {
            if pattern.is_match(&content) {
                issues.push(SecurityIssue {
                    severity: severity.clone(),
                    description: format!(
                        "{} in {}",
                        description,
                        file.display()
                    ),
                    affected_versions: vec![],
                    fix_version: None,
                });
            }
        }
        Ok(())
    }

    fn check_version(&self, package: &Package, issues: &mut Vec<SecurityIssue>) {
        if package.version.major == 0 {
            issues.push(SecurityIssue {
                severity: Severity::Low,
                description: format!(
                    "Package {} is pre-1.0 ({}) - API may be unstable",
                    package.name, package.version
                ),
                affected_versions: vec![package.version.to_string()],
                fix_version: None,
            });
        }
    }

    fn check_dependencies(&self, package: &Package, issues: &mut Vec<SecurityIssue>) {
        // Check dependency count
        if package.dependencies.len() > 20 {
            issues.push(SecurityIssue {
                severity: Severity::Low,
                description: format!(
                    "Large number of dependencies ({}) increases attack surface",
                    package.dependencies.len()
                ),
                affected_versions: vec![package.version.to_string()],
                fix_version: None,
            });
        }

        // Check for yanked dependencies
        for dep in &package.dependencies {
            if dep.req.to_string().contains("*") {
                issues.push(SecurityIssue {
                    severity: Severity::High,
                    description: format!(
                        "Wildcard dependency version for {} - security risk",
                        dep.name
                    ),
                    affected_versions: vec![package.version.to_string()],
                    fix_version: None,
                });
            }
        }
    }

    fn check_build_scripts(&self, package: &Package, issues: &mut Vec<SecurityIssue>) {
        if package.targets.iter().any(|t| t.kind.contains(&"custom-build".to_string())) {
            issues.push(SecurityIssue {
                severity: Severity::Medium,
                description: format!(
                    "Package {} contains build scripts - review for security",
                    package.name
                ),
                affected_versions: vec![package.version.to_string()],
                fix_version: None,
            });
        }
    }
}
