use anyhow::Result;
use cargo_metadata::{MetadataCommand, Package};
use serde::Serialize;
use std::collections::HashMap;
use tracing::info;

use crate::models::{DependencyInfo, SecurityIssue};
use crate::scanner::SecurityScanner;

#[derive(Debug, Serialize)]
pub struct DependencyAnalysis {
    pub total_dependencies: usize,
    pub direct_dependencies: Vec<DependencyInfo>,
    pub dependency_tree: HashMap<String, Vec<String>>,
    pub security_issues: HashMap<String, Vec<SecurityIssue>>,
}

pub struct Analyzer {
    manifest_path: String,
    security_scanner: SecurityScanner,
}

impl Analyzer {
    pub fn new(manifest_path: String) -> Result<Self> {
        Ok(Self {
            manifest_path,
            security_scanner: SecurityScanner::new()?,
        })
    }

    pub async fn analyze(&self) -> Result<DependencyAnalysis> {
        info!("Analyzing dependencies from {}", self.manifest_path);

        let metadata = MetadataCommand::new()
            .manifest_path(&self.manifest_path)
            .exec()?;

        let root_package = metadata
            .root_package()
            .ok_or_else(|| anyhow::anyhow!("No root package found"))?;

        let direct_deps: Vec<DependencyInfo> = root_package
            .dependencies
            .iter()
            .map(|dep| DependencyInfo {
                name: dep.name.clone(),
                version: dep.req.to_string(),
                is_direct: true,
                features: dep.features.clone(),
                dependencies: Vec::new(),
            })
            .collect();

        let mut dep_tree: HashMap<String, Vec<String>> = HashMap::new();
        self.build_dependency_tree(&metadata.packages, &mut dep_tree)?;

        let mut security_issues = HashMap::new();
        for package in &metadata.packages {
            if let Ok(issues) = self.security_scanner.scan_package(package) {
                if !issues.is_empty() {
                    security_issues.insert(package.name.clone(), issues);
                }
            }
        }

        Ok(DependencyAnalysis {
            total_dependencies: metadata.packages.len() - 1,
            direct_dependencies: direct_deps,
            dependency_tree: dep_tree,
            security_issues,
        })
    }

    fn build_dependency_tree(
        &self,
        packages: &[Package],
        tree: &mut HashMap<String, Vec<String>>,
    ) -> Result<()> {
        for package in packages {
            let deps: Vec<String> = package
                .dependencies
                .iter()
                .map(|dep| dep.name.clone())
                .collect();

            tree.insert(package.name.clone(), deps);
        }

        Ok(())
    }
}
