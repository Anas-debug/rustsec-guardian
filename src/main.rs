use anyhow::Result;
use clap::Parser;
use tracing::info;

mod analyzer;
mod models;
mod scanner;

use analyzer::Analyzer;

/// Supply Chain Intelligence Platform for Rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to Cargo.toml
    #[arg(short, long, default_value = "Cargo.toml")]
    manifest_path: String,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    output: String,

    /// Enable deep scanning
    #[arg(long)]
    deep: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    info!("Starting dependency analysis for: {}", args.manifest_path);

    // Create analyzer
    let analyzer = Analyzer::new(args.manifest_path)?;
    
    // Run analysis
    let analysis = analyzer.analyze().await?;

    // Output results based on format
    match args.output.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&analysis)?),
        _ => {
            println!("\nDependency Analysis Results:");
            println!("==========================");
            println!("Total Dependencies: {}", analysis.total_dependencies);
            
            println!("\nDirect Dependencies:");
            for dep in &analysis.direct_dependencies {
                println!("- {} ({})", dep.name, dep.version);
            }

            if !analysis.security_issues.is_empty() {
                println!("\nSecurity Issues Found:");
                println!("=====================");
                for (package, issues) in &analysis.security_issues {
                    println!("\n{} has {} issues:", package, issues.len());
                    for issue in issues {
                        println!("  - [{}] {}", issue.severity, issue.description);
                        if let Some(fix) = &issue.fix_version {
                            println!("    Fix available in version {}", fix);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
