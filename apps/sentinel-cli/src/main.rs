use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sentinel-cli")]
#[command(about = "Sentinel AI CLI — rule management and utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ImportSigma {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long, default_value = "rules_imported")]
        output: PathBuf,

        #[arg(short, long)]
        dir: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ImportSigma { input, output, dir } => {
            if dir {
                let rules = sentinel_sigma::import_sigma_dir(&input.to_string_lossy())?;
                std::fs::create_dir_all(&output)?;
                let count = rules.len();
                for rule in &rules {
                    let filename = format!(
                        "{}/{}.yaml",
                        output.display(),
                        rule.rule.id.replace("sigma-", "")
                    );
                    let yaml = serde_yaml::to_string(&rule)?;
                    std::fs::write(&filename, yaml)?;
                    println!("Imported: {}", filename);
                }
                println!("Imported {} rules to {}", count, output.display());
            } else {
                let rule = sentinel_sigma::import_sigma_file(&input.to_string_lossy())?;
                std::fs::create_dir_all(&output)?;
                let filename = format!(
                    "{}/{}.yaml",
                    output.display(),
                    rule.rule.id.replace("sigma-", "")
                );
                let yaml = serde_yaml::to_string(&rule)?;
                std::fs::write(&filename, yaml)?;
                println!("Imported 1 rule to {}", filename);
            }
        }
    }

    Ok(())
}
