use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
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
        #[arg(
            short, long
        )]
        input: PathBuf,
        #[arg(
            short,
            long,
            default_value = "rules_imported"
        )]
        output: PathBuf,
        #[arg(
            short, long
        )]
        dir: bool,
    },
    ExportAlerts {
        #[arg(
            short,
            long,
            default_value = "json"
        )]
        format: ExportFormat,
        #[arg(
            short, long
        )]
        output: Option<PathBuf>,
        #[arg(
            short,
            long,
            default_value = "100"
        )]
        limit: u32,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    Csv,
    Json,
}

#[derive(Serialize)]
struct AlertRow {
    id: String,
    rule_id: String,
    risk_score: i64,
    severity: i64,
    state: i64,
    created_at: String,
    updated_at: String,
    acknowledged_by: Option<String>,
    acknowledged_at: Option<String>,
    events: String,
    ai_summary: Option<String>,
}

impl AlertRow {
    fn csv_header() -> &'static str {
        "id,rule_id,risk_score,severity,state,created_at,updated_at,acknowledged_by,acknowledged_at,events,ai_summary"
    }

    fn to_csv_row(&self) -> String {
        let escape = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
        format!(
            "{},{},{},{},{},{},{},{},{},{},{}",
            escape(&self.id),
            escape(&self.rule_id),
            self.risk_score,
            self.severity,
            self.state,
            escape(&self.created_at),
            escape(&self.updated_at),
            self.acknowledged_by
                .as_deref()
                .map(escape)
                .unwrap_or_default(),
            self.acknowledged_at
                .as_deref()
                .map(escape)
                .unwrap_or_default(),
            escape(&self.events),
            self.ai_summary.as_deref().map(escape).unwrap_or_default(),
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ImportSigma { input, output, dir } => {
            if dir {
                let rules = sentinel_sigma::import_sigma_dir(&input.to_string_lossy())?;
                std::fs::create_dir_all(&output)?;
                for rule in &rules {
                    let filename =
                        format!("{}/{}.yaml", output.display(), rule.rule.id.replace("sigma-", ""));
                    let yaml = serde_yaml::to_string(&rule)?;
                    std::fs::write(&filename, yaml)?;
                    println!("Imported: {}", filename);
                }
                println!("Imported {} rules to {}", rules.len(), output.display());
            } else {
                let rule = sentinel_sigma::import_sigma_file(&input.to_string_lossy())?;
                std::fs::create_dir_all(&output)?;
                let filename =
                    format!("{}/{}.yaml", output.display(), rule.rule.id.replace("sigma-", ""));
                let yaml = serde_yaml::to_string(&rule)?;
                std::fs::write(&filename, yaml)?;
                println!("Imported 1 rule to {}", filename);
            }
        },

        Commands::ExportAlerts { format, output, limit, state, db } => {
            let db_path = db
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(default_db_path);

            if !std::path::Path::new(&db_path).exists() {
                anyhow::bail!(
                    "Database not found at {}. Start sentinel-core-service first to collect data.",
                    db_path
                );
            }

            let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}?mode=ro", db_path)).await?;

            let mut sql = String::from(
                "SELECT id, rule_id, risk_score, severity, state, created_at, updated_at, \
                 acknowledged_by, acknowledged_at, events, ai_summary \
                 FROM alerts WHERE 1=1",
            );

            if let Some(ref s) = state {
                let state_num: i32 = match s.as_str() {
                    "new" => 0,
                    "acknowledged" => 1,
                    "investigating" => 2,
                    "resolved_true_positive" => 3,
                    "resolved_false_positive" => 4,
                    "suppressed" => 5,
                    _ => return Err(anyhow::anyhow!("Unknown state: {}", s)),
                };
                sql.push_str(&format!(" AND state = {}", state_num));
            }

            sql.push_str(&format!(" ORDER BY created_at DESC LIMIT {}", limit));

            let rows = sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    i64,
                    i64,
                    i64,
                    String,
                    String,
                    Option<String>,
                    Option<String>,
                    String,
                    Option<String>,
                ),
            >(&sql)
            .fetch_all(&pool)
            .await?;

            let alerts: Vec<AlertRow> = rows
                .into_iter()
                .map(
                    |(
                        id,
                        rule_id,
                        risk_score,
                        severity,
                        state,
                        created_at,
                        updated_at,
                        acknowledged_by,
                        acknowledged_at,
                        events,
                        ai_summary,
                    )| {
                        AlertRow {
                            id,
                            rule_id,
                            risk_score,
                            severity,
                            state,
                            created_at,
                            updated_at,
                            acknowledged_by,
                            acknowledged_at,
                            events,
                            ai_summary,
                        }
                    },
                )
                .collect();

            let output_str = match format {
                ExportFormat::Json => serde_json::to_string_pretty(&alerts)?,
                ExportFormat::Csv => {
                    let mut csv = String::from(AlertRow::csv_header());
                    csv.push('\n');
                    for alert in &alerts {
                        csv.push_str(&alert.to_csv_row());
                        csv.push('\n');
                    }
                    csv
                },
            };

            match output {
                Some(path) => {
                    std::fs::write(&path, &output_str)?;
                    println!("Exported {} alerts to {}", alerts.len(), path.display());
                },
                None => {
                    println!("{}", output_str);
                },
            }
        },
    }

    Ok(())
}

fn default_db_path() -> String {
    dirs::data_local_dir()
        .map(|mut p| {
            p.push("sentinel");
            p.push("sentinel.db");
            p.to_string_lossy().to_string()
        })
        .unwrap_or_else(|| "sentinel.db".into())
}
