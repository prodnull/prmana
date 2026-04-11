//! prmana-evidence-export — local/export-first posture snapshots and evidence bundles.

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};
use pam_prmana::evidence::{
    build_evidence_export_bundle, load_host_posture_snapshot, parse_rfc3339_to_utc,
    render_evidence_events_csv, EvidenceFilter,
};

#[derive(Parser, Debug)]
#[command(name = "prmana-evidence-export")]
#[command(about = "Generate host posture snapshots and evidence exports from prmana state")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Export a local posture snapshot from policy.yaml.
    Posture {
        #[arg(long, default_value = "/etc/prmana/policy.yaml")]
        policy: PathBuf,
    },
    /// Export filtered evidence from the audit log.
    Export {
        #[arg(long, short = 'f', default_value = "/var/log/prmana-audit.log")]
        file: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "event")]
        event_types: Vec<String>,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Json,
    Csv,
}

fn run() -> Result<String, pam_prmana::evidence::EvidenceError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Posture { policy } => load_host_posture_snapshot(&policy).and_then(|snapshot| {
            serde_json::to_string_pretty(&snapshot).map_err(|e| {
                pam_prmana::evidence::EvidenceError::Serialize {
                    target: "posture_json".to_string(),
                    reason: e.to_string(),
                }
            })
        }),
        Command::Export {
            file,
            policy,
            from,
            to,
            event_types,
            format,
        } => {
            let posture = policy
                .map(|path| load_host_posture_snapshot(&path))
                .transpose();

            let mut filter = EvidenceFilter::default();
            if let Some(from) = from.as_deref() {
                filter.from = Some(parse_rfc3339_to_utc(from)?);
            }
            if let Some(to) = to.as_deref() {
                filter.to = Some(parse_rfc3339_to_utc(to)?);
            }
            filter.event_types = event_types.into_iter().collect();

            posture.and_then(|posture| {
                let bundle = build_evidence_export_bundle(&file, &filter, posture)?;
                match format {
                    OutputFormat::Json => serde_json::to_string_pretty(&bundle).map_err(|e| {
                        pam_prmana::evidence::EvidenceError::Serialize {
                            target: "bundle_json".to_string(),
                            reason: e.to_string(),
                        }
                    }),
                    OutputFormat::Csv => Ok(render_evidence_events_csv(&bundle.events)),
                }
            })
        }
    }
}

fn main() {
    match run() {
        Ok(output) => {
            println!("{output}");
        }
        Err(error) => {
            eprintln!("Error: {error}");
            process::exit(1);
        }
    }
}
