use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "zplfmt", version)]
#[command(about = "Format ZPL source")]
struct Cli {
    /// Path to the ZPL file to format.
    #[arg(value_name = "ZPL_FILE")]
    zpl: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let source = fs::read_to_string(cli.zpl)?;
    print!("{}", zplc::format::format_zpl(&source));
    Ok(())
}
