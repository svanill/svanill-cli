use std::path::PathBuf;
use structopt::StructOpt;


#[derive(Debug, StructOpt)]
#[structopt(name = "svanill-cli", about = "An easily auditable tool to encrypt/decrypt your sensitive data.")]
struct Opt {
    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,
    /// Input file
    #[structopt(name="input file", parse(from_os_str))]
    input: PathBuf,
    /// Output file, stdout if not present
    #[structopt(short="o",parse(from_os_str))]
    output: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
}


#[derive(Debug,StructOpt)]
enum Command {
    ENC {
        /// How many iterations should we do to derive the key
        #[structopt(short = "t", long = "iterations", default_value = "100_000")]
        iterations: u32,
    },
    DEC {},
}

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
}

