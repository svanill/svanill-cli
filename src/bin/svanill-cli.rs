use std::path::PathBuf;
use structopt::StructOpt;
use svanill::{encrypt, generate_iv, generate_salt};
extern crate rpassword;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "svanill",
    about = "An easily auditable tool to encrypt/decrypt your sensitive data."
)]
struct Opt {
    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,
    /// Input file
    #[structopt(name = "input file", parse(from_os_str))]
    input: PathBuf,
    /// Output file, stdout if not present
    #[structopt(short = "o", parse(from_os_str))]
    output: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    ENC {
        /// How many iterations should we do to derive the key
        #[structopt(short = "t", long = "iterations", default_value = "100000")]
        iterations: u32,
    },
    DEC {},
}

fn main() {
    let opt = Opt::from_args();

    match opt.cmd {
        Command::ENC { iterations } => {
            let pass1: String = rpassword::read_password_from_tty(Some("Password: ")).unwrap();

            if pass1.is_empty() {
                eprintln!("Error: the password cannot be empty");
                std::process::exit(1);
            }

            let pass2: String =
                rpassword::read_password_from_tty(Some("Confirm Password: ")).unwrap();

            if pass1 != pass2 {
                eprintln!("Error: the two passwords do not match.");
                std::process::exit(2);
            }

            let b_salt = generate_salt();
            let b_iv = generate_iv();
            println!(
                "{}",
                encrypt("XXX TODO content", &pass1, iterations, b_salt, b_iv).unwrap()
            );
        }
        Command::DEC {} => unimplemented!("Decryption is not ready yet."),
    }
}
