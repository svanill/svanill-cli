extern crate rpassword;

use std::path::PathBuf;
use structopt::StructOpt;
use svanill::crypto::{decrypt, encrypt};
use svanill::proc_utils::attempt_to_lock_memory;

#[cfg(not(debug_assertions))]
use svanill::proc_utils::disable_core_dump;

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
    attempt_to_lock_memory();

    #[cfg(not(debug_assertions))]
    disable_core_dump().unwrap();

    let opt = Opt::from_args();

    let content: String = std::fs::read_to_string(opt.input).unwrap_or_else(|e: std::io::Error| {
        eprintln!("Couldn't read the input file: error was: {}", e);
        std::process::exit(1);
    });

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

            println!("{}", encrypt(&content, &pass1, iterations).unwrap());
        }
        Command::DEC {} => {
            let pass: String = rpassword::read_password_from_tty(Some("Password: ")).unwrap();

            match decrypt(&content, &pass) {
                Ok(plaintext) => {
                    println!("{}", plaintext);
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
