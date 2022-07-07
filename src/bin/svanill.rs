extern crate rpassword;

use anyhow::{Context, Result};
use atty::Stream;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
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
    /// Input file, use stdin if not present
    #[structopt(short = "i", name = "input file", parse(from_os_str))]
    input: Option<PathBuf>,
    /// Output file, use stdout if not present
    #[structopt(short = "o", name = "output file", parse(from_os_str))]
    output: Option<PathBuf>,
    #[structopt(subcommand)]
    cmd: Command,
    #[structopt(short = "p", env = "SVANILL_PW", hide_env_values = true)]
    /// Password file
    pw: Option<String>,
    #[structopt(long = "pw-from-file", name = "path")]
    /// Password
    pw_filepath: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
enum Command {
    Enc {
        /// How many iterations should we do to derive the key
        #[structopt(short = "t", long = "iterations", default_value = "100000")]
        iterations: u32,
    },
    Dec {
        /// Maximum number of key iterations we can afford
        #[structopt(short = "m", long = "max-iterations", default_value = "500000")]
        max_iterations: u32,
    },
}

fn main() -> Result<()> {
    let is_memory_locked = attempt_to_lock_memory();

    #[cfg(not(debug_assertions))]
    disable_core_dump().unwrap();

    let opt = Opt::from_args();

    if opt.debug && !is_memory_locked {
        eprintln!("WARN: Couldn't lock memory, it could potentially end up in swap file");
    }

    if !atty::is(Stream::Stdin) && opt.pw.is_none() && opt.pw_filepath.is_none() {
        eprintln!("ERROR: if you pipe data to stdin you must pass the password as command option");
        std::process::exit(1);
    }

    if atty::is(Stream::Stdin) && opt.input.is_none() {
        eprintln!("ERROR: either provide <input file> as arg or pipe data to stdin");
        std::process::exit(1);
    }

    let mut content = Vec::new();

    if let Some(content_path) = opt.input {
        let mut f = File::open(&content_path)
            .with_context(|| format!("Trying to read input file: {:?}", content_path))?;
        f.read_to_end(&mut content)
            .with_context(|| "Couldn't read the input file")?;
    } else {
        std::io::stdin()
            .read_to_end(&mut content)
            .with_context(|| "Couldn't read from STDIN")?;
    }

    let mut need_pw_confirm = false;

    let pass1 = if let Some(pw) = opt.pw {
        pw
    } else if let Some(pw_path) = opt.pw_filepath {
        let pw_f = File::open(&pw_path)
            .with_context(|| format!("Couldn't read password at: {:?}", &pw_path))?;
        let mut pw_f = BufReader::new(pw_f);
        rpassword::read_password_from_bufread(&mut pw_f).unwrap()
    } else {
        need_pw_confirm = true;
        rpassword::prompt_password("Password: ").unwrap()
    };

    match opt.cmd {
        Command::Enc { iterations } => {
            if pass1.is_empty() {
                eprintln!("Error: the password cannot be empty");
                std::process::exit(1);
            }

            if need_pw_confirm {
                let pass2: String = rpassword::prompt_password("Confirm Password: ")?;

                if pass1 != pass2 {
                    eprintln!("Error: the two passwords do not match.");
                    std::process::exit(2);
                }
            }

            let b_encrypted_data = encrypt(&content, &pass1, iterations)?.into_bytes();
            match opt.output {
                Some(path) => File::create(path)?.write_all(&b_encrypted_data)?,
                None => std::io::stdout().write_all(&b_encrypted_data)?,
            }
        }
        Command::Dec { max_iterations } => {
            let b_plaintext = decrypt(&content, &pass1, max_iterations)?;
            match opt.output {
                Some(path) => File::create(path)?.write_all(&b_plaintext)?,
                None => std::io::stdout().write_all(&b_plaintext)?,
            }
        }
    };

    Ok(())
}
