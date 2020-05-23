![Continuous integration](https://github.com/svanill/svanill-cli/workflows/Continuous%20integration/badge.svg)

# Svanill (cli)

A command line tool to encrypt/decrypt your sensitive data.

The resulting data has the same format of [Svanill (web)](https://github.com/svanill/svanill), so you can pass data from one tool to the other.

The sync with an external server is not ready yet, but the plan is to be able to optionally sync with [https://api.svanill.com], as Svanill (web) already allows.

# How to run

```
# encrypt (you will be prompted for the password)
svanill -i <input file> -o <output file> enc

# decrypt (you will be prompted for the password)
svanill -i <input file> -o <output file> dec

# you can omit input/output file, and use stdin/stdout instead
```

If you want to decrypt/open-in-editor/encrypt a file, you may find usefull `svanill-edit`

```
svanill-edit <filename>
```

Beware, to display plaintext in your editor of choice `svanill-edit` will keep a temporary file around, which is removed when the process terminates.

# How to run the tests

```
cargo test
```

# Goals

- have the means to manage secrets
- must be open source
- it must be a standalone program
- it must be portable (Linux, Windows (at least WSL), macOS, ...)
- it must be able to work in a sandboxed environment - no network, no filesystem, no ipc...
- the source code must be easily auditable
- any optional outgoing network requests must send data encrypted client-side

# Non goals

- write the smallest possible file sacrificing documentation or readability
- give the ability to upload to more than one external service at once

# Use cases

- You are using Svanill (web) too and you want to access your secrets using the command line
- You want to easily edit a file with secrets
- You want to share something privately, passing the password on a different channel

# Encryption

Content is secured by a symmetric encryption algorithm, using AES-GCM.

The primitives comes from [ring](https://github.com/briansmith/ring/).

The key is derived using PBKDF2-HMAC-SHA-256, 100.000 iterations (default).

The size of the iv/nonce is 96 bit, randomly generated before any encryption.

The salt is 128 bit long, randomly generated before any encryption.

Random data is obtained from [ring::rand::SystemRandom](https://briansmith.org/rustdoc/ring/rand/struct.SystemRandom.html) (its PRNG is suitable for cryptographic purposes).

Everything but the key is prepended to the ciphertext and thus public.

The data must be secure at rest, so the strength of the key is what matters most.
You should [use the longest passphrase](https://en.wikipedia.org/wiki/Password_strength) you are confident to remember (assuming just english letters and digits, it should be at least 14 characters long - around 72 bit of entropy).

You can get informations about the produced output at [Svanill (web) documentation](https://github.com/svanill/svanill).

To protect against a purposefully crafted high iteration number, which would starve the cpu, Svanill won't attempt to decrypt if that number is higher than what we use to encrypt.

Nothing from decryption is reused for future encryption, to prevent downgrade attacks or blatant compromissions (like reusing the iv).

## Why not...

Most choices depend on the constraints of [Svanill (web) documentation](https://github.com/svanill/svanill).

# F.A.Q.

## Does it work without an Internet connection?

Yes, you could keep a local copy to encrypt/decrypt data (you would not be able to sync online of course).

# License

Svanill, an easily auditable tool to encrypt/decrypt your sensitive data.
Copyright (C) 2017 Riccardo Attilio Galli

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
