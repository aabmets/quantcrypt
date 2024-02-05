# Changelog

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).  
_NOTE: This changelog is generated and managed by [devtools-cli](https://pypi.org/project/devtools-cli/), **do not edit manually**._


### [0.4.2] - 2024-02-05 - _latest_

- Restored --version and --info options to qclib CLI command

### [0.4.1] - 2024-02-04

- Prettified encrypt and decrypt CLI commands
- Prettified sign and verify CLI commands
- Added pytests for all CLI commands
- FastSphincs and SmallSphincs now generate armored keyfiles  
  without underscores in their names in the keyfile envelopes

### [0.3.4] - 2024-02-04

- Updated PQClean dependency to commit 3b43bc6
- Prettified keygen and optimize CLI command
- Improved --help docs for qclib CLI commands
- Fixed an issue with precompiled binaries Python version

### [0.3.3] - 2024-01-28

- Added security statement to README.md
- KryptonKEM now accepts relative paths as parameter inputs
- KryptonFile now accepts strings and relative paths as parameter inputs
- DSS sign_file and verify_file now accept relative paths as parameter inputs

### [0.3.2] - 2024-01-23

- Updated wiki link

### [0.3.1] - 2024-01-21

- Added sign_file and verify_file methods to BaseDSS class
- Added sign and verify CLI commands

### [0.3.0] - 2024-01-21

- Reduced KryptonKEM memory cost from 2GB to 1GB. This still requires 10^77 GB of memory  
  to brute force all 256 bit combinations, which is astronomically unattainable.
- Improved docstrings across multiple classes, methods and CLI commands.
- KryptonKEM now accepts ASCII armored keys as key argument values for encrypt and decrypt methods.
- Implemented encrypt and decrypt CLI commands.

### [0.2.0] - 2024-01-19

- Added keygen subcommand for qclib CLI
- Implemented the KryptonFile class for file cryptography
- Doubled the memory cost of Argon2 default security parameters
- Argon2 now outputs 64 byte hashes by default
- Implemented the KryptonKEM class which uses asymmetric KEM keys
- Changed KEM keyfile suffixes from .qclib to .qc in CLI keygen subcommand

### [0.1.3] - 2024-01-12

- Added CHANGELOG.md
- Renamed MemSize class in KDF module to MemCost and changed its interface
- Added CLI command `qclib` with options `--info` and `--version`

[0.4.2]: https://github.com/aabmets/quantcrypt/compare/0.4.0...0.4.2
[0.4.0]: https://github.com/aabmets/quantcrypt/compare/0.3.4...0.4.0
[0.3.4]: https://github.com/aabmets/quantcrypt/compare/0.3.3...0.3.4
[0.3.3]: https://github.com/aabmets/quantcrypt/compare/0.3.2...0.3.3
[0.3.2]: https://github.com/aabmets/quantcrypt/compare/0.3.1...0.3.2
[0.3.1]: https://github.com/aabmets/quantcrypt/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/aabmets/quantcrypt/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/aabmets/quantcrypt/compare/0.1.3...0.2.0
[0.1.3]: https://github.com/aabmets/quantcrypt/compare/0.1.0...0.1.3