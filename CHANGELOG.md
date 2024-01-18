# Changelog

All notable changes to this project will be documented in this file.  
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).  
_NOTE: This changelog is generated and managed by [devtools-cli](https://pypi.org/project/devtools-cli/), **do not edit manually**._


### [0.2.0] - 2024-01-19 - _latest_

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

[0.2.0]: https://github.com/aabmets/quantcrypt/compare/0.1.3...0.2.0
[0.1.3]: https://github.com/aabmets/quantcrypt/compare/0.1.0...0.1.3