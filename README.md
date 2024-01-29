# QuantCrypt

<img src="https://raw.githubusercontent.com/aabmets/quantcrypt/main/docs/images/quantcrypt-logo.jpg" alt="Logo" width="500">


[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/quantcrypt)](https://pypi.org/project/quantcrypt/)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/aabmets/quantcrypt/pypi_publish_pipeline.yaml)](https://github.com/aabmets/quantcrypt/actions/workflows/pypi_publish_pipeline.yaml)
[![codecov](https://codecov.io/gh/aabmets/quantcrypt/graph/badge.svg?token=jymcRynp2P)](https://codecov.io/gh/aabmets/quantcrypt)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/quantcrypt)](https://pypistats.org/packages/quantcrypt)


[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)<br/>
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=bugs)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)


### Description

QuantCrypt is a cross-platform Python library for Post-Quantum Cryptography using precompiled PQClean binaries.  
QuantCrypt contains only the **strongest** variants of the PQC algorithms from the [NIST PQC standardization process](https://csrc.nist.gov/projects/post-quantum-cryptography) as recommended by the [CNSA advisory by NSA](https://en.wikipedia.org/wiki/Commercial_National_Security_Algorithm_Suite).


### Motivation

Currently, there does not exist any pure-Python implementation of Post-Quantum Cryptographic algorithms, 
which requires Python developers to first discover where to get reliable C source code of PQC algorithms, 
then install the necessary C compilers on their system and then figure out how to use CFFI to compile and 
use the C code in their Python source code. Furthermore, those binaries would be only compatible with the 
platform that they were compiled on, making it very difficult to use separate platforms for development 
and deployment workflows, without having to recompile the C source code each time.

This library solves this problem by pre-compiling the C source code of PQC algorithms for Windows, Linux and 
Darwin platforms in GitHub Actions using CFFI, and it also provides a nice Python wrapper around the PQC binaries. 
Since I wanted this library to be all-encompassing, it also contains a lot of helper classes which one might need 
when working with Post-Quantum cryptography. This library places a lot of focus on Developer Experience, aiming 
to be powerful in features, yet easy and enjoyable to use, so it would _just work_ for your project.


### Quickstart

The full documentation of this library can be found in the [Wiki](https://github.com/aabmets/quantcrypt/wiki).
Because this library is rich in docstrings which provide detailed insight into the library's behavior, 
it is suggested to use an IDE which supports autocomplete and intellisense when working with this library.


#### Install

```shell
pip install quantcrypt
```

#### Script Imports

```python
from quantcrypt import (
    kem,     # Key Encapsulation Mechanism algos   - public-key cryptography
    dss,     # Digital Signature Scheme algos      - secret-key signatures
    cipher,  # The Krypton Cipher                  - symmetric cipher based on AES-256
    kdf,     # Argon2 helpers + KMAC-KDF           - key derivation functions
    errors,  # All errors QuantCrypt may raise     - also available from other modules
    utils    # Helper utilities from all modules   - gathered into one module
)
```

#### CLI Commands

The general functionality of this library is also available from the command-line, which you can access 
with the `qclib` command. Keep in mind that if you install QuantCrypt into a venv, you will need to activate 
the venv to access the CLI. QuantCrypt uses [Typer](https://typer.tiangolo.com/) internally to provide the CLI experience. 
You can use the `--help` option to learn more about each command and subcommand.

```shell
qclib --help
qclib --info
qclib --version

qclib keygen --help
qclib encrypt --help
qclib decrypt --help
qclib sign --help
qclib verify --help
qclib optimize --help
```

### Security Statement

The PQC algorithms used in this library inherit their security from the [PQClean](https://github.com/PQClean/PQClean) project. 
You can read the security statement of the PQClean project from their [SECURITY.md](https://github.com/PQClean/PQClean/blob/master/SECURITY.md) file. 
To report a security vulnerability for a PQC algorithm, please create an [issue](https://github.com/PQClean/PQClean/issues) in the PQClean repository.


### Credits

This library would be impossible without these essential dependencies:

* [PQClean](https://github.com/PQClean/PQClean) - C source code of Post-Quantum Cryptography algorithms
* [Cryptodome](https://pypi.org/project/pycryptodome/) - AES-256 and SHA3 implementation
* [Argon2-CFFI](https://pypi.org/project/argon2-cffi/) - Argon2 KDF implementation

I thank the creators and maintainers of these libraries for their hard work.
