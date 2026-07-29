

# QuantCrypt

<img src="https://raw.githubusercontent.com/aabmets/quantcrypt/main/docs/images/quantcrypt-logo.jpg" alt="Logo" width="500">


[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/quantcrypt)](https://pypi.org/project/quantcrypt/)
[![GitHub License](https://img.shields.io/github/license/aabmets/quantcrypt)](https://github.com/aabmets/quantcrypt/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/aabmets/quantcrypt/graph/badge.svg?token=jymcRynp2P)](https://codecov.io/gh/aabmets/quantcrypt)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/aabmets/quantcrypt/pytest-codecov.yml?label=tests)](https://github.com/aabmets/quantcrypt/actions/workflows/pytest-codecov.yml)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/quantcrypt)](https://pypistats.org/packages/quantcrypt)


[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)<br/>
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=bugs)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=aabmets_quantcrypt&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=aabmets_quantcrypt)


## AVISO: Intención de Archivado

Este proyecto se marcará como de solo lectura junto con el proyecto PQClean en julio de 2026.  
Por favor, migre su código a cualquier implementación alternativa, si es que existe alguna para Python.  
Consulte el problema [PQClean/PQClean#604](https://github.com/PQClean/PQClean/issues/604) para obtener más información.

## Descripción

QuantCrypt es una biblioteca de Python multiplataforma para Criptografía Post-Cuántica que utiliza binarios precompilados de PQClean. 
Si bien QuantCrypt contiene múltiples variantes de algoritmos PQC estandarizados por el [NIST](https://csrc.nist.gov/projects/post-quantum-cryptography), 
se recomienda utilizar únicamente las variantes más fuertes, tal como lo aconseja la [recomendación CNSA de la NSA](https://en.wikipedia.org/wiki/Commercial_National_Security_Algorithm_Suite).


## Motivación

Actualmente, no existe ninguna implementación pura en Python de algoritmos de Criptografía Post-Cuántica, 
lo que obliga a los desarrolladores de Python a descubrir primero dónde obtener código fuente confiable en C de algoritmos PQC, 
luego instalar los compiladores C necesarios en su sistema y después averiguar cómo usar CFFI para compilar y 
usar el código C en su código fuente de Python. Además, esos binarios solo serían compatibles con la 
plataforma en la que se compiló, lo que dificulta mucho el uso de plataformas separadas para el desarrollo 
y los flujos de trabajo de implementación, sin tener que recompilar el código fuente C cada vez.

Esta biblioteca resuelve este problema precompilando el código fuente C de los algoritmos PQC para las plataformas Windows, Linux y 
Darwin en GitHub Actions usando CFFI, y también proporciona un buen wrapper (envoltorio) de Python alrededor de los binarios PQC. 
Dado que quería que esta biblioteca fuera integral, también contiene muchas clases auxiliares que uno podría necesitar 
al trabajar con criptografía post-cuántica. Esta biblioteca pone mucho énfasis en la Experiencia del Desarrollador, con el objetivo 
de ser potente en funciones, pero fácil y agradable de usar, para que _simplemente funcione_ en su proyecto.


## Inicio rápido

La documentación completa de esta biblioteca se puede encontrar en la [Wiki](https://github.com/aabmets/quantcrypt/wiki).
Dado que esta biblioteca es rica en docstrings que ofrecen información detallada sobre el comportamiento de la biblioteca, 
se sugiere usar un IDE que soporte autocompletado y sugerencias de código al trabajar con esta biblioteca. 
Las opciones más populares son PyCharm o VS Code con complementos específicos para Python.


### Instalación

Para instalar QuantCrypt con sus dependencias predeterminadas (sin compilador), use uno de los siguientes comandos:

Usando [UV](https://docs.astral.sh/uv/) _(recomendado)_:  
```shell
uv add quantcrypt
```

Usando [Poetry](https://python-poetry.org/docs/): 
```shell
poetry add quantcrypt
```

Usando [pip](https://pip.pypa.io/en/stable/getting-started/):
```shell
pip install quantcrypt
```


Si desea recompilar los binarios PQA en su propia máquina, puede instalar QuantCrypt con 
dependencias opcionales agregando `[compiler]` a uno de los comandos de instalación descritos anteriormente. 

QuantCrypt publica ruedas (wheels) precompiladas con binarios precompilados en el registro de PyPI.
Si su plataforma es compatible con una de las ruedas precompiladas, entonces no necesita instalar 
QuantCrypt con la opción de compilador para poder usar la biblioteca.

_**Nota:**_ Si decide recompilar los binarios PQA, deberá instalar herramientas de compilación `C/C++` específicas de la plataforma como [Visual Studio](https://visualstudio.microsoft.com/), [Xcode](https://developer.apple.com/xcode/) o 
[GNU Make](https://www.gnu.org/software/make/) _(lista no exhaustiva)_.

_**Nota:**_ Si intenta importar el módulo del compilador programáticamente cuando faltan las dependencias opcionales, 
recibirá un error de importación. 


### Importaciones de Script

```python
from quantcrypt import (
    kem,      # Key Encapsulation Mechanism algos   - public-key cryptography
    dss,      # Digital Signature Scheme algos      - secret-key signatures
    cipher,   # The Krypton Cipher                  - symmetric cipher based on AES-256
    kdf,      # Argon2 helpers + KMAC-KDF           - key derivation functions
    errors,   # All errors QuantCrypt may raise     - also available from other modules
    utils,    # Helper utilities from all modules   - gathered into one module
    compiler  # Tools for compiling PQA binaries    - requires optional dependencies
)
```

### Comandos CLI

La funcionalidad general de esta biblioteca también está disponible desde la línea de comandos, a la que puede acceder 
con el comando `qclib`. Tenga en cuenta que si instala QuantCrypt en un venv, deberá activar 
el venv para acceder a la CLI. QuantCrypt usa [Typer](https://typer.tiangolo.com/) internamente para proporcionar la experiencia de CLI. 
Puede usar la opción `--help` para obtener más información sobre cada comando y subcomando.

```shell
qclib --help
qclib --version

qclib info --help
qclib keygen --help
qclib encrypt --help
qclib decrypt --help
qclib sign --help
qclib verify --help
qclib remove --help
qclib compile --help
```

_**Nota:**_ El comando CLI `compile` queda disponible cuando QuantCrypt 
ha sido instalado con las dependencias opcionales para el compilador.


## Declaración de Seguridad

Los algoritmos PQC utilizados en esta biblioteca heredan su seguridad del proyecto [PQClean](https://github.com/PQClean/PQClean). 
Puede leer la declaración de seguridad del proyecto PQClean en su archivo [SECURITY.md](https://github.com/PQClean/PQClean/blob/master/SECURITY.md). 
Para informar una vulnerabilidad de seguridad de un algoritmo PQC, por favor cree un [problema (issue)](https://github.com/PQClean/PQClean/issues) en el repositorio de PQClean.


## Créditos

Esta biblioteca sería imposible sin estas dependencias esenciales:

* [PQClean](https://github.com/PQClean/PQClean) - Código fuente en C de algoritmos de Criptografía Post-Cuántica
* [Cryptodome](https://pypi.org/project/pycryptodome/) - Implementación de AES-256 y SHA3
* [Argon2-CFFI](https://pypi.org/project/argon2-cffi/) - Implementación de KDF Argon2

Agradezco a los creadores y mantenedores de estas bibliotecas por su arduo trabajo.
