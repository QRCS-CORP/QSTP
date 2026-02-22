# Quantum Secure Tunneling Protocol V1.4 (QSTP)

## Introduction

[![Build](https://github.com/QRCS-CORP/QSTP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/QSTP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/QSTP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/QSTP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/qstp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/qstp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSTP/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/QSTP/security/policy)
[![License: Private](https://img.shields.io/badge/License-Private-blue.svg)](https://github.com/QRCS-CORP/QSTP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSTP)](https://github.com/QRCS-CORP/QSTP/releases/tag/2025-06-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/QSTP.svg)](https://github.com/QRCS-CORP/QSTP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Financial/Defense&color=brightgreen)](#)

**QSTP** is a post-quantum secure tunneling protocol that integrates key exchange, authentication, and encrypted communications into a single, self-contained specification. Engineered from the ground up to address the cryptographic challenges posed by quantum computing, QSTP avoids the design compromises and legacy constraints of protocols such as TLS, SSH, and PGP. There is no algorithm negotiation, no versioning attack surface, and no backward compatibility with classical-only primitives.

---

## Documentation

| Resource | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/QSTP/) | Full API and usage reference |
| [Summary Document](https://qrcs-corp.github.io/QSTP/pdf/qstp_summary.pdf) | Protocol overview and design rationale |
| [Protocol Specification](https://qrcs-corp.github.io/QSTP/pdf/qstp_specification.pdf) | Complete formal protocol definition |
| [Formal Analysis](https://qrcs-corp.github.io/QSTP/pdf/qstp_formal.pdf) | Security proofs and formal verification |
| [Implementation Analysis](https://qrcs-corp.github.io/QSTP/pdf/qstp_analysis.pdf) | Implementation security considerations |
| [Integration Guide](https://qrcs-corp.github.io/QSTP/pdf/qstp_integration.pdf) | Deployment and integration instructions |

---

## Overview

QSTP establishes an encrypted tunnel between a client and server using a three-party, root-anchored trust model. A **Root Domain Security Server (RDS)** acts as the certificate authority, issuing signed certificates to servers and distributing its public verification certificate to all clients in the domain. Clients authenticate servers against the root certificate before any key material is exchanged, providing strong identity assurance prior to the handshake.

The protocol is complete and self-contained. It does not depend on external PKI infrastructure, certificate revocation services, or runtime algorithm negotiation. All cryptographic parameters are fixed at compile time for a given configuration, eliminating downgrade attacks and cipher-suite confusion by construction.

### Key Properties

- **Post-quantum security** — all asymmetric operations use NIST-standardized post-quantum algorithms
- **Transcript binding** — session keys are derived from a running hash of the complete protocol transcript, cryptographically committing them to every exchanged message
- **Forward secrecy** — ephemeral encapsulation keys are generated per-session and securely destroyed immediately after use
- **Explicit key confirmation** — the server's final transcript hash is sent to the client; the session is not established unless both parties hold an identical transcript
- **Minimal attack surface** — no algorithm negotiation, no fallback cipher paths, no protocol versioning surface
- **MISRA-C aligned** — structured for deployment in safety-critical and high-assurance environments

---

## Cryptographic Primitives

QSTP is built exclusively on algorithms from the NIST Post-Quantum Cryptography standardization process and NIST FIPS standards.

### Key Encapsulation (KEM)

| Algorithm | NIST Security Level | Standard |
|---|---|---|
| ML-KEM (Kyber) | 1 / 3 / 5 | NIST FIPS 203 |
| Classic McEliece | 1 / 3 / 5 | NIST PQC Selected |

Encapsulation keys are ephemeral — a fresh key pair is generated for every session and the private key is destroyed immediately after decapsulation.

### Digital Signatures

| Algorithm | NIST Security Level | Standard |
|---|---|---|
| ML-DSA (Dilithium) | 2 / 3 / 5 | NIST FIPS 204 |

Dilithium is used to authenticate the server's ephemeral public encapsulation key during the handshake and to sign the root and server certificates offline.

### Symmetric AEAD Cipher

Two AEAD cipher options are supported, selectable at compile time:

| Cipher | Construction | Authentication |
|---|---|---|
| **RCS** (Rijndael Cryptographic Stream) | Wide-block Rijndael, 256-bit state, increased rounds, strengthened key schedule | KMAC or QMAC (post-quantum secure) |
| **AES-256-GCM** | AES-256 in Galois/Counter Mode | GHASH |

RCS is the recommended option for post-quantum deployments. It operates on a 256-bit wide Rijndael state with a cryptographically strengthened key schedule and integrates authentication natively via post-quantum secure KMAC or QMAC, requiring no separate MAC computation.

AES-256-GCM is provided for environments requiring interoperability with existing hardware acceleration or compliance requirements.

### Hash and Key Derivation

| Primitive | Algorithm | Purpose |
|---|---|---|
| Hash | SHA3-256 (Keccak) | Certificate binding, transcript hashing |
| KDF | cSHAKE-256 | Session key derivation from shared secret and transcript |

---

## Key Exchange Protocol

The QSTP handshake is a three-round authenticated key exchange between client and server, with the root domain security server participating offline through certificate issuance.

### Trust Model
```
Root Domain Security Server (RDS)
        │
        │  Signs server certificate (offline)
        ▼
    QSTP Server ──── presents signed certificate ────► Client
                                                          │
                                               Authenticates server using
                                               root public certificate
```

The client holds only the root public verification certificate. It uses this to authenticate the server's certificate, which in turn authenticates the server's ephemeral encapsulation key for the current session.

### Exchange Sequence
```
Legend:
  C        = Client
  S        = Server
  H        = SHA3-256
  KEM      = Key Encapsulation Mechanism
  SIG      = Dilithium Signature
  cSHAKE   = Customizable SHAKE-256 KDF
  sch      = Running transcript hash
  phdr     = Serialized packet header
  pk_kem   = Ephemeral public encapsulation key

Round 1  C → S :  serial || cfg
                  sch₀ = H(cfg || serial || root_verkey)

Round 2  S → C :  SIG(H(phdr || sch₀ || pk_kem)) || pk_kem
                  sch₁ = H(sch₀ || H(phdr || sch₀ || pk_kem))

Round 3  C → S :  KEM_Encaps(pk_kem) → ciphertext || secret
                  sch₂ = H(sch₁ || ciphertext)
                  session_keys = cSHAKE(secret, sch₂)

Confirm  S → C :  sch₂
                  C verifies sch₂ matches local transcript
                  Session established only on exact match
```

Session keys are derived from `cSHAKE(shared_secret, transcript_hash)`, binding them cryptographically to the complete protocol exchange. The server transmits its final transcript hash as an explicit key confirmation — a mismatch immediately terminates the connection on both sides before any application data is processed.

### Security Properties

| Property | Mechanism |
|---|---|
| Server authentication | Root-signed certificate verified before key exchange begins |
| Forward secrecy | Ephemeral KEM keys generated per-session, destroyed after decapsulation |
| Transcript integrity | SHA3-256 running hash commits every protocol message into derived keys |
| Key confirmation | Server returns transcript hash; client verifies before accepting session |
| Replay resistance | Per-session ephemeral keys with packet sequence number validation |
| Downgrade resistance | No algorithm negotiation; all parameters fixed at compile time |

---

## Applications

QSTP is well-suited for any environment requiring strong mutual authentication and encrypted communications, particularly where quantum-era adversaries must be considered:

- Client registration and onboarding on managed networks
- Secure cloud storage access
- Hub-and-spoke enterprise communications
- Financial services: commodity trading and electronic currency exchange
- Defense and government classified communications
- IoT device provisioning and secure telemetry

---

## Performance and Scalability

The QSTP server is implemented as a multi-threaded platform capable of maintaining a uniquely keyed encrypted tunnel for each connected client. The per-client connection state is under 4 kilobytes, enabling a single server instance to sustain hundreds of thousands of simultaneous connections. Ephemeral encapsulation keys are generated and destroyed within each exchange, ensuring complete session isolation with no shared key material between connections.

---

## Compilation

QSTP uses the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) — a standalone, portable, MISRA-aligned cryptographic library written in C23. QSC supports platform-optimized builds across Windows, macOS, and Linux, with hardware acceleration for AES-NI, AVX2/AVX-512, and RDRAND where available.

### Prerequisites

| Tool | Requirement |
|---|---|
| CMake | 3.15 or newer |
| Windows | Visual Studio 2022 or newer |
| macOS | Clang via Xcode or Homebrew |
| Linux | GCC or Clang |
| Dependency | [QSC Library](https://github.com/QRCS-CORP/QSC) |

---

### Windows (MSVC)

The Visual Studio solution contains four projects: **QSTP** (library), **Root**, **Server**, and **Client**. The QSTP library is expected in a folder parallel to the Root, Server, and Client project folders.

> **Critical:** The `Enable Enhanced Instruction Set` property must be set to the **same value** across the QSC library, the QSTP library, and every application project (Root, Server, Client) in both Debug and Release configurations. Mismatched intrinsics settings produce ABI-incompatible struct layouts and are a source of undefined behavior.

**Build order:**
1. Build the **QSC** library
2. Build the **QSTP** library
3. Build **Root**, **Server**, and **Client**

**Include path configuration:**
If the library files are not at their default locations, update the include paths in each project under:
`Configuration Properties → C/C++ → General → Additional Include Directories`

Default paths:
- `$(SolutionDir)QSTP`
- `$(SolutionDir)..\QSC\QSC`

Ensure each application project's **References** property includes the QSTP library, and that the QSTP library references the QSC library.

#### Local Protocol Test (Visual Studio)
```
1. Right-click QSTP Root → Debug → Start New Instance
   root> generate <days>
   Note the certificate path.

2. Right-click QSTP Server → Debug → Start New Instance
   Paste the root certificate path when prompted.
   The server generates its key pair. Note the server certificate path.
   Close the Server console.

3. In the Root console:
   root> sign C:\Users\<username>\Documents\QSTP\Server\qstp_<computername>.qrc
   Close the Root console.

4. Reopen the QSTP Server console.
   server> waiting for a connection

5. Right-click QSTP Client → Debug → Start New Instance
   Enter address: 127.0.0.1
   Enter root certificate path when prompted.
   Enter server certificate path when prompted.
   The client is now connected over a post-quantum secure channel.
   Messages typed in the client are echoed back by the server.
```

---

### macOS / Linux (Eclipse)

The QSC and QSTP library projects, along with the Root, Server, and Client projects, have been tested with the Eclipse IDE on Ubuntu and macOS.

Eclipse project files (`.project`, `.cproject`, `.settings`) are located in platform-specific subdirectories under the `Eclipse` folder. Copy the files from `Eclipse/Ubuntu/<project-name>` or `Eclipse/MacOS/<project-name>` directly into the folder containing each project's source files.

To create a project in Eclipse: select **C/C++ Project → Create an empty project** and use the same name as the source folder. Eclipse will load all settings automatically. Repeat for each project. GCC and Clang project files differ — select the set that matches your platform.

The default Eclipse projects are configured with no enhanced instruction extensions. Add flags as needed for your target hardware.

#### Compiler Flag Reference

**AVX (256-bit FP/SIMD)**
```
-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2
```
| Flag | Purpose |
|---|---|
| `-msse2` | Baseline x86_64 SSE2 |
| `-mavx` | 256-bit FP/SIMD |
| `-maes` | AES-NI hardware acceleration |
| `-mpclmul` | Carry-less multiply (GHASH) |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | Bit manipulation (PEXT/PDEP) |

**AVX2 (256-bit integer SIMD)**
```
-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2
```
| Flag | Purpose |
|---|---|
| `-mavx2` | 256-bit integer and FP SIMD |
| *(others as above)* | |

**AVX-512 (512-bit SIMD)**
```
-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -maes -mpclmul -mrdrnd -mbmi2
```
| Flag | Purpose |
|---|---|
| `-mavx512f` | 512-bit Foundation instructions |
| `-mavx512bw` | 512-bit byte/word integer operations |
| `-mvaes` | Vector-AES in 512-bit registers |
| *(others as above)* | |

---

## Cryptographic Dependencies

QSTP depends on the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) for all underlying cryptographic operations, including post-quantum primitives, symmetric ciphers, hash functions, and random number generation.

---

## License

> **Investment Inquiries:**  
> QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment are invited to contact us at [contact@qrcscorp.ca](mailto:contact@qrcscorp.ca) or visit [https://www.qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of our products and services.

> **Patent Notice:**  
> One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

**License and Use Notice (2025–2026)**

This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation (QRCS) for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.

All source code and materials in this repository are provided under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**, unless explicitly stated otherwise.

This license permits non-commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.

For licensing inquiries, supported implementations, or commercial use, contact: [licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca)

*Quantum Resistant Cryptographic Solutions Corporation, 2026. All rights reserved.*