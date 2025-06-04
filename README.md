# Quantum Secure Tunneling Protocol (QSTP)

## Introduction

[![Build](https://github.com/QRCS-CORP/QSTP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/QSTP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/QSTP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/QSTP/actions/workflows/codeql-analysis.yml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSTP/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/QSTP/security/policy)
[![License: Private](https://img.shields.io/badge/License-Private-blue.svg)](https://github.com/QRCS-CORP/QSTP/blob/main/QRCS-PL%20License.txt)  

QSTP is a next-generation cryptographic protocol designed to enable secure communication between clients and servers by establishing an encrypted tunnel using a root trust anchor. Unlike traditional key exchange protocols (e.g., TLS, PGP, SSH) that are components of larger systems, QSTP provides a complete specification that integrates a key exchange function, robust authentication mechanisms, and an encrypted tunnel within a single protocol.

Engineered to address the challenges posed by quantum computing threats, QSTP introduces entirely new mechanisms—designed from the ground up for both security and performance in a post-quantum context. This design avoids the legacy issues of backward compatibility, complex versioning, and outdated APIs.

[QSTP Help Documentation](https://qrcs-corp.github.io/QSTP/)  
[QSTP Protocol Specification](https://qrcs-corp.github.io/QSTP/pdf/QSTP_Specification.pdf)  
[QSTP Summary Document](https://qrcs-corp.github.io/QSTP/pdf/QSTP_Summary.pdf)  

## Cryptographic Primitives

QSTP employs state-of-the-art cryptographic algorithms to deliver strong security:

- **Asymmetric Ciphers:**  
  QSTP supports either **Kyber** or **McEliece** as its key encapsulation mechanisms.

- **Digital Signatures:**  
  The protocol uses the asymmetric signature schemes **Dilithium** or **Sphincs+** for signing.

- **Symmetric Cipher:**  
  QSTP utilizes the Rijndael-based Cryptographic Stream (RCS) cipher. This cipher is enhanced with:
  - Uses the wide-block form of Rigndael with a 256-bit state.
  - An increased number of rounds
  - A cryptographically strong key schedule
  - Integrated AEAD authentication via post-quantum secure KMAC or QMAC

## QSTP Key Exchange

The key exchange in QSTP follows a three-party, one-way trust model in which the client trusts the server based on certificate authentication provided by a root domain security server (RDS). A single shared secret is securely exchanged between the server and the client, which is then used to create an encrypted tunnel.

Key features include:

- **Efficiency:**  
  The QSTP exchange is fast and lightweight, providing 256-bit post-quantum security to protect against future quantum-based threats.

- **Versatility:**  
  QSTP is suitable for applications such as:
  - Client registration on networks
  - Secure cloud storage
  - Hub-and-spoke model communications
  - Commodity trading
  - Electronic currency exchange

- **Scalability:**  
  The QSTP server is implemented as a multi-threaded communications platform capable of generating a uniquely keyed encrypted tunnel for each connected client. With a lightweight state footprint of less than 4 kilobytes per client, a single server can handle potentially hundreds of thousands of simultaneous connections.  
  The cipher encapsulation keys used in each exchange are ephemeral and unique, ensuring each key exchange remains secure and independent of previous sessions.

- **Certificate Management:**  
  The root domain security server (RDS) distributes a public signature verification certificate to every client in its domain. This certificate is used to authenticate the QSTP server's signed public certificate, which in turn is used to verify signed messages from the server to the client. This robust certificate management establishes a chain of trust that is crucial for verifying identities and securing the key exchange process.

## Compilation

QSTP uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building QSTP library and the Client/Root/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the Server and Client projects: QSTP, Root, Server, and Client.
Extract the files, and open the Server and Client projects. The QSTP library has a default location in a folder parallel to the Server, Root, and Client project folders.  
The server, root, and client projects additional files folder are set to: **$(SolutionDir)..\QSTP\QSTP** and **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to server/client project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **[server/root/client]->References** property contains a reference to the QSTP library, and that the QSTP library contains a valid reference to the QSC library.  
QSC and QSTP support every AVX instruction family (AVX/AVX2/AVX-512).  
Set the QSC and QSTP libries and every server/client project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and QSTP to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), build the QSTP library, then build the Server and Client projects.

#### MacOS / Ubuntu (Eclipse)

The QSC and the QSTP library projects, along with the Server, Root, and Client projects have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu\[project-name]** folder to the folder containing the project's header and implementation files on QSTP, Server, Root, and Client projects.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'. Repeat for every additional project.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, but are set to use AVX2, AES-NI, and RDRand by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


## Conclusion

By integrating cutting-edge cryptographic primitives, an efficient key exchange mechanism, and robust certificate management, QSTP provides flexible, high-performance, and quantum-resistant security for networked communications. It represents a significant leap forward over legacy protocols, offering strong post-quantum security without the complexity and limitations of older systems.

## Cryptographic Dependencies

QSTP relies on the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) for its underlying cryptographic functions.

## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact:
john.underhill@protonmail.com  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and QSTP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. 2025._

