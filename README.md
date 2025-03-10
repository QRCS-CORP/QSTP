# Quantum Secure Tunneling Protocol (QSTP)

## Introduction

QSTP is a next-generation cryptographic protocol designed to enable secure communication between clients and servers by establishing an encrypted tunnel using a root trust anchor. Unlike traditional key exchange protocols (e.g., TLS, PGP, SSH) that are components of larger systems, QSTP provides a complete specification that integrates a key exchange function, robust authentication mechanisms, and an encrypted tunnel within a single protocol.

Engineered to address the challenges posed by quantum computing threats, QSTP introduces entirely new mechanisms—designed from the ground up for both security and performance in a post-quantum context. This design avoids the legacy issues of backward compatibility, complex versioning, and outdated APIs.

[View full documentation online](https://qrcs-corp.github.io/QSTP/)

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

## Conclusion

By integrating cutting-edge cryptographic primitives, an efficient key exchange mechanism, and robust certificate management, QSTP provides flexible, high-performance, and quantum-resistant security for networked communications. It represents a significant leap forward over legacy protocols, offering strong post-quantum security without the complexity and limitations of older systems.

## Cryptographic Dependencies

QSTP relies on the [QSC Cryptographic Library](https://github.com/QRCS-CORP/QSC) for its underlying cryptographic functions.

## License

QRCS-PL private License. See license file for details.  
Software is copyrighted and QSTP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
All rights reserved by QRCS Corp. 2025.

