#ifndef QSTP_DOXYMAIN_H
#define QSTP_DOXYMAIN_H

/**
 * \mainpage Quantum Secure Tunneling Protocol (QSTP)
 *
 * \section introduction Introduction
 *
 * QSTP is a next-generation cryptographic protocol designed to enable secure communication between clients and servers
 * through the establishment of an encrypted tunnel using a root trust anchor. Unlike traditional key exchange protocols
 * (e.g., TLS, PGP, SSH) that are components of larger systems, QSTP provides a complete specification that integrates a key
 * exchange function, robust authentication mechanisms, and an encrypted tunnel within a single protocol.
 *
 * QSTP is engineered to meet the challenges posed by quantum computing threats. Instead of retrofitting existing
 * protocols with quantum-resistant algorithms, QSTP introduces an entirely new set of mechanisms designed from the
 * ground up for both security and performance in a post-quantum security context. Its design avoids the legacy issues of backwards
 * compatibility, complex versioning, and outdated APIs.
 *
 * \subsection crypto_primitives Cryptographic Primitives
 *
 * QSTP employs state-of-the-art cryptographic algorithms:
 *
 * - **Asymmetric Ciphers:** The protocol supports Kyber or McEliece as its key encapsulation mechanisms.
 * - **Digital Signatures:** It uses the asymmetric signature schemes Dilithium or Sphincs+ for signing.
 * - **Symmetric Cipher:** QSTP uses the Rijndael-based Cryptographic Stream (RCS) cipher, enhanced with an increased number
 *   of rounds, a cryptographically strong key schedule, and integrated AEAD authentication via post-quantum secure KMAC or QMAC.
 *
 * \section key_exchange QSTP Key Exchange
 *
 * The QSTP key exchange is a three-party, one-way trust model in which the client trusts the server based on certificate
 * authentication facilitated by a root domain security server. A single shared secret is securely exchanged between the
 * server and the client, which is then used to create an encrypted tunnel. Designed for efficiency, the QSTP exchange is
 * fast and lightweight, while providing 256-bit post-quantum security to protect against future quantum-based threats.
 *
 * This protocol is versatile and can be used in a wide range of applications, such as:
 *
 * - Client registration on networks
 * - Secure cloud storage
 * - Hub-and-spoke model communications
 * - Commodity trading
 * - Electronic currency exchange
 *
 * The QSTP server is built as a multi-threaded communications platform capable of generating a uniquely keyed encrypted
 * tunnel for each connected client. With a lightweight state footprint of less than 4 kilobytes per client, a single
 * server can handle potentially hundreds of thousands of simultaneous connections. The cipher encapsulation keys
 * used during each key exchange are ephemeral and unique, ensuring that every key exchange remains secure and independent
 * from previous exchanges.
 *
 * The root domain security server (RDS) distributes a public signature verification certificate to every
 * client in its domain. This certificate is used to authenticate the QSTP application server's signed public certificate,
 * and the server's certificate is subsequently used to verify signed messages from the server to the client.
 *
 * A key aspect of QSTP is its robust certificate management. A root security server serves as the trust anchor by
 * signing certificates that authenticate application servers. This chain of trust is crucial for verifying
 * identities and securing the key exchange process.
 *
 * \section conclusion Conclusion
 *
 * By integrating cutting-edge cryptographic primitives, an efficient key exchange mechanism, and robust certificate
 * management, QSTP provides flexible, high-performance, and quantum-resistant security for networked communications.
 * It represents a significant leap forward over legacy protocols, offering strong post-quantum security without the
 * complexity and limitations of older systems.
 *
 * \subsection library_dependencies Cryptographic Dependencies
 *
 * QSTP relies on the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 *
 * \section license_sec License
 *
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 *
 * \author John G. Underhill
 * \date 2025-02-10
 */


#endif