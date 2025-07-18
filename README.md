# Crypto Messaging System

A secure, privacy-focused messaging system that uses layered cryptographic techniques and mix networks to anonymize message transmission.

---

## Project Overview

This project implements a multi-hop encrypted messaging system inspired by mix networks. Messages are encrypted in multiple layers using a combination of symmetric (AES/Fernet) and asymmetric (RSA) encryption. Each intermediate node (mix server) decrypts a single layer, revealing the next hop address, and forwards the message in a randomized order to obscure traffic analysis and enhance sender anonymity.

At the final destination, the message is decrypted using a symmetric key derived from a shared password and salt, ensuring confidentiality and integrity throughout the transmission.

The system demonstrates key cryptographic concepts including layered encryption, key derivation, message mixing, and anonymized routing.

---

## Key Features

- **Layered Encryption:** Messages are wrapped in successive RSA encryptions for each mix server along the route.
- **Symmetric Encryption:** Actual message content is encrypted with AES via Fernet, with keys derived from passwords.
- **Mix Network:** Multiple mix servers forward messages in randomized order to break traceability.
- **Secure Key Handling:** Generation and usage of RSA key pairs for encryption/decryption.
- **Multi-threaded Server:** Mix servers handle multiple clients concurrently, ensuring efficient message routing.

---

## Usage

The system requires setup of mix servers, message senders, and receivers. Using provided scripts and configuration files, the network can be launched to send anonymized encrypted messages across multiple hops.

---

## Disclaimer

This project is an educational prototype and not intended for production use. Security features like certificate verification, replay protection, and secure key storage are minimal.
