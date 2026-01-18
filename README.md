# Putting Ring-Signatures to praxis: Create a Webapp to anonymously (Ring-)Sign Messages
[cite_start]**Bachelor-Project by: Tom Pfirsig** [cite: 2] | [cite_start]**Date:** 08.10.2025 [cite: 3]

---

## 1. About this Project
[cite_start]In this Bachelor-Project, I implemented the Ring Signature by Ronald L. Rivest, Adi Shamir, and Yael Tauman as described in the paper "How to leak a secret"[cite: 5].

* [cite_start]**Framework:** The project uses the Django-Framework for its Python base and simple database organization[cite: 6].
* [cite_start]**Data Privacy:** Although first drafts used a database, the final product does not, to ensure that stored data cannot compromise anonymity[cite: 7, 9].
* [cite_start]**Anonymity:** To protect connections, the project can be hosted within the Tor network[cite: 10]. [cite_start]The algorithm itself ensures mathematical anonymity[cite: 11].
* [cite_start]**Implementation:** Signing and verification logic is located in `views.py` with detailed comments[cite: 11].

## 2. Features
* [cite_start]Signing using the RSA 1024/2048/4096 cryptosystems[cite: 13].
* [cite_start]Verification of existing signatures[cite: 14].
* [cite_start]Public Key lookup via the GitHub API[cite: 15].
* [cite_start]Support for signing PDF files[cite: 18].
* [cite_start]Deployment in the Tor network for server-side anonymity[cite: 17].

## 3. Installation
1. [cite_start]**Prerequisites:** Ensure Docker is installed and running[cite: 20].
2. [cite_start]**Clone the repository:** `git clone https://github.com/tompfi/bp-ring-signing`[cite: 23].
3. [cite_start]**Run Docker:** `docker-compose up --build`[cite: 24].
4. [cite_start]**Access:** Local via `http://localhost:8000` [cite: 26] [cite_start]or via the Tor `.onion` address[cite: 27].

---

## 4. How to sign a message
1. [cite_start]Click **"Create Ring Signature"** on the landing page[cite: 31].
2. [cite_start]Enter a message or upload a **PDF file**[cite: 32].
3. [cite_start]**Add Ring Members:** Use the GitHub lookup or enter names and RSA public keys (1024/2048/4096) manually[cite: 34, 35, 36].
4. [cite_start]Select the actual Signer[cite: 37].
5. [cite_start]Click **"Create Signature"**[cite: 38].

## 5. How to verify a message
1. [cite_start]Click **"Verify Ring Signature"**[cite: 40].
2. [cite_start]Provide the original message or the signed PDF file[cite: 41].
3. [cite_start]Enter the **Glue Value (v)**[cite: 42].
4. [cite_start]Enter the **X-Values** (one per line or comma-separated)[cite: 43].
5. [cite_start]Provide all Public Keys in PEM format and click **"Verify"**[cite: 44, 45].

---

## 6. Mathematical Foundations
### 7.1 Requirements
* [cite_start]For every member, a public key is required; the signer also needs their private key[cite: 62].
* [cite_start]All keys must belong to the RSA system[cite: 63, 64].
* [cite_start]Symmetric encryption: $E_{k}(x) = (x + k) \mod 2^{128}$[cite: 65, 85].

### 7.2 Terminology
* [cite_start]**Signature:** $\sigma = (P_{1}, \dots, P_{r}; v; x_{1}, \dots, x_{r})$[cite: 67].
* **X-Values:** Signature components. [cite_start]These are random for non-signers and computed for the signer using their private key[cite: 71, 72].
* [cite_start]**Glue Value (v):** A 128-bit random seed for the combining function[cite: 87, 91].



## 7. The Algorithm
* [cite_start]**Signer's X-value:** Computed by solving the ring equation $C_{k,v}(y_{1}, \dots, y_{n}) = v$[cite: 155].
* [cite_start]**Uniformity:** A target bit length is determined for all X-values so the signer cannot be identified by the length of their value[cite: 143, 145].
* [cite_start]**Combining Function:** Mathematically links all members through nested encryption: $E_{k}(y_{n} \oplus E_{k}(y_{n-1} \dots))$[cite: 192, 196].

---

## 8. Technical Debts
* [cite_start]**Security Risk:** Signers currently must trust the server with their private key[cite: 323].
* [cite_start]**Expansion:** Future support for asymmetric systems other than RSA is needed[cite: 324].
* [cite_start]**Link Verification:** Direct verification via link is currently only in a basic stage[cite: 325].

## 9. Sources
* **[1]** Rivest, R.L., Shamir, A., Tauman, Y. (2006). [cite_start]*How to Leak a Secret*[cite: 328].
* **Fig. 1** Rivest et al. (2001)[cite_start], Page 560[cite: 331].
