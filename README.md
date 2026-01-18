# Putting Ring-Signatures to praxis: Create a Webapp to anonymously (Ring-)Sign Messages
[cite_start]**Bachelor-Project by: Tom Pfirsig** **Date:** 08.10.2025 [cite: 2, 3]

---

## 1. About this Project
[cite_start]In this Bachelor-Project, I implemented the Ring Signature by Ronald L. Rivest, Adi Shamir and Yael Tauman as described in the Paper "How to leak a secret"[cite: 5].

* [cite_start]**Framework:** The project uses the Django-Framework due to its use of Python and simple database organization[cite: 6].
* [cite_start]**Data Privacy:** Although the first drafts included a database, the final product does not use one to ensure that stored data cannot compromise anonymity[cite: 7, 9].
* [cite_start]**Anonymity:** To ensure anonymity, the project can be hosted within the Tor network to conceal connections to the server[cite: 10]. [cite_start]The algorithm itself ensures anonymity already[cite: 11].
* [cite_start]**Code:** All relevant code for signing and verification is located in `views.py` with heavy commenting for clarity[cite: 11].

## 2. Features
* [cite_start]Signing using the **RSA 1024/2048/4096** cryptosystem[cite: 13].
* [cite_start]Verifying given signatures[cite: 14].
* [cite_start]**GitHub-API Integration** for simple public key lookups[cite: 15].
* [cite_start]Simple Bootstrap UI with complex error messages to guide the user[cite: 16].
* [cite_start]Hosting inside the **Tor-Network** to ensure connection anonymity[cite: 17].
* [cite_start]Support for uploading a **PDF** as a message to sign[cite: 18].

## 3. How to install
1. [cite_start]**Prerequisites:** Make sure Docker is installed and running[cite: 20].
2. **Clone the repository:**
   ```bash
   git clone [https://github.com/tompfi/bp-ring-signing](https://github.com/tompfi/bp-ring-signing)
   cd bp-ring-signing
   [cite_start]``` [cite: 22, 23]
3. [cite_start]**Run Docker:** `docker-compose up --build` [cite: 24]
4. **Access the application:**
   * [cite_start]**Local:** `http://localhost:8000` [cite: 26]
   * [cite_start]**Tor-Network:** Use a browser that can handle .onion addresses and open the URL found in `bp-ring-signing/tor/hostname`[cite: 27, 28].

---

## 4. How to sign a message
1. [cite_start]On the Landing Page, click on **"Create Ring Signature"**[cite: 31].
2. [cite_start]Write a message in the form field OR upload a **PDF-File**[cite: 32].
3. **Add the Ring Members:**
   * [cite_start]For GitHub users, lookup their username in the "Quick Add from Github" form[cite: 34].
   * [cite_start]Otherwise, manually fill in the form with a Name and Public Key (RSA 1024, 2048, or 4096)[cite: 35, 36].
4. [cite_start]Choose the actual Signer[cite: 37].
5. [cite_start]Click **"Create Signature"**[cite: 38].

## 5. How to verify a message
1. [cite_start]On the Landing Page, click on **"Verify Ring Signature"**[cite: 40].
2. [cite_start]Enter the original message OR upload the same **PDF file** that was signed[cite: 41].
3. [cite_start]Enter the **Glue Value (v)** from the signature[cite: 42].
4. [cite_start]Enter the **X-Values** (signature components), one per line or comma-separated[cite: 43].
5. [cite_start]Enter all **Public Keys** of the ring members in PEM format[cite: 44].
6. [cite_start]Click **"Verify Signature"**[cite: 45].
7. [cite_start]The system will display whether the signature is **VALID** or **INVALID**[cite: 46].

---

## 6. Why Ring Signatures?
[cite_start]Ring signatures allow a user (e.g., a whistleblower) to leak secrets to a journalist without being traced[cite: 49, 51]. Unlike group signatures, ring signatures:
* [cite_start]Can be created from any group without preparatory work or a group manager[cite: 57].
* [cite_start]Are designed so there is no way to break the anonymity of the signature[cite: 58].
* [cite_start]Allow the recipient to verify that the source is trustworthy (part of the ring) without knowing the specific individual[cite: 59].

---

## 7. Mathematical Foundations
### 7.1 Requirements
* [cite_start]A Public Key for every member and the signer's Private Key, all within the same cryptosystem (RSA)[cite: 62, 63, 64].
* [cite_start]Symmetric encryption to link the message to the signature: $E_{k}(x) = (x + k) \mod 2^{128}$, where $k$ is the hash of the message[cite: 65].

### 7.2 Terminology
* [cite_start]**Ring Signature:** $\sigma = (P_{1}, \dots, P_{r}; v; x_{1}, \dots, x_{r})$[cite: 67].
* [cite_start]**Ring:** The group of all members (signer and non-signers)[cite: 68].
* **X-Values:** Signature components; for non-signers, these are random. [cite_start]For the signer, it is computed using the private key to satisfy the ring equation[cite: 71, 72].
* [cite_start]**Y-Values:** Computed from X-values using the RSA trap-door function: $y_{i} = g_{i}(x_{i}) = x_{i}^{e_{i}} \mod n_{i}$[cite: 84].
* [cite_start]**Glue Value (v):** A random 128-bit value that serves as the starting point for the combining function[cite: 87].



## 8. The Algorithm - Signing
1. [cite_start]**Pick a random Glue Value (v):** A 128-bit seed that ensures signature uniqueness[cite: 90, 93].
2. [cite_start]**Compute symmetric key (k):** $k = H(m) \mod 2^{128}$ using SHA-256 to bind the signature to the message[cite: 101, 103].
3. [cite_start]**Generate random X-values for non-signers:** Create "fake" signatures using their public keys[cite: 108, 110, 112].
4. [cite_start]**Determine target length:** A temporary X-signer value is computed to ensure all X-values have similar bit lengths to protect anonymity[cite: 142, 143, 145].
5. [cite_start]**Solve for the signer's X-value:** Use the combining function backwards to find $x_{s}$ such that $C_{k,v}(y_{1}, \dots, y_{n}) = v$[cite: 154, 155, 156].

### The Combining Function
The function links all members through nested encryption:
[cite_start]$C_{k,v}(y_{1}, \dots, y_{n}) = E_{k}(y_{n} \oplus E_{k}(y_{n-1} \oplus E_{k}(\dots E_{k}(y_{1} \oplus v) \dots)))$[cite: 192].
[cite_start]It binds the message, enables anonymity, and prevents forgery[cite: 197, 199, 200].

---

## 9. GitHub API & Tor Deployment
* [cite_start]**GitHub Integration:** Automatically fetches RSA public keys from user profiles via `https://api.github.com/users/{username}/keys`[cite: 260, 264].
* [cite_start]**Tor Deployment:** Uses Nginx as a reverse proxy and Tor hidden services to hide server locations and user IP addresses[cite: 300, 301, 304, 305].

## 10. Technical Debts
* [cite_start]**Private Key Security:** Currently, the signer must send their private key to the server, which requires high trust[cite: 323].
* [cite_start]**Algorithm Diversity:** Future updates should implement additional asymmetric cryptosystems beyond RSA[cite: 324].
* [cite_start]**Verification:** The direct signature verification via link needs further improvement[cite: 325].

---

## 11. Sources
* **[1]** Rivest, R.L., Shamir, A., Tauman, Y. (2006). [cite_start]*How to Leak a Secret: Theory and Applications of Ring Signatures.* Springer, Berlin, Heidelberg[cite: 327, 328, 330].
* **Fig. [cite_start]1** Rivest, R. L., Shamir, A., Tauman, Y.: *How to Leak a Secret*, Springer LNCS, 2001, Page 560[cite: 331].
