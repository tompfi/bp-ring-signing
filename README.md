# Putting Ring-Signatures to praxis: Create a Webapp to anonymously (Ring-)Sign Messages
**Bachelor-Project by: Tom Pfirsig** | **Date: 08.10.2025**

---

## 1. About this Project
In this Bachelor-Project, I implemented the Ring Signature by Ronald L. Rivest, Adi Shamir, and Yael Tauman as described in the paper "How to leak a secret".

* **Framework:** The project uses the Django-Framework for its Python base and simple database organization.
* **Data Privacy:** Although first drafts used a database, the final product does not, to ensure that stored data cannot compromise anonymity.
* **Anonymity:** To protect connections, the project can be hosted within the Tor network. The algorithm itself ensures mathematical anonymity.
* **Implementation:** All relevant code for the signing and verification process can be found in `views.py`, which is heavily commented for clarity.

## 2. Features
* Signing using the RSA 1025/2048/4096 cryptosystems.
* Verifying given signatures.
* Using the GitHub API for simple GitHub-Key lookup.
* Simple Bootstrap UI with complex error messages to guide the user.
* Hosting inside the Tor network to ensure anonymity.
* Uploading a PDF as a message to sign.

## 3. How to install
1.  **Prerequisites:** Make sure Docker is installed and running.
2.  **Clone the repository:** `git clone https://github.com/tompfi/bp-ring-signing`
    `cd bp-ring-signing`
3.  **Run Docker:** `docker-compose up --build`
4.  **Access the application:**
    * **Local:** `http://localhost:8000`
    * **Tor-Network:** Open the URL found in `bp-ring-signing/tor/hostname` using a browser that can handle onion addresses.

---

## 4. How to sign a message
1.  On the Landing Page, click on **"Create Ring Signature"**.
2.  Write a message in the form field OR upload a **PDF-File**.
3.  **Add the Ring Members:** * Lookup GitHub usernames to pull their RSA keys automatically.
    * Or manually enter a name and the Public Key in PEM format.
4.  Choose the actual Signer.
5.  Click **"Create Signature"**.

## 5. How to verify a message
1.  On the Landing Page, click on **"Verify Ring Signature"**.
2.  Enter the original message or upload the same PDF file that was signed.
3.  Enter the **Glue Value (v)** from the signature.
4.  Enter the **X-Values** (signature components) — one per line or comma-separated.
5.  Enter all **Public Keys** of the ring members in PEM format.
6.  Click **"Verify Signature"**.

---

## 6. Mathematical Foundations
### 6.1 Requirements
* For every member in the ring, a Public Key is required; the signer also requires their Private Key.
* All keys must be within the RSA cryptosystem.
* Symmetric encryption to link the message: $E_{k}(x) = (x + k) \mod 2^{128}$, where $k$ is derived from hashing the message.

### 6.2 Terminology
* **Ring Signature:** $\sigma = (P_{1}, \dots, P_{r}; v; x_{1}, \dots, x_{r})$.
* **X-Values:** The signature components. For non-signers, these are random values. For the signer, this value is computed to satisfy the ring equation.
* **Glue Value (v):** A random 128-bit value serving as the starting point for the combining function.



## 7. The Algorithm
* **Symmetric Key:** Calculated as $k = H(m)$ using SHA-256 and truncated to 128 bits to bind the signature to the specific message.
* **Target Length:** To ensure anonymity, the signer's X-value bit length is matched to the others so the signer cannot be identified by value size.
* **Combining Function:** Links all members through nested encryption: $C_{k,v}(y_{1}, \dots, y_{n}) = v$.

---

## 8. Technical Debts
* **Private Key Trust:** A major weakness is that the signer must send their private key to the server.
* **Cryptosystems:** Future versions should implement asymmetric systems other than RSA.
* **Verification:** Direct signature verification via link is currently only implemented in a basic form.

## 9. Sources
* Rivest, R.L., Shamir, A., Tauman, Y. (2006). *How to Leak a Secret: Theory and Applications of Ring Signatures*.
* Fig. 1: Rivest, R. L., Shamir, A., Tauman, Y.: *How to Leak a Secret*, Springer LNCS, 2001.
