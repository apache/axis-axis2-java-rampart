# Security Threat Model — Apache Rampart

## Project Description

Apache Rampart is the WS-Security implementation for Apache Axis2/Java.
It provides message-level security for SOAP web services: XML Signature,
XML Encryption, UsernameToken authentication, SAML 1.1/2.0 assertion
processing, Kerberos token support, WS-Trust (Secure Token Service), and
WS-SecureConversation. Rampart is deployed as an Axis2 module (MAR) that
adds inbound and outbound security handlers to the Axis2 message
processing pipeline.

Rampart delegates cryptographic operations to Apache WSS4J (4.0.1) and
SAML processing to OpenSAML (5.2.1). It is the security enforcement
layer — if Rampart is bypassed or misconfigured, Axis2 services have no
message-level security.

## Roles and Trust Levels

| Role | Trust Level | Description |
|------|-------------|-------------|
| **Server Administrator** | Fully trusted | Configures Rampart policies, manages keystores, deploys MAR modules. |
| **Service Deployer** | Trusted | Attaches WS-SecurityPolicy to services via WSDL or programmatic configuration. |
| **Security Token Service (STS)** | Trusted (configurable) | Issues SAML assertions and security context tokens. May be local (rahas module) or remote. Trust established via certificate validation. |
| **Authenticated Client** | Partially trusted | Presents valid security tokens (X.509 signature, SAML assertion, UsernameToken, Kerberos ticket). Rampart validates tokens against policy. |
| **Anonymous Client** | Untrusted | Sends SOAP messages without security headers. Rampart rejects if policy requires security. |

## Security Boundaries

### What IS a security issue

- **Signature wrapping attacks** — an attacker manipulates the XML
  structure so that a valid signature covers a different element than
  intended, allowing modification of unsigned message parts.
- **XML External Entity (XXE) injection** — XXE in SAML assertion
  parsing, WS-SecurityPolicy processing, or any XML parsing performed
  by Rampart or its dependencies (WSS4J, OpenSAML).
- **Signature/encryption bypass** — a flaw that allows a message to
  pass Rampart validation without the security tokens required by policy.
- **Key confusion or certificate substitution** — an attacker presents a
  valid certificate for a different identity to pass signature validation.
- **SAML assertion forgery** — crafting or replaying SAML assertions that
  Rampart accepts as valid (forged signatures, expired assertions
  accepted, issuer spoofing).
- **Weak cryptographic defaults** — default algorithm suites that use
  deprecated algorithms (3DES, SHA-1 for signing), making deployed
  services vulnerable to cryptographic attacks.
- **Nonce/timestamp replay** — replaying previously valid security
  headers because nonce caching or timestamp validation is inadequate.
- **Private key exposure** — Rampart leaking keystore passwords, private
  keys, or session keys through error messages, logs, or SOAP faults.
- **Deserialization of untrusted data** — any path where Rampart or its
  dependencies deserialize Java objects from message content.
- **Denial of service via cryptographic operations** — crafted messages
  that cause excessive CPU consumption during signature verification,
  decryption, or certificate chain validation.

### What is NOT a security issue

- **Missing Rampart engagement.** If a service deployer does not engage
  the Rampart module or attach a security policy, messages are processed
  without security. This is a deployment configuration issue.
- **Transport-layer security (TLS).** Rampart handles message-level
  security. TLS termination is the servlet container's responsibility.
  `TransportBinding` policy requires HTTPS but does not enforce it —
  it trusts the container's `isSecure()` flag.
- **Application-level authorization.** Rampart authenticates message
  senders and validates security tokens. Deciding whether an
  authenticated principal is authorized for a specific operation is
  the application's responsibility.
- **Vulnerabilities in the Axis2 core engine.** XML parsing, HTTP
  transport, and deployment issues are in the Axis2/Java core repo's
  scope, not Rampart's.
- **KeyStore management.** Protecting keystore files with proper
  filesystem permissions and strong passwords is the administrator's
  responsibility.

## Architecture and Attack Surface

### Message Processing Flow

```
Incoming SOAP Message
    |
    v
Axis2 Transport-In Phase
    |
    v
RampartReceiver (inbound handler)
    |
    v
RampartEngine.process(MessageContext)
    |
    v
Extract WS-Security header
    |
    v
WSSecurityEngine (WSS4J 4.0.1)
  - Validate signatures (XML-DSIG via Apache Santuario)
  - Decrypt encrypted parts (XML-ENC)
  - Validate UsernameToken (password callback)
  - Validate SAML assertions (OpenSAML 5.2.1)
  - Validate Kerberos tokens (JDK JAAS/GSS)
  - Validate timestamps (clock skew tolerance)
    |
    v
PolicyBasedResultsValidator
  - Match WSS4J results against WS-SecurityPolicy assertions
  - Verify required tokens present
  - Verify signed/encrypted parts match policy
    |
    v
Service method invocation (if validation passes)
    |
    v
RampartSender (outbound handler)
    |
    v
MessageBuilder
  - Apply signatures, encryption per outbound policy
  - Add timestamps, nonces
  - Insert security header into SOAP envelope
    |
    v
Axis2 Transport-Out Phase
```

### Attack Surface by Component

| Component | Threats | Mitigations |
|-----------|---------|-------------|
| **XML Signature validation** (WSS4J/Santuario) | Signature wrapping; reference manipulation; HMAC truncation | WSS4J 4.0.1 signature reference validation; Santuario's strict reference processing |
| **XML Encryption** (WSS4J/Santuario) | Padding oracle; chosen-ciphertext attacks; CBC mode weaknesses | Algorithm suite enforcement; GCM recommended over CBC |
| **SAML assertion parsing** (OpenSAML 5.2.1) | XXE in assertion XML; forged assertions; expired/replayed assertions; issuer spoofing | OpenSAML unmarshalling; assertion signature validation; NotBefore/NotOnOrAfter enforcement; issuer certificate pinning |
| **SAML2Utils.getSAML2KeyInfo()** | XXE — `DocumentBuilderFactory.newInstance()` without explicit XXE hardening flags | Depends on OpenSAML's `AxiomParserPool` configuration; **review needed** |
| **UsernameToken validation** | Plaintext password interception; weak hashing; brute force | TransportBinding requires HTTPS for plaintext; nonce+created for hashed; callback-based validation |
| **Kerberos token decoding** | Forged tickets; replay attacks | JDK Kerberos SPI handles validation; keytab/realm configuration is admin responsibility |
| **Certificate/key management** | Key confusion; expired certificates; revocation bypass | `CertificateValidator` extends WSS4J `SignatureTrustValidator`; chain validation delegated to JDK |
| **Timestamp validation** | Replay attacks; clock skew exploitation | WSS4J timestamp processing; configurable skew tolerance |
| **Nonce caching** | Replay of previously valid nonces | In-memory nonce cache; cache TTL configuration |
| **Policy matching** | Downgrade attacks; policy confusion | `PolicyBasedResultsValidator` enforces all required assertions |
| **Transport binding validation** | HTTPS bypass | `RampartUtil.validateTransport()` checks servlet container's `isSecure()` flag and optionally extracts client certificate from `jakarta.servlet.request.X509Certificate` attribute — **trusts container entirely** |
| **Crypto caching** | Stale key material | `CachedCrypto` with TTL; thread-safe access |

### Critical Dependencies

| Dependency | Version | Security Role |
|-----------|---------|---------------|
| **WSS4J** | 4.0.1 | Core WS-Security processing — signatures, encryption, token validation |
| **OpenSAML** | 5.2.1 | SAML assertion parsing, validation, and issuance |
| **Apache Santuario** (xmlsec) | via WSS4J | XML Signature and XML Encryption implementation |
| **Bouncy Castle** | runtime dependency | JCE provider for advanced crypto algorithms |

**Maintenance note (RAMPART-454):** When updating these dependencies,
reviewers must read every intermediate CVE release note (not just the
latest version), ensure no weak algorithm or key size is reintroduced
as a default, and re-run all policy samples to verify no regression.

## CVE History

Rampart has no independently assigned CVEs. Its security posture depends
heavily on WSS4J and OpenSAML, which have extensive CVE histories:

- **WSS4J CVEs** include signature wrapping (CVE-2011-2487), HMAC
  truncation, and various XML signature bypass issues. Rampart 2.0.0
  uses WSS4J 4.0.1, which addresses all known issues.
- **OpenSAML CVEs** include XXE in SAML assertion parsing and assertion
  replay. Rampart 2.0.0 uses OpenSAML 5.2.1.

The scan should verify that Rampart's integration with these libraries
does not reintroduce vulnerabilities that the libraries themselves have
fixed — particularly in areas where Rampart wraps or preprocesses data
before passing it to WSS4J/OpenSAML (e.g., `Axis2Util.getDocumentFromSOAPEnvelope()`,
`SAML2Utils.getSAML2KeyInfo()`).

## Areas Requiring Extra Scrutiny

1. **`SAML2Utils.getSAML2KeyInfo()`** — Creates `DocumentBuilderFactory`
   without visible XXE hardening. If the OpenSAML `AxiomParserPool`
   does not enforce XXE protections, this is a vulnerability.

2. **`RampartUtil.validateTransport()`** — Trusts the servlet
   container's `isSecure()` flag and X.509 certificate attribute without
   re-validating the certificate chain. Container misconfiguration could
   bypass client certificate authentication.

3. **Algorithm suite defaults** — Policy samples include `sp:Basic128`
   which uses 3DES. Scan for any code path where weak algorithms are
   accepted by default without explicit policy opt-in.

4. **Plaintext password handling** — `RampartUsernameTokenValidator`
   overrides WSS4J's default password verification. Verify the override
   does not weaken validation.

## Reporting Security Issues

Report vulnerabilities to: **security@apache.org**

Follow the [Apache Security Policy](https://www.apache.org/security/).
