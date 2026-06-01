# AGENTS.md — Apache Rampart

## Security Threat Model

See [SECURITY.md](SECURITY.md) for the full threat model, including:

- Project description (WS-Security implementation for Axis2)
- Roles and trust levels
- Security boundaries: what is and is not a security issue
- Attack surface by component (signatures, encryption, SAML, Kerberos, UsernameToken)
- Critical dependency versions (WSS4J 4.0.1, OpenSAML 5.2.1)
- CVE history context

## High-Priority Scan Areas

### 1. SAML Assertion Parsing (XXE risk)

`SAML2Utils.getSAML2KeyInfo()` creates a `DocumentBuilderFactory` without
visible XXE hardening flags. Verify that OpenSAML's `AxiomParserPool`
(configured in `AxiomParserPool.java`) enforces XXE protections, and that
no code path bypasses it.

Key files:
- `modules/rampart-trust/src/main/java/org/apache/rahas/impl/util/SAML2Utils.java`
- `modules/rampart-trust/src/main/java/org/apache/rahas/impl/util/AxiomParserPool.java`

### 2. Signature Wrapping

Rampart relies on WSS4J 4.0.1 for signature reference validation. Verify
that Rampart's preprocessing in `Axis2Util.getDocumentFromSOAPEnvelope()`
(which converts Axiom to DOM and normalizes namespaces) does not create
opportunities for signature wrapping attacks.

Key files:
- `modules/rampart-core/src/main/java/org/apache/rampart/util/Axis2Util.java`
- `modules/rampart-core/src/main/java/org/apache/rampart/RampartEngine.java`
- `modules/rampart-core/src/main/java/org/apache/rampart/PolicyBasedResultsValidator.java`

### 3. Transport Binding Validation

`RampartUtil.validateTransport()` trusts the servlet container's
`isSecure()` flag and X.509 certificate attribute. A container
misconfiguration (e.g., reverse proxy not setting the secure flag)
could bypass client certificate authentication entirely.

Key files:
- `modules/rampart-core/src/main/java/org/apache/rampart/util/RampartUtil.java` (line ~1890)

### 4. Cryptographic Algorithm Defaults

Scan for code paths where weak algorithms (3DES, SHA-1 for signing,
RSA-OAEP with MGF1-SHA1) are accepted by default without explicit
policy opt-in. Check algorithm suite resolution in binding builders.

Key files:
- `modules/rampart-core/src/main/java/org/apache/rampart/builder/BindingBuilder.java`
- `modules/rampart-core/src/main/java/org/apache/rampart/builder/AsymmetricBindingBuilder.java`
- `modules/rampart-core/src/main/java/org/apache/rampart/builder/SymmetricBindingBuilder.java`
- `modules/rampart-policy/src/main/java/org/apache/ws/secpolicy/model/AlgorithmSuite.java`

### 5. Password and Credential Handling

`RampartUsernameTokenValidator` overrides WSS4J's default plaintext
password verification. Verify the override does not weaken validation.
Also check that password callback handlers do not leak credentials
through logging or error messages.

Key files:
- `modules/rampart-core/src/main/java/org/apache/rampart/RampartUsernameTokenValidator.java`
- `modules/rampart-core/src/main/java/org/apache/rampart/handler/CertificateValidator.java`

## Project Structure

```
modules/
  rampart-core/    Core WS-Security processing: handlers, engine,
                   binding builders, policy validation
  rampart-policy/  WS-SecurityPolicy assertion builders and models
  rampart-trust/   WS-Trust STS: SAML token issuance, validation,
                   SecureConversation token management
  rampart-mar/     Axis2 module archive packaging (rampart.mar)
  rampart-trust-mar/  STS module archive packaging (rahas.mar)
  rampart-integration/  End-to-end integration tests (SAML, Kerberos, X.509)
  rampart-tests/   Unit tests
  rampart-samples/ 9 policy sample configurations
```

## Testing

Integration tests cover SAML 1.1/2.0 (bearer, holder-of-key),
UsernameToken, X.509 certificate, and Kerberos token scenarios.
No fuzz testing infrastructure exists for Rampart.

## Reporting

Security vulnerabilities: **security@apache.org**
