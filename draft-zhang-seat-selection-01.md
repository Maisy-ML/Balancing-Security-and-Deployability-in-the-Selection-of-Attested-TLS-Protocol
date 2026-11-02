---
title: Balancing Security and Deployability in the Selection of Attested TLS Protocol
abbrev: SEAT Selection
docname: draft-zhang-seat-selection-02
date: {DATE}
category: info
ipr: trust200902
area: Security
workgroup: SEAT

stand_alone: yes
pi:

  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  text-list-symbols: -o*+
  docmapping: yes

author:

-
  name: Jun Zhang
  org: Huawei Technologies France S.A.S.U.
  email:  junzhang1@huawei.com

- name: Houda Labiod
  org: Huawei Technologies France S.A.S.U.
  email: houda.labiod@huawei.com

- name: Meiling Chen
  org: China Mobile
  email: chenmeiling@chinamobile.com
--- abstract

This document analyzes the selection of Attested Transport Layer Security (aTLS) protocols, among pre-handshake, intra-handshake, and post-handshake aTLS protocols, 
focusing on the trade-off between theoretical security strength and practical deployability. The goal is to enable flexible, context-aware deployment of endpoint attestation while maintaining compatibility with existing infrastructure.

--- middle

# Introduction

Attested TLS (aTLS) enables a TLS server to provide cryptographic proof of its endpoint behavior, including configuration, identity, and software integrity. This is essential for high-assurance use cases such as zero-trust architectures, compliance verification, and supply chain security.

However, the timing and method of attestation delivery significantly affect both security strength and network deployability. This document considers three models:

Pre-handshake: Attestation sent before TLS begins.

Intra-handshake: Attestation embedded in TLS handshake messages.

Post-handshake: Attestation sent after handshake completion.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

Attester: The entity that generates attestation evidence.

Verifier: The entity that validates the attestation.

Relying Party: The client or service relying on the attestation result.

TLS Exporter: A TLS 1.3 mechanism to derive keying material from the handshake.

Middlebox: Network devices that inspect or modify TLS traffic (e.g., firewalls, load balancers).

Identity Key (IK): The cryptographic key pair used for endpoint authentication during the TLS handshake (referred to as AIK in [draft-fossati-seat-expat] or TIK in [draft-fossati-seat-early-attestation] ).


# The Theoretical Upper Bound of Security

In an ideal world, aTLS should achieve the following security properties:

**Cryptographic Binding**: The attestation evidence MUST be cryptographically bound to both the specific TLS session and the authentication identity to prevent relay and substitution attacks.

*  **Session Binding**: The evidence MUST include a unique session-derived value (e.g., a hash of the handshake transcript for intra-handshake attestation, or a value derived via TLS Exporter for post-handshake attestation). This ensures that the evidence is fresh and bound to the current active channel, preventing an attacker from replaying evidence from a different or previous session.

* **Identity Binding**: : The evidence MUST be cryptographically linked to the public key of the certificate used for authentication (e.g., by including the hash of the Identity Key public key). This ensures that the environment being attested is the same entity that holds the private key used for the TLS connection, preventing key substitution or relay attacks where a healthy TEE provides evidence for an insecure TLS key.

**Freshness**: The attestation must be fresh to prevent replay attacks. Freshness MUST be guaranteed by incorporating a unique session-specific value into the evidence.

**Zero-Knowledge (Optional Privacy)**: The protocol should allow for selective disclosure, proving properties (e.g., "I am running patched Linux") without revealing the exact measurement hash, if desired.

**Formal Verification**: The protocol composition should be formally verified under a defined threat model to provide provable security guarantees, complemented by cryptographic analysis to address implementation-specific edge cases.

**Attack Window**：  The "Attack Window" (AW) quantifies the temporal exposure during which an attacker can influence a connection before its authenticity is cryptographically verified. AW = T_verify - T_attack_start,
   Where:

   - T_attack_start: The earliest time an attacker can begin intervention.
   
   - T_verify: The time when cryptographic verification is completed.

   A smaller AW indicates a stronger security posture.  The theoretical optimum is AW ≈ 0, where verification occurs synchronously with connection establishment. 

The Upper Bound implies a tight integration where the attestation is signed over the TLS handshake state, effectively making the attestation a mandatory extension of the Finished messages.

# The Practical Lower Bound of Deployment

In the real world, protocols face harsh constraints that define the "Lower Bound" of what is acceptable:

**Middlebox Compatibility**: While TLS 1.3 encrypts many handshake extensions, enterprise networks and strict DPI (Deep Packet Inspection) firewalls can still cause deployment failures. This occurs when custom extensions significantly increase the handshake packet size, triggering fragmentation issues, or when non-standard protocol behavior triggers security heuristics in legacy middleboxes. A viable protocol must ensure that attestation data does not cause unexpected connection resets or packet drops.


**Application Friction**: Forcing every application to explicitly handle attestation logic creates a massive deployment barrier. A practical solution must support Transparent Integration, where the aTLS logic is encapsulated within a TEE-aware Runtime or a Library Shim. This ensures that existing applications can leverage attestation without modifying their source code or business logic.

**Library Fragmentation**: Not all clients and servers use the latest OpenSSL/BoringSSL. The solution must ideally be backward compatible or implementable as a modular extension.

**Hardware Asymmetry**:

*  High-End: Servers with TPMs 2.0 or Intel SGX/TDX can perform complex signing operations during the handshake.

*  Low-End: IoT devices or highly loaded servers may experience significant latency if the handshake is blocked waiting for hardware signing.

**Operational Complexity**: Verifying attestation requires a complex infrastructure (Verifier, Policy Engine). If the protocol requires the TLS server to act as the Verifier for the client, it increases server load and state management complexity.

**Passive Observation**: In some deployment models (e.g., mutual TLS), the verifier might be an offline entity analyzing logs rather than the immediate peer, requiring the attestation to be accessible post-handshake.

The Lower Bound dictates that the protocol must be resilient to extension stripping, must not add unacceptable latency, and must allow for a "pass-through" mode where the TLS stack is unaware of the attestation semantics.

# Selection Analysis



## The "Binding" Gap
The primary tension in aTLS lies in the trade-off between binding strength and implementation complexity.

**Theory**: To achieve near-zero attack windows, the attestation evidence SHOULD be cryptographically bound to the unique TLS handshake transcript (e.g., via the Transcript Hash as proposed in [draft-fossati-seat-early-attestation]). This ensures that the evidence is inextricably linked to the specific handshake messages, preventing any form of session substitution.

**Practice**: In practice, generating a signature over the handshake transcript during the handshake requires deep integration into the TLS state machine. For many production-grade libraries (e.g., OpenSSL, BoringSSL), such modifications are invasive, risk introducing security vulnerabilities, and complicate the upgrade path. To mitigate this, a decoupled implementation pattern can be adopted:
Instead of modifying the core state machine, the TLS stack can be designed to expose a fixed transcript checkpoint (e.g., the hash of messages from ClientHello through ServerHello) to an external attestation shim. This shim acts as an intermediary, passing the checkpoint hash and the identity public key to the TEE for signing. By treating the attestation as a side-car operation triggered at a specific handshake event, the strong binding of a transcript hash can be achieved without invasive changes to the TLS library's internal logic.

**Selection Decision**: The selection of the binding mechanism should be driven by the deployment environment:

- **For Controlled Environments**: Mechanisms using the Handshake Transcript Hash are RECOMMENDED to achieve maximum security strength.

- **For General Deployment**: Mechanisms using the TLS Exporter [RFC5705] are RECOMMENDED to bridge the gap. By deriving a unique session-binding value outside the strict handshake state machine, the attestation can be generated as a modular extension. This provides a cryptographically sound binding to the session while respecting the lower bound of library modularity and deployability.


## The "Middlebox" Gap
**Theory**: We control the whole stack and can enforce attestation requirements strictly.

**Practice**: The path contains F5 load balancers, legacy proxies, and SaaS inspection tools. While encrypting payloads prevents content-based interference, middleboxes may still strip unrecognized TLS extensions (e.g., remoteAttestation in [draft-fossati-seat-early-attestation]) entirely during the handshake.

**Capability Negotiation**: To prevent connection failures (false positives) when attestation is unsupported, the protocol MUST use a TLS Extension to signal capabilities during the handshake.

- **Extension Present**: The server explicitly supports attestation. If evidence is subsequently missing or invalid, the client MUST abort (Hard Fail).

- **Extension Absent**: The server does not support attestation (or the extension was stripped). The client MAY fallback to standard TLS (Soft Fail), depending on local policy.

**Selection Decision**: The placement of evidence is a trade-off between security and robustness:

- **Intra-Handshake**: Strongest security via transcript binding (Attestation Binder). Payload encryption mitigates content-based stripping, but the session remains vulnerable to Extension-ID stripping by legacy middleboxes.

- **Post-Handshake**: Most robust against middlebox interference as it bypasses handshake extension filtering.
Crucially, the decision to abort or fallback MUST be based on the negotiated capability (Extension presence) rather than the mere absence of evidence.

## The "Latency" Gap

**Theory**: Attestation is instant.

**Practice**: TPM signing takes 50ms-200ms; SGX quoting is variable.

**Selection Decision**: To avoid the performance penalty of blocking the TLS handshake, the attestation timing should be configurable depending on the security policy:

*   **Strict Mode (Synchronous)**: Attestation is mandatory and blocking. The handshake fails if evidence is not validated before the `Finished` message. Use this for high-security cores where no unverified data can ever enter the system.

*   **Balanced Mode (Asynchronous/Restricted)**: The connection is established immediately, but enters a "Restricted" state. Basic connectivity is allowed, but sensitive operations are blocked until the background attestation is validated.

*   **Permissive Mode (Optimistic)**: Attestation runs fully in the background. Application data flows without restriction, and the session is terminated only if the delayed attestation result returns a failure. Use this for low-risk services where availability is prioritized over strict platform integrity.


# Evaluation of Attestation Phases

## Pre-Handshake Attestation

- **Description**: Attestation sent before TLS handshake begins.
- **Pros**:
  - Allows early rejection of untrusted servers.
  - Can be used in stateless environments.
- **Cons**:
  - No cryptographic binding to TLS session.
  - Vulnerable to downgrade or substitution attacks.
  - Requires out-of-band channel or non-standard port.
- **Mitigation Strategies**:
  - **Token-based Session Binding**: To mitigate the lack of cryptographic binding, raw attestation evidence SHOULD NOT be used directly. Instead, a trusted intermediary (e.g., a NAC Gateway) MAY validate the evidence and issue a short-lived, cryptographically bound token (such as a TLS-PSK identity). This anchors the pre-handshake trust to the subsequent TLS session.
  - **Out-of-Band Channel Pairing**: To reduce the risk of substitution attacks, the attestation exchange SHOULD be performed over a secure control plane or a dedicated management channel that is logically paired with the data plane used for the TLS handshake.
- **Attack Window**: Near-infinite (attacker can intervene before any TLS message is sent; there is no cryptographic binding to the session)
- **Verdict**: Raw Pre-handshake Attestation is not recommended due to weak session binding; however, token-based approaches are suitable for network admission control (NAC).

## Intra-Handshake Attestation

- **Description**: Attestation embedded in TLS handshake messages (e.g., via extensions or `Certificate`).
- **Pros**:
  - Strongest security: fully bound to handshake transcript.
  - Enables mutual authentication with attestation.
  - No additional round-trips.
- **Cons**:
  - **Handshake Latency**: TEE quoting/signing can introduce significant delays, potentially causing handshake timeouts.
  - **Implementation Complexity**: Requires tight integration between the TLS stack and the TEE/Attestation service.
  - **Middlebox Risk**: Despite encryption, some aggressive network filters may still flag unusual handshake patterns.
- **Attack Window**: Near-zero (verification occurs synchronously with 
the handshake; any tampering with the transcript invalidates the session)
- **Mitigation Strategies**:
  - **Privacy-Preserving Transport**: To mitigate middlebox interference (e.g., extension stripping), attestation evidence SHOULD be placed within encrypted handshake messages (e.g., EncryptedExtensions or Certificate in TLS 1.3). This masks the attestation data from network observers, preventing targeted stripping by middleboxes.
  - **Modular Binding**: To reduce integration complexity, the binding between attestation and the session SHOULD be achieved via a decoupled derivation process. By using a binder independent of the main TLS key schedule, implementations can avoid modifying the core TLS state machine and the underlying core library implementation. This allows the attestation logic to be integrated as a modular extension without requiring invasive patches to standard, off-the-shelf TLS stacks.
  - **Asynchronous Verification**: To prevent blocking the TLS handshake (which may cause timeouts due to TEE latency), implementations MAY support a Background Check model. In this model, the connection is established first, and evidence is verified asynchronously, with the application layer enforcing a "pending-verification" state to restrict access to sensitive resources until the process completes.
- **Verdict**: Maximum security, conditional deployability. Highly recommended for controlled environments and high-assurance use cases.

##  Post-Handshake Attestation

- **Description**: Attestation sent after handshake completion via application data.
- **Pros**:
  - No middlebox issues (uses standard TLS record layer).
  - Easy to implement and deploy.
  - Compatible with TLS 1.3 and widely deployed stacks.
  - Supports Capability Negotiation: Allows the client to detect support via TLS extensions before expecting evidence, preventing false connection aborts on legacy servers.
- **Cons**:
  - Requires explicit binding to handshake (e.g., via exporter).
  - Slight latency cost (one extra message).
-  **Attack Window**: Bounded (AW = T_verify - T_handshake_complete, typically 
  one RTT). During this window, the channel is encrypted but the endpoint's identity is unverified. An attacker who compromised the endpoint during handshake could operate undetected until verification completes.
- **Mitigation Strategies**: 
  - **Strong Session Anchoring**: To bridge the "binding gap," the post-handshake evidence MUST be cryptographically bound to the session using TLS Exporters [RFC5705]. By incorporating exporter-derived keying material into the attestation signature, the evidence is anchored to the specific session transcript, preventing replay or relay attacks.
  - **Application-Level Guarding**: To mitigate the temporal attack window (the period between handshake completion and verification), the Relying Party SHOULD implement an Application-Level Guard. The session should be treated as "Unverified" by default, and high-privilege API calls or data transfers SHOULD be blocked until the attestation is successfully validated.
  - **Freshness Enforcement**: To prevent the use of stale evidence, the verifier SHOULD provide a fresh nonce or a timestamp challenge that the attester must incorporate into the signed evidence.
- **Verdict**: High deployability and robust security. Highly recommended for general-purpose uncontrolled network environments.

#     Failure Mode Analysis

   Beyond the happy path, the failure characteristics of each approach are critical for deployability:

## Hard Failure (Pre-handshake and Intra-handshake)

   Attestation is performed before or during the TLS handshake.  Any failure—whether due to network issues, TEE unavailability, or verification errors—results in complete connection failure.

   User Experience: Connection refused with no context Recovery: Client must retry entire handshake or re-attest
   Production Impact: Brittle; may cause service disruptions

##  Soft Failure (Post-handshake)

   TLS handshake completes successfully.  Attestation failure occurs after the encrypted channel is established, allowing the application to handle the situation gracefully.

   User Experience: Partial service, user prompt, or graceful degradation
   Recovery: Application-defined policy (terminate, retry, or continue with reduced privileges)
   Production Impact: Resilient; supports business continuity

   This distinction is a key factor when selecting attestation timing for high-availability deployments.

# Context-Dependent Selection

The following decision matrix summarizes the recommended attestation timing for each deployment scenario:

| Scenario                       | Recommended Phase | Failure Mode |
   |--------------------------------|-----------------|------------|
   | General Internet               | Post-handshake  | Soft       |
   | Controlled Environments        | Intra-handshake | Hard/Soft       |
   | Protocols with Native Support  | Intra-handshake | Hard/Soft       |
   | Network Admission Control      | Pre-handshake   | Hard       |

## General Internet Deployment
For public-facing services (e.g., HTTPS, APIs), **post-handshake attestation** like[draft-fossati-seat-expat] is REQUIRED due to widespread middlebox deployment and legacy infrastructure, and is 
recommended for broad interoperability.

## Controlled Environments and Integrated Protocols
In enterprise networks, data centers, or IoT deployments, where:

- Middleboxes are under administrative control,

- TLS stacks are upgradable,

- Security is paramount,

**Intra-handshake attestation** MAY be used when network environment allows.


## Protocols with Native Attestation Support

Certain protocols, for example the LAKE Protocol [I-D.ietf-lake-ra], provide native support for attestation integration without requiring protocol modifications. In such cases, **Intra-handshake attestation is RECOMMENDED**. This approach enables zero-cost attestation, optimal cryptographic binding, and protocol-level trust composition.


## Niche Case: Pre-Handshake for Network Admission Control
In architectures featuring a validating gateway (e.g., a Zero Trust Network Access gateway):

1. The client attests to the gateway via a separate protocol (e.g., EST over CoAP, or a custom UDP protocol).
2. The gateway validates the attestation.
3. The gateway issues a short-lived Attestation Token (e.g., a psk_identity for TLS-PSK).
4. The client initiates the TLS handshake to the internal server, presenting the Token.
5. The server validates the Token to authorize the session.

Token-based Pre-handshake attestation is RECOMMENDED for gateway-based NAC, provided the Token is cryptographically bound to the TLS session.

## Decision Flowchart

   The following flowchart provides a quick reference for selecting the appropriate attestation timing:


     +-----------------------+
     |   START: Select Phase |
     +-----------------------+
                 |
                 v
     +-----------------------+
     | Network Controlled?   |
     +-----------------------+
        |              |
      Yes              No
        |              |
        v              v
     +------------+  +-----------+
     | TLS        |  | NAC       |
     | Upgradable?|  | Gateway?  |
     +-----------+   +-----------+
      |      |       |      |
     Yes     No     Yes     No
      |      |       |      |
      v      v       v      v
    +------+ +-----+ +----+ +-----+
    |Intra|  |Post | |Pre | |Post |  
    |HS   |  |HS   | |HS  | |HS   |
    |H/S  |  |Soft | |Hard| |Soft |
    |Fail |  |Fail | |Fail| |Fail | 
    +------+ +-----+ +----+ +-----+
{: #fig-flow-chart title="Decision Flowchart"}

**Flowchart Interpretation**:

The decision flow prioritizes deployability while maintaining security:

1. **Network Controlled?** → If yes, check TLS upgradability.
2. **TLS Upgradable?** → If yes, use Intra-Handshake. The hard/soft fail depends on the policy setting.
3. **NAC Gateway?** → If yes, use Pre-Handshake (token-based).
4. **Default** → Post-Handshake (best balance).

This ensures that the most secure option is chosen only when the network 
environment can support it, avoiding deployment failures in uncontrolled 
environments.

# IANA Considerations
TODO

# Security Considerations
TODO

# References

## Normative References

[RFC8446]
: Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, August 2018.

[RFC5705]
: Rescorla, E., "Keying Material Exporters for TLS", RFC 5705, March 2010.

[RFC2119]
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.

[RFC8174]
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.

## Informative References
[draft-fossati-seat-early-attestation] : Fossati, T., et al., "Using Attestation in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)", Work in Progress, Internet-Draft, draft-fossati-seat-early-attestation.

[draft-fossati-seat-expat] :
Sardar, M., et al., "Remote Attestation with Exported Authenticators",  Work in Progress, Internet-Draft, draft-fossati-seat-expat

[I-D.ietf-lake-ra]  
: Yuxuan, S., et al., "Remote Attestation over EDHOC", Internet-Draft, draft-ietf-lake-ra.



# Acknowledgements


<cref>TODO</cref>
