---
title: Balancing Security and Deployability in the Selection of Attested TLS Protocol
abbrev: SEAT Selection
docname: draft-zhang-seat-selection-01
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

# The Theoretical Upper Bound of Security

In an ideal world, aTLS should achieve the following security properties:

**Cryptographic Binding**: The attestation evidence MUST be cryptographically bound to the TLS session. Specifically, the evidence should cover the TLS handshake transcript (e.g., ClientHello...ServerHello). This prevents a "Man-in-the-Middle" (MITM) from stripping the attestation or replaying a valid attestation from a different session.

**Freshness**: The attestation must be fresh, preventing replay attacks. Ideally, the nonce used in the attestation is derived from the TLS handshake.

**Zero-Knowledge (Optional Privacy)**: The protocol should allow for selective disclosure, proving properties (e.g., "I am running patched Linux") without revealing the exact measurement hash, if desired.

**Formal Verification**: The protocol composition (TLS + Attestation) should be formally verified to ensure no security degradation (e.g., no downgrade attacks).

**Attack Window**：  The "Attack Window" (AW) quantifies the temporal exposure during which an attacker can influence a connection before its authenticity is cryptographically verified. AW = T_verify - T_attack_start,
   Where:

   - T_attack_start: The earliest time an attacker can begin intervention.
   
   - T_verify: The time when cryptographic verification is completed.

   A smaller AW indicates a stronger security posture.  The theoretical optimum is AW ≈ 0, where verification occurs synchronously with connection establishment. 

The Upper Bound implies a tight integration where the attestation is signed over the TLS handshake state, effectively making the attestation a mandatory extension of the Finished messages.

# The Practical Lower Bound of Deployment

In the real world, protocols face harsh constraints that define the "Lower Bound" of what is acceptable:

**Middlebox Compatibility**: Enterprise networks, firewalls, and TLS terminators often inspect or modify TLS handshakes. A protocol that breaks these middleboxes (e.g., by adding large custom extensions that are stripped) will fail to deploy.

**Library Fragmentation**: Not all clients and servers use the latest OpenSSL/BoringSSL. The solution must ideally be backward compatible or implementable as a modular extension.

**Hardware Asymmetry**:
-High-End: Servers with TPMs 2.0 or Intel SGX/TDX can perform complex signing operations during the handshake.

-Low-End: IoT devices or highly loaded servers may experience significant latency if the handshake is blocked waiting for hardware signing.

**Operational Complexity**: Verifying attestation requires a complex infrastructure (Verifier, Policy Engine). If the protocol requires the TLS server to act as the Verifier for the client, it increases server load and state management complexity.

**Passive Observation**: In some deployment models (e.g., mutual TLS), the verifier might be an offline entity analyzing logs rather than the immediate peer, requiring the attestation to be accessible post-handshake.

The Lower Bound dictates that the protocol must be resilient to extension stripping, must not add unacceptable latency, and must allow for a "pass-through" mode where the TLS stack is unaware of the attestation semantics.

# Selection Analysis

## The "Binding" Gap

The primary tension lies in Binding. 

**Theory**: The attestation signature MUST cover the ClientHello.random and ServerHello.random.

**Practice**: Generating this signature inside the TLS state machine is difficult for many libraries.

**Selection Decision**: The group should prefer mechanisms that use the TLS Exporter [RFC5705] to bridge this gap. This allows the attestation to be generated "outside" the strict handshake code but still be cryptographically bound to the session, satisfying the upper bound while respecting the lower bound of library modularity.

## The "Middlebox" Gap

**Theory**: We control the whole stack and can enforce attestation requirements strictly.

**Practice**: The path contains F5 load balancers, legacy proxies, and SaaS inspection tools that may strip unknown TLS extensions or block non-standard handshake behaviors.

**Capability Negotiation**: To prevent connection failures (false positives) when attestation is unsupported, the protocol MUST use a TLS Extension (e.g., attestation_supported) to signal capabilities during the handshake.

- **Extension Present**: The server explicitly supports attestation. If evidence is subsequently missing or invalid, the client MUST abort (Hard Fail).

- **Extension Absent**: The server does not support attestation (or the extension was stripped). The client MAY fallback to standard TLS (Soft Fail), depending on local policy.

**Selection Decision**: Sending attestation evidence as Application Data (post-handshake) is the most robust against middlebox interference. However, the decision to abort or fallback MUST be based on the negotiated capability (Extension presence) rather than the mere absence of evidence.

## The "Latency" Gap

**Theory**: Attestation is instant.

**Practice**: TPM signing takes 50ms-200ms; SGX quoting is variable.

**Selection Decision**: To prevent blocking the TLS handshake (which hurts performance), Asynchronous Attestation should be supported. The connection can be established, and data can flow (perhaps restricted), while the attestation is being validated in the background. This lowers the performance impact to the practical floor.


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
- **Attack Window**: Near-infinite (attacker can intervene before any TLS message is sent; there is no cryptographic binding to the session)
- **Verdict**: Raw Pre-handshake Attestation is not recommended due to weak session binding.

## Intra-Handshake Attestation

- **Description**: Attestation embedded in TLS handshake messages (e.g., via extensions or `Certificate`).
- **Pros**:
  - Strongest security: fully bound to handshake transcript.
  - Enables mutual authentication with attestation.
  - No added latency.
- **Cons**:
  - High risk of **middlebox interference** (e.g., stripping unknown extensions).
  - Difficult to deploy on the open Internet.
  - May require protocol-specific integration.
- **Attack Window**: Near-zero (verification occurs synchronously with 
the handshake; any tampering with the transcript invalidates the session)
- **Verdict**: High security, low deployability. Suitable only in controlled environments.

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
- **Verdict**: Best balance of security and deployability.

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
   | Controlled Environments        | Intra-handshake | Hard       |
   | Protocols with Native Support  | Intra-handshake | Hard       |
   | Network Admission Control      | Pre-handshake   | Hard       |

## General Internet Deployment
For public-facing services (e.g., HTTPS, APIs), **post-handshake attestation** like[draft-fossati-seat-early-attestation] is REQUIRED due to widespread middlebox deployment and legacy infrastructure, and is 
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
    |Hard |  |Soft | |Hard| |Soft |
    |Fail |  |Fail | |Fail| |Fail | 
    +------+ +-----+ +----+ +-----+
{: #fig-flow-chart title="Decision Flowchart"}

**Flowchart Interpretation**:

The decision flow prioritizes deployability while maintaining security:

1. **Network Controlled?** → If yes, check TLS upgradability.
2. **TLS Upgradable?** → If yes, use Intra-Handshake (strongest security).
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

[I-D.ietf-lake-ra]  
: Yuxuan, S., et al., "Remote Attestation over EDHOC", Internet-Draft, draft-ietf-lake-ra.



# Acknowledgements


<cref>TODO</cref>
