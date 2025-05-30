MCP Authorization Extension: UCAN-Based Object Capabilities

1. Introduction

Modern Model Context Protocol (MCP) implementations use bearer tokens (typically OAuth 2.1 access tokens) to authorize requests ￼. This approach provides coarse-grained, session-oriented access control but lacks the fine-grained, delegable authority that emerging agentic AI use cases demand. This extension proposal introduces object capability security, modeled after the User-Controlled Authorization Network (UCAN), as a first-class authorization mechanism in MCP. The goal is to standardize how UCAN capabilities can be used to invoke AI tools and access resources with least-privilege rights, complementing (and optionally replacing) traditional bearer-token authentication.

Object capabilities (OCAP) allow authorization to be tied to specific objects or actions, rather than an all-or-nothing token. A capability token encodes what permission is granted and to whom, in a self-contained, cryptographically verifiable credential. In UCAN's model, each capability is essentially a "noun" plus a "verb" – a description of a resource and an allowed action ￼. Unlike static OAuth scopes, these capabilities are openly extensible and can represent arbitrary granular permissions understood by the service (for example, "read file X" or "invoke Tool Y with only certain parameters"). By adopting UCAN-style capabilities in MCP, we enable secure delegation of tool access to AI agents with built-in constraints, auditability, and fine-grained control.

This proposal defines a dual authorization model for MCP: it adds UCAN-based capabilities as an alternative authorization type alongside legacy bearer tokens. It is designed to align with the existing MCP JSON-RPC transport and maintain backward compatibility. Servers may continue to accept bearer tokens as before, while optionally supporting capability tokens for more granular authorization. The extension is written as a formal specification draft, intended for consideration by the MCP standards committee, and uses terminology and normative language consistent with the MCP 2025-03-26 specification.

2. Dual-Mode Authorization Overview

MCP shall support two modes of authorization in parallel:
	1.	Legacy Bearer Tokens:  An unchanged implementation of OAuth 2.1 bearer tokens (such as API keys or OAuth access tokens) for authenticating requests, as described in the core MCP spec ￼. This remains for compatibility with existing clients and infrastructure.
	2.	UCAN Object Capabilities: A new mechanism wherein clients present UCAN capability tokens that convey specific tool or resource permissions. In this mode, authorization is tied to object capabilities (with delegated rights) rather than a static session token. The server MUST validate the UCAN's signature and contained rights before executing a request.

MCP servers SHOULD advertise which authorization modes they support (e.g. via metadata or capabilities in the MCP handshake). A server that implements this extension can operate in a dual-mode fashion, accepting either a valid bearer token or a valid capability for a given request. The server's security policy may dictate which endpoints or tools require a capability. For example, a high-privilege tool might only be invokable with a matching UCAN capability even if a broad OAuth token is present, enforcing least-privilege by design.

MCP clients must be prepared to handle both modes. A capable client MAY attempt a capability-based invocation first (if it knows the server supports it), and fall back to the legacy OAuth flow if the server returns an authorization error. In dual-mode scenarios, the server's response to an unauthorized request SHOULD indicate whether a different auth type is needed (for instance, using distinct error codes or messages for "bearer token required" vs "capability required"). This ensures smooth interoperability during the transition period.

Rationale: Maintaining two modes allows an incremental migration. Existing MCP integrations can continue to use API keys and OAuth 2.1 flows unchanged, while newer AI agent deployments can begin leveraging object capabilities for enhanced security. Over time, as capability support matures, deployments may opt to deprecate the bearer-token path and require UCAN capabilities for all AI tool invocations. The following sections detail the UCAN capability schema and how it is used within MCP's JSON-RPC transport.

3. UCAN Capability Schema for MCP

3.1 Capability Structure and Semantics

In this extension, an MCP capability is a declarative permission tying a specific resource or tool to an allowed action. We adopt the UCAN object-capability format to describe these permissions. Each capability is an object (often JSON-encoded) with at minimum the following fields:
	•	with – A URI or identifier for the resource context or tool that the capability applies to. This is the object (noun) being acted upon. For MCP tools, this could be a tool identifier or endpoint URI (e.g. a DID for the tool server, or a URI representing a particular dataset or service).
	•	can – A string describing the allowed action (verb) on that resource. This could be a method name, an operation like "read"/"write", or an MCP RPC method reference. The action string syntax is drawn from UCAN's vocabulary (often namespaced like crud/read, msg/send, etc., or specific to the tool domain).
	•	Optional fields (caveats) – Any additional constraints or context for the permission. This may include:
	•	nbf / exp – Validity period (not-before, expiration timestamps) limiting when the capability is usable.
	•	ext (or UCAN facts/policy) – Extensible conditions that must be satisfied on invocation. For example, a capability to send email might include an extension field restricting the recipient address to a certain domain.

In essence, a capability states: "The holder may perform X action on Y resource, possibly under condition Z." The UCAN design is extensible: services define the meaning of resource and action strings, and can add domain-specific caveats. There is no central list of actions – any verb understood by the server can be used ￼. This flexibility allows modeling complex permissions beyond what simple OAuth scopes allow.

Figure 1: "Anatomy of a Capability" – Each capability contains a resource (with) and an allowed action (can), akin to a noun-verb pair. The example above shows two capabilities: one permitting read access to a photo album (with: http://example.com/alice/photos/, can: crud/read), and another allowing sending email (with: mailto:borris@fisson.codes, can: msg/send). The second capability has an extension field (ext) adding a condition that the to address must end in @fission.codes. This illustrates how fine-grained constraints can be embedded directly in the capability.  ￼ ￼

For MCP, tools and resources exposed by a server would be represented in the with field. For example, a tool named "get_weather" might be represented as with: "<server-DID>/tools/get_weather" (using the server's DID as a namespace), with an action like can: "invoke" or a more specific verb. Alternatively, the action could encode the tool name (e.g. can: "tools/get_weather"), and use with to scope to the server or dataset. This specification does not mandate a singular format for the with string, but RECOMMENDS that servers use a URI or DID reference that clearly identifies the target object or service. For instance, a file resource might use a URI (with: "mcp://server.example/files/<<path>>"), whereas a general tool invocation might use the tool name as part of can. Servers and clients MUST agree on the convention through documentation or capability discovery mechanisms.

Example – Capability for an MCP Tool: Suppose an MCP server offers a tool "database.query" that allows read access to a database. A corresponding capability granting an AI agent read-only access to a specific table might look like:

{
  "with": "urn:tool:dbserver:database", 
  "can": "db/query",
  "ext": { "table": "Employees", "readonly": true },
  "exp": 1735689600
}

This (hypothetical) capability says the holder can perform the db/query action on the database resource of "dbserver", restricted to the Employees table and only read operations, and expires at a certain timestamp. The extensible nature of capabilities allows encoding such granular policies directly in the token. When the AI agent later invokes the tool, the server will verify these conditions against the actual request (ensuring, for example, that the query does not attempt to modify data because readonly:true was required).

3.2 UCAN Token Format

Capabilities in MCP are transported and cryptographically verified using UCAN tokens. A UCAN token is a secure container (JSON Web Token compatible) that holds one or more capability statements and associated metadata. UCAN tokens are JSON-based and use standard JWT structure: a base64-encoded header, payload, and signature ￼. The header typically indicates the signing algorithm (e.g. EdDSA) and may include a UCAN version (e.g. "ucv": "0.9.0" for UCAN v0.x). The payload contains the delegated capabilities and standard fields like issuer, audience, and expiry. Finally, the token is signed by the issuer's private key, yielding a signature that the verifier (audience) can check against the issuer's public key.

Conforming to the UCAN specification, an MCP UCAN MUST include the following fields in its JWT payload (note that field names are lowercase to match UCAN JWT conventions):
	•	iss (Issuer): the DID of the entity granting the capability. This could be a user's DID or an intermediate agent in a delegation chain. In an initial token issued by a resource owner, iss might represent the user or organization.
	•	**aud``** (Audience): the DID of the entity to whom the capability is delegated. In most MCP scenarios, the *audience will be the MCP server's DID* (or a specific tool service's DID) that is expected to honor the token. By setting aud` to the server, we ensure the token is only intended for that server (it will not be valid if presented elsewhere, since other servers won't match the audience).
	•	capabilities (or att in UCAN v0.x): an array of one or more capability objects (each with with, can, etc. as defined above) that the token grants. The server will interpret these to decide what actions are authorized. For UCAN v1.0+, this may be represented through a single delegated capability (cmd/pol fields) – but the semantics are equivalent.
	•	nbf / exp: Not-Before and Expiration timestamps, to define the token's valid time window. All capability tokens MUST have a finite expiration (exp) to limit risk. Servers SHOULD reject any token without an expiration or with an expiration too far in the future (per their policy).
	•	prf / proof (if present): One or more proof tokens – i.e., other UCANs – that this token is built upon. This field is used for delegation chaining (see next section). Each proof is a UCAN (embedded by reference or by value) that the current token relies on as authority. For example, if Alice delegates to an agent (producing token A), and the agent further delegates to another agent (token B), token B will include token A as a proof. Proofs enable the verifier to reconstruct the chain of trust back to an original authority.

A UCAN token in transit is typically a compact string (URL-safe base64). For readability, here is a simplified illustration of a UCAN payload (JSON) carrying one capability:

{
  "iss": "did:example:alice",          // Issuer (delegator DID)
  "aud": "did:example:mcp-server",     // Audience (target MCP server DID)
  "exp": 1735689600,                   // Expiration time (Unix timestamp)
  "att": [                             // Attenuations (capabilities)
    {
      "with": "mcp:tools/translator", 
      "can": "translate/text",
      "ext": { "lang": "fr" }
    }
  ]
}

This token's capability (in att[0]) says Alice allows the holder to invoke the "translator" tool to translate/text (a made-up action) and perhaps restricts the language to French via the lang condition. The token would be signed by Alice's key. Upon receiving this token, the MCP server identified by did:example:mcp-server will verify the signature and check that the described capability covers the requested operation.

Security properties: UCAN capability tokens are self-describing and verifiable. The server does not need to consult a central auth server or database to know what the token permits; it can inspect the token's payload to see the allowed with/can and ensure the signature (from iss) is valid. If the issuer is not known a priori, the server can resolve the issuer's DID to obtain the public key. Because the token lists its issuers and audience, it inherently provides an audit trail of who delegated authority to whom at each step. This is a significant improvement in auditability over opaque bearer tokens, which convey no delegation history. As noted by one of UCAN's authors, a capability token "contains all of the information you need for invocation" – effectively combining authorization and the invocation context into one package ￼ (though in MCP we still transmit the invocation as a JSON-RPC call, the token carries the authority for that call).

3.3 Delegation and Attenuation Model

A core feature of UCAN capabilities is delegation: any entity that holds a capability can further delegate a subset of its authority to another entity by issuing a new UCAN token. This creates a chain (or proof chain) of trust. Each link in the chain is a UCAN signed by the delegator, and includes the previous token as a proof. In a valid chain, each successive token can only attenuate (narrow or equal) the permissions of its predecessor – it cannot expand them. This aligns with the principle of least authority, ensuring that delegation cannot accidentally or maliciously escalate privileges ￼.

For example, consider a user who has a broad capability (like access to an entire database). The user's agent might delegate a narrower capability to a sub-agent, such as access to only one table. That sub-agent could further delegate an even more restricted capability (perhaps read-only access to a single column) to a temporary worker. Each delegation is represented by a UCAN, and the final UCAN presented will carry proofs of the earlier delegations. The MCP server, as the ultimate verifier, will walk the chain of proofs included with the presented token to ensure: (a) each token in the chain was properly signed by its issuer, (b) each token's iss matches the aud of the previous token (so the chain links are unbroken), and (c) the final requested action is within the intersection of all capabilities in the chain. If any link is invalid (signature wrong, expired, or trying to grant a broader access than its parent), the server MUST reject the entire chain as unauthorized.

The delegation chain provides an audit trail of how authority was passed along. Because UCANs use DIDs for principals, each issuer is a cryptographically verifiable identity. Servers SHOULD log the relevant DID chain when a capability is used, to facilitate later audit – one can see which user originally authorized an action and through which agents it passed. This is a level of transparency not available in single-hop bearer token use. Moreover, capability chains are verifiable offline: given the tokens, one can validate the chain purely with public keys, without needing the original issuer online ￼.

It is important to note that revocation in a capability system is an additional consideration. In OAuth, a bearer token can typically be revoked by the authorization server (making it immediately invalid). With UCAN, since tokens are often self-contained and offline-verifiable, revocation is handled by separate revocation lists or very short expirations. This proposal encourages short-lived UCANs and/or the implementation of a revocation mechanism (such as a special revocation endpoint or a ledger of revoked UCAN CIDs) – however, the specifics of revocation are beyond the scope of this document and can follow the emerging UCAN Revocation spec if needed. Servers MAY refuse to honor a capability token that, while not expired, is known (by CID or other ID) to be revoked. In practice, rotating capabilities frequently or tying them to user sessions can achieve similar safety as OAuth's revocable tokens.

4. Capability Invocation Flow in MCP

This section describes how an AI agent (MCP client) would use a UCAN capability to invoke a tool on an MCP server, and how the server processes such an authorized call. The flow is modeled to fit into MCP's existing JSON-RPC message exchange.

4.1 Obtaining Capabilities (Delegation Flow)

Capability issuance can happen out-of-band or via MCP itself, depending on the use case:
	•	In a typical scenario, a human user or an application (the resource owner) will first authenticate normally to the MCP server (e.g. via OAuth 2.1 web flow or other means) and establish their identity. At this point, rather than (or in addition to) obtaining a bearer access token, the user can obtain a UCAN capability token for the tools/resources they want to permit an AI agent to use. This could be done through a special endpoint or a UI provided by the server. For example, an MCP management UI might let the user check a box for "Allow AI Assistant to call Tool X on my behalf" – which under the hood generates a UCAN signed by the server (or by the user's own key, if available) delegating just that tool access to the agent's DID.
	•	Alternatively, if the user's agent itself has a cryptographic identity (DID), the user could directly sign a capability and hand it to the agent. In practice, not all users will have personal DIDs or keys ready, so the server might act as an issuer on the user's behalf. One implementation approach is a capability exchange: the client connects to the server with a bearer token (proving the user authenticated), and calls a method like auth/delegate to request a UCAN. The server, seeing a valid user session, then issues a UCAN token embedding the requested capabilities (within the scope of what the user is allowed) and signs it as the issuer (iss = server's DID or the user's DID under server control). The aud would be the agent's DID. The client (AI agent or its controlling app) receives this UCAN and will use it for subsequent calls.
	•	In a delegation chain scenario, there may be multiple hand-offs. For instance, User -> Orchestrator -> Tool-specific Agent. Each party would create a UCAN for the next, as allowed. Ultimately, the agent directly calling the MCP server holds a token whose aud is the server.

However the capability is obtained, at the end of this step the calling client possesses one or more UCAN tokens that grant it specific tool permissions on the target MCP server. It also should have the proof chain (if any beyond the last token), though these can be bundled in the token itself.

4.2 Invoking a Tool with a Capability (Request Flow)

Once an agent has a capability token, invoking the tool is straightforward, with a couple of options for how the token is presented:

Option 1: HTTP Authorization Header (Bearer UCAN) – Since UCAN tokens are JWT-compatible, the client SHOULD transmit the capability in the standard HTTP Authorization header, using the Bearer scheme. For example:

Authorization: Bearer eyJhbGciOiJF...<token>...sig...

The MCP server, upon receiving a request with this header, will detect that the token is a UCAN (e.g., by its structure or claims). One team's experience with UCAN notes that this approach "plugs right into their Rust server as a bearer token in the header," which then simply needs to invoke a UCAN library to interpret it ￼. In other words, from a transport perspective it looks like a typical bearer JWT, which maximizes compatibility with HTTP middleware and existing infrastructure ￼.

Servers implementing this extension MUST attempt UCAN verification on any incoming bearer token that is not a valid OAuth access token. Concretely, if the Authorization: Bearer ... value doesn't validate as an OAuth token, the server should treat it as a potential UCAN:
	•	Parse the JWT.
	•	If the payload contains expected UCAN fields (iss, aud, maybe att or capabilities, etc.), proceed to verify signature and evaluate the capability.
	•	Important: The server needs its own DID or identifier to compare with the token's aud. The token is intended for this server only if aud matches the server's DID or a trustable identifier (e.g., an OAuth client ID representing the server). If not, the token is not meant for this server and must be rejected.
	•	If verification succeeds, authorize the request only for the operations allowed by the capability. If the client tries to invoke a different method or resource not covered, the server MUST deny it (as a forbidden operation).
	•	If the token is expired, not yet valid, revoked, or the signature fails, the server MUST treat it as invalid (respond with HTTP 401 or 403 as appropriate).

The actual JSON-RPC request would then be processed normally. For example, an HTTPS request to call a tool might look like:

POST /v1/mcp HTTP/1.1
Host: api.example.com
Authorization: Bearer <UCAN-token>

{ "jsonrpc": "2.0", "id": 42, "method": "tools/call", "params": { "name": "X", ... } }

The server will verify the token from the header before executing the tools/call. The token's capability might say the client can call tool X; the server checks that "name": "X" in params matches that permission. If everything checks out, the call proceeds. If not (say the token was only for tool X but the client is calling tool Y), the server returns an authorization error.

Option 2: In-JSON Capabilities Field – In non-HTTP transports (or to allow multiple tokens), this extension defines an optional JSON-RPC parameter to carry capabilities. MCP over WebSocket or other transports may not use an HTTP header; instead, the JSON-RPC message itself can include an "authorization" field or similar. We propose a reserved top-level field in the request object (not inside params to avoid clashing with method-defined params): for example, a request object could include "capabilities": [ "<UCAN-token1>", "<UCAN-token2>" ] alongside method, id, etc. JSON-RPC 2.0 does not forbid additional members in the request object, so a compliant implementation would typically ignore unknown members if not supported. Servers supporting this extension MAY accept a "capabilities" array or a single "capability" field in requests. Each entry would be a UCAN token (as a string). The server would extract them and perform the same verification as above.

For backward compatibility, if a server does not understand the "capabilities" field, it will likely return an error (maybe "invalid params" if strict). Therefore, clients should use this in negotiated environments or alongside an Authorization header for safety. The advantage of in-JSON is the ability to send multiple capability proofs if needed, and applicability to persistent connections.

Note: At the time of writing, the favored approach for HTTP is the Authorization header, given its simplicity and existing support. For ucanto (the UCAN RPC library used in Bluesky and related systems), capabilities are often sent as payloads (e.g., in CAR files or as JSON arrays) in a single request ￼ ￼. MCP can accommodate either style. This proposal is agnostic to the exact wire encoding as long as the server ultimately receives the UCAN token(s) to validate. The focus is on the semantics of authorization, not the transport bits.

4.3 Server-side Processing

On the MCP server, integrating capability checks involves augmenting the request handling pipeline:
	•	Authentication vs Authorization: The server must map the UCAN to an authenticated principal. With OAuth, the access token implicitly represents a user or client identity and attached scopes. With UCAN, the token itself carries the identity of the issuer (iss) and the fact that iss delegated to aud (often the server). In many cases, the iss will correspond to a user's DID or the DID of an upstream service. The server may want to treat that iss as the acting user for logging and context. For instance, if Alice's DID signed the token, the server knows "this request is on behalf of Alice." We preserve the notion of resource owner by using sub or iss in UCAN – the UCAN spec's Subject (sub) field can convey the original principal if needed (often sub is set to the root delegator's DID). Servers SHOULD use these fields to attribute actions to the correct user (e.g., in audit logs or when enforcing per-user quotas).
	•	Capability validation: The server must ensure the requested action is allowed by some capability in the token chain. This involves matching the JSON-RPC request to a capability:
	•	The resource: depending on how with is defined, the server checks that the target of the RPC (the tool or resource being accessed) matches the with. If with is a general server URI or DID, the server might require further checking in ext conditions. If with encodes a specific sub-resource (like a file path or tool name), it should directly correspond.
	•	The action: determine what action the RPC call represents. For a tools/call invocation, the action could be the tool name or an abstract "invoke" action on that tool. For a direct resource access (if MCP were used for fetching a resource), it could be "read" or "write". The capability's can must cover this action. Matching can be exact string match or a hierarchical match (UCAN supports wildcard or namespace semantics, e.g., crud/read might be a subset of crud/*).
	•	Arguments constraints: If the capability has caveats like ext conditions (e.g., allowed email recipient domain, allowed file path prefix, etc.), the server must inspect the actual request parameters to ensure they satisfy these conditions. This might require method-specific logic. For example, if a capability says ext: { "to": ".*@fission.codes" } for an email-sending tool, the server code handling the send_email method must check that the "to" parameter in the request matches the regex .*@fission.codes. If not, the invocation is denied as it violates the capability's policy ￼.

If all checks pass, the server authorizes the execution. It may then proceed to enforce any additional Trust & Safety checks (which is outside the scope of this auth spec) and ultimately perform the tool action. The response is returned to the client as usual. The server SHOULD include in the response or logs which capability (by some identifier or the token CID) was used to authorize the action, to aid in auditing.

4.4 Example Flow

To solidify the concept, consider an illustrative example:
	•	Scenario: An enterprise uses an MCP server that provides a tool "analysis.exportReport", which allows exporting a financial report. This action is sensitive, so they want fine control over which AI agents can do it, and under what conditions.

	1.	User delegation: The company's IT admin, Alice (DID did:corp:alice), wants to permit an AI assistant (running with DID did:agent:assistant1) to use the exportReport tool, but only for reports in the "Q4" folder and only until the end of the week. Alice authenticates to the MCP server (perhaps via an OAuth login) and uses an admin dashboard to create a delegation. The server interface lets her specify the tool and conditions. Upon confirmation, the MCP server's auth module generates a UCAN token:
	•	iss = did:corp:alice (assuming Alice has a key; or the server uses its own issuer but notes Alice in sub field)
	•	aud = did:agent:assistant1 (the agent's DID that will receive this token)
	•	Capability: with = mcp:tools/analysis.exportReport, can = invoke/export, ext = { "folder": "Q4" }
	•	exp = <Unix timestamp for this Friday 23:59>
This token is signed by Alice's key (or a corporate key on her behalf) and given to the AI assistant (perhaps as a file or via a secure transfer). Now the assistant holds a capability granting it just the power to export Q4 reports.
	2.	Invocation: The AI assistant, integrated into a financial analysis app, decides it needs to call analysis.exportReport on the MCP server to fetch a chart. It prepares the JSON-RPC request:

{ 
  "jsonrpc": "2.0", "id": 1001, "method": "tools/call", 
  "params": { "name": "analysis.exportReport", "arguments": { "path": "/reports/Q4/summary.xlsx" } }
}

It attaches the UCAN capability token in the HTTP Authorization header as Bearer <token>.

	3.	Verification: The MCP server receives the request. It sees the Authorization header and decodes the token:
	•	Signature checks out (signed by did:corp:alice, and the server knows/trusts Alice's public key via the corporate DID registry).
	•	aud matches the server's DID, good.
	•	The capability says with: mcp:tools/analysis.exportReport and can: invoke/export with folder = Q4. The server maps this to the current request: the requested tool "analysis.exportReport" matches the with (or is a subset of it if wildcards were used). The action is essentially "invoke exportReport", which fits invoke/export (assuming that's the defined verb for using that tool).
	•	It then checks the argument: the path "/reports/Q4/summary.xlsx" indeed lies in the Q4 directory as required by the folder: "Q4" condition. All good.
	•	Token is not expired (it's only Wednesday), and not-before is fine.
The server concludes the agent is authorized only for this specific operation.
	4.	Execution: The server executes the tool, which gathers the Q4 summary report and returns the result. The JSON-RPC response is sent back to the assistant. The server logs might record: "analysis.exportReport invoked by assistant1 (delegated from alice) on resource /reports/Q4/summary.xlsx." If the assistant later tries to export something outside Q4 or after the token's expiry, the server will reject those calls.

This example demonstrates how object capabilities allow precise access control in MCP, far beyond what a generic API key would do (which might have let the assistant export any and all reports). The delegation chain in this case was just one link (Alice -> Assistant), but could be longer if needed. The use of DIDs ensures identities are clear at each step, and cryptographic signatures prevent forgery.

5. JSON-RPC Encoding and Backward Compatibility

One design goal of this proposal is minimal disruption to existing MCP clients and servers. The introduction of capabilities is done in an additive manner:
	•	No changes to core JSON-RPC schema: The JSON-RPC request and response structures remain as defined in the MCP spec. Authorization in HTTP transports is handled via headers (or an out-of-band negotiation for other transports). Thus, an unmodified MCP server that doesn't understand capabilities will simply ignore the Authorization header if it doesn't recognize the token, and likely return an HTTP 401 (Unauthorized). There is no change to required JSON fields that would break older clients. Only in advanced use (Option 2 with "capabilities" field in JSON) is there a potential incompatibility, and that is optional and to be used in controlled scenarios.
	•	Use of JWT for UCAN: UCAN tokens are encoded in JWT format specifically to leverage the existing tooling for tokens ￼. Many programming frameworks have JWT parsing middleware that will accept a token from the Authorization header and decode claims. While those libraries won't validate a UCAN out of the box (since validation requires checking a DID signature, not a shared secret or traditional JWT signing key), this approach means adding UCAN support is as simple as adding a UCAN verification step after the token is extracted. It "looks like" a standard bearer token during transport ￼. In fact, one can store UCAN tokens in systems like cookies or HTTP headers just as with OAuth tokens.
	•	Server advertisement: To facilitate a smooth upgrade path, an MCP server SHOULD advertise its support for UCAN capabilities. This could be done in the OAuth 2.0 Authorization Server Metadata document (e.g., add "capability_authorization_supported": true) or a field in the MCP version handshake. For example, when a client connects, the server's capabilities JSON could include:

"authorization": {
    "bearer": true,
    "ucan": true,
    "ucan_version": "1.0"
}

This is an illustrative structure – the MCP spec might formalize such a field. If the server does not advertise UCAN support, clients SHOULD assume only bearer tokens are accepted.

	•	Fallback behavior: A client that possesses a UCAN token but isn't sure the server supports it can attempt to use it. If the server returns 401 Unauthorized, the client can then initiate the OAuth flow as per current spec ￼. This does mean an extra round-trip in the worst case. To avoid that, future MCP discovery could integrate auth methods (as above). Conversely, a client might initially authenticate via OAuth and then upgrade to UCAN by exchanging the token – this dual strategy ensures the request will be authorized one way or another. The dual-mode approach guarantees that introducing capabilities does not prevent any legacy integration from working as before; it only adds new possibilities.
	•	Compatibility with OAuth scopes: In some deployments, it may be desirable to link OAuth scopes with capabilities. For example, an OAuth access token might carry a scope "mcp.tools.export" indicating general export permission. A UCAN could convey a narrower version of that. Servers could choose to accept UCAN tokens in lieu of OAuth tokens for certain scopes. During a transition, a server might even internally mint a UCAN for the client based on an OAuth token's scopes (essentially converting one format to the other). This is implementation-specific and not mandated here, but it's a viable strategy to bridge the systems.

In summary, backward compatibility is maintained by making the UCAN auth path optional and parallel. Clients and servers that are updated to support it will negotiate or try it, while others will continue with bearer tokens seamlessly.

6. Security Considerations and Comparison of Approaches

Object-capability authorization via UCAN brings significant security benefits to MCP, especially in the context of AI agents acting on behalf of users. Below we highlight comparisons between the UCAN capability model and the traditional bearer-token model in terms of security, granularity, and auditability:
	•	Granular Least-Privilege Access: UCAN capabilities allow precise specification of what an agent can do. Bearer tokens typically grant broad access (e.g., "user X can use all tools on server Y until token expiry"). Even OAuth scopes, while narrower, are predefined and coarse-grained (e.g., "read all files" or "use tools:*.read"). In contrast, a capability can be as granular as "use this specific tool on this specific resource with these constraints". This ensures an AI agent gets only the minimum authority it needs. Following the principle of least privilege reduces the blast radius if the agent is compromised or goes rogue. For example, if an LLM is prompted maliciously, a bearer token might let it delete all user data, whereas a well-crafted capability might only allow read access to one folder, preventing greater harm.
	•	Delegation with Accountability: In bearer systems, delegation (sharing access) is either not possible or done insecurely (by sharing your token or key, which is discouraged). With UCAN, delegation is a first-class feature: one entity can delegate to another without exposing its full credentials. Every delegation is signed and traceable. This provides accountability: the chain of iss -> aud in UCANs means you can always identify which principal ultimately authorized an action. In an enterprise setting, this could map to an audit log entry: "Assistant acted on behalf of Alice, who acted on behalf of OrgAdmin." Bearer tokens lack this chain; if a token is misused, it's often hard to ascertain who (or what) shared it or how it was acquired by an attacker.
	•	Transparency and Auditability: As mentioned, UCAN tokens carry human-readable (and machine-enforceable) descriptions of allowed actions. This makes access rights auditable at rest. A security reviewer can inspect a stored UCAN token and immediately see what it permits, and until when. They can also verify it independently of the server (given the public keys). Bearer tokens are opaque; the effective permissions live on the server side (in ACLs or scope interpretation), making it harder to audit what a stolen or leaked token could do. With UCAN, even if a token is leaked, it has a very clear, limited use which can be understood and then revoked or left to expire. Moreover, capabilities can be composed safely – multiple small rights don't automatically combine into a bigger right unless explicitly delegated together (and even then, the union is explicitly encoded and signed). This contrasts with scope-based systems where combining scopes can unintentionally create broader access.
	•	Security of Transfer: Both bearer tokens and UCAN tokens are bearer instruments in the sense that whoever holds the token can use it (there is no further proof-of-possession by default). UCAN does support the notion of an audience key, but generally if an attacker obtains the token string, they can present it until expiry. This is why both systems rely on TLS transport and token secrecy. In that regard, they are similar. However, capabilities can be made non-transferable in practice by tying them to a specific audience (the agent's DID) and possibly requiring the agent to authenticate as that DID (e.g., by establishing a DID-based secure channel). Bearer tokens typically don't distinguish between Alice's token used by Alice vs. stolen and used by Mallory – the server will treat it the same. With UCAN, since the token's issuer chain is known, misuse can potentially be detected (if an agent suddenly uses a token outside expected context, it can be flagged by anomaly detection using DID context).
	•	Revocation and Lifecycle: As noted, bearer tokens usually have short lifetimes or revocation lists maintained by the server (e.g., refresh token rotation). UCAN's decentralized nature shifts some responsibility to token issuers – tokens should be short-lived or actively revoked via separate channels if needed. One advantage in UCAN's favor is composability with content addressing: a UCAN can be assigned a content ID (CID) which can be used to check revocation or deduplicate tokens. Logging the usage of capability CIDs provides a clear audit trail (e.g., "token X was used at time T for action Y"). Revocation remains a challenge: an organization might decide to revoke all capabilities delegated by a departing employee – this can be done by having a revocation list of UCAN CIDs issued by that employee. Though less immediate than centralized revocation, this is a trade-off for the offline and distributed benefits of OCAP. In practice, a hybrid approach can be used: the server may accept UCANs only if presented along with a valid bearer session or after a one-time OAuth authentication, thereby allowing it to kill the session which indirectly stops capability use.
	•	Complexity and Overhead: A bearer-token system is straightforward – a single opaque string check. UCAN verification is more complex: verifying signatures, walking delegation chains, parsing conditions. This introduces some overhead in request processing. However, the overhead is manageable: UCAN tokens are typically small (hundreds of bytes) and involve ED25519 or similar signature checks which are quite fast. Caching strategies (e.g., remembering that token X was checked recently) can mitigate repeated cost. The design also allows the capability verification to be decoupled – one could imagine a separate service or middleware handling UCAN validation and only passing through requests that are authorized (for instance, a gateway that processes the Authorization header). This could be scaled independently if needed for performance. Additionally, by narrowing authority, UCAN can reduce the need for additional authorization logic in the application (the token itself does half the work), which can simplify the overall system.

In summary, UCAN-based capabilities bring greater security granularity and clarity at the cost of a bit more complexity in validation. They complement the existing OAuth model by introducing a scoped, verifiable, delegation-friendly mode of authorization suitable for the multi-agent scenarios MCP envisions. Table 1 contrasts key aspects:

Aspect	Bearer Tokens (OAuth API keys)	UCAN Capabilities (OCAP)
Delegation	Not inherently supported (sharing token disfavored); requires centralized issuance for any new token.	Built-in delegation chaining; each party can attenuate and re-delegate authority with cryptographic proof.
Granularity	Coarse scopes (often all-or-nothing or broad categories).	Fine-grained, can target single object or action; arbitrary conditions possible.
Identification	Token itself doesn't indicate who holds or issued it (mapped server-side to a user/session).	Token carries issuer and audience DIDs; provenance of authority is explicit in token.
Verification	Server checks a token against a database or introspects JWT (signature by known authority).	Server verifies signatures of possibly multiple issuers (DIDs) and evaluates capability logic.
Revocation	Centralized: immediate invalidation by server possible (token lookup or short TTL).	Decentralized: relies on short expiration or external revocation list; harder to immediately revoke unless designed.
Audit Trail	Limited: need server logs linking token to user; token reuse hard to attribute if leaked.	Strong: each use tied to a token that names issuers. Chains can be inspected after the fact to see delegation path.
Usage in MCP	Already implemented (OAuth2.1) ￼; good for user-level consent flows.	New extension; ideal for tool-level permissions and automated agent authorization.

Both models can coexist to serve different needs. Simpler integrations might stick with bearer tokens, while advanced security-conscious deployments will prefer issuing tightly-scoped UCAN capabilities for AI agents. Notably, UCAN capabilities can be made interoperable with existing systems – since they can be encoded as JWTs, they can often be stored and transmitted in places expecting a token without modification ￼. As Brooklyn Zelenka (one of UCAN's creators) observed, using JWT encoding means "it works with all of [our] existing tools" and slots into the Authorization header just like a normal bearer token ￼. The heavy lifting is in the interpretation, which this spec addresses for MCP.

7. Migration Path for MCP Implementations

Adopting object capabilities in an existing MCP ecosystem will be a gradual process. This section outlines a possible migration strategy:

Phase 0: Design and Experimentation. (Current phase) MCP community discusses and refines the capability extension (this document). Pilot implementations may appear as plugins or forks of MCP servers to prove out the concept with one or two tools. During this phase, feedback is gathered on the schema and integration approach (e.g., header vs param).

Phase 1: Optional Support in Servers. MCP servers introduce beta support for UCAN capabilities alongside OAuth. This might involve:
	•	Assigning a DID to the server (if not done already) to use as audience and possibly as an issuer for delegation.
	•	Implementing UCAN verification logic (either via an existing UCAN library or a custom verifier following the spec).
	•	Adding configuration to enable capability auth. By default, it could be off to avoid any behavior change; admins can turn it on.
	•	Documenting the specific resource and action strings the server recognizes for its tools (so clients can request proper capabilities).

In this phase, servers would likely still require a bearer token or capability. For example, an MCP server might require initial OAuth authentication to get any access, but then accept UCANs for subsequent calls. Or it may allow either on equal footing. It's up to the server policy. The key is that nothing breaks for existing clients.

Clients (like AI orchestration frameworks, e.g. LangChain or Copilot agents) can then be updated to take advantage. A client might gain the ability to request a UCAN from the user or include a provided UCAN in calls. This could be an opt-in feature (e.g., a flag like use_capabilities=True). We may see libraries that help users create UCANs for MCP (potentially using services like Kepler, DID key resolvers, etc., to handle keys if users don't have them).

Phase 2: Ecosystem Tooling and Best Practices. As adoption grows, best practices will emerge:
	•	CapBot / Capability Authority: Organizations might run a service that issues capabilities on demand. For instance, a company could integrate with their SSO so that when an AI assistant logs in, instead of giving it an API key, the system issues a tailored UCAN for that session. We might see "capability issuance endpoints" standardized (akin to OAuth token endpoints, but returning UCANs).
	•	User Experience: For end-users, UIs need to simplify capability management. We expect MCP UIs where a user can see "Active AI Permissions" – a list of UCAN capabilities they have delegated, each possibly with an on/off switch or revoke button. This makes the normally invisible token-based auth more transparent. Educating users that they can grant a specific permission to an AI, and later revoke it, will improve trust in AI agents.
	•	Logging and Monitoring: Enterprises will integrate capability usage into their monitoring. Alerts could be set if an agent tries actions outside its capability (which would cause server denials), possibly indicating a compromised agent or a prompt injection attempt.

During this phase, both authorization modes are still available. We expect many deployments to run in hybrid mode for an extended period.

Phase 3: Capability-First or Capability-Only. Once the community has confidence in the capability approach, new MCP features and tools might require capabilities. For example, imagine a sensitive MCP tool that will not even issue an OAuth scope; it only works if a valid capability token with certain predicates is presented. This could be voluntary ("our tool is high-risk, so we enforce OCAP") or standardized ("MCP 2.0 deprecates bearer tokens entirely"). In this hypothetical future, agents would operate almost entirely with UCANs, and bearer tokens would be used only for initial bootstrap (or not at all, if users manage their own keys).

Existing implementations would migrate by:
	•	Converting internal permission checks to rely on capabilities.
	•	Phasing out long-lived bearer tokens (maybe replacing them with long-lived refresh tokens that mint short-lived UCANs).

Even if we reach a "capability-only" world, it's likely that under the hood some compatibility remains (since UCAN can be carried as JWT, even OAuth infrastructure could carry a UCAN as the token). The difference would be philosophical: security is defined by capabilities, not by who you are alone.

Impact on Standards and Interop: This extension is aligned with trends in the broader industry (e.g., decentralized auth in Bluesky's AT Protocol using capabilities, W3C verifiable credentials, etc.). By standardizing UCAN in MCP, we open the door to cross-ecosystem interoperability. For instance, a capability issued in a different context (say a Bluesky data server) could, if the format matches, be presented to an MCP server if that makes sense, and vice versa. This creates possibilities for a web of trust and authorization beyond siloed API keys.

During migration, documentation is crucial. MCP spec should include a section (if this proposal is accepted) describing how to implement both modes. SDKs will need updates:
	•	The MCP client SDK can include methods like authorize_with_ucan(token) or even handle requests for capabilities from the user.
	•	The MCP server SDK can provide middleware to do UCAN verification and expose the resulting principal and permissions to the tool-handling code.

Finally, a migration success will be measured by security improvements in real deployments. We expect to see reports of, e.g., "We integrated UCAN capabilities and prevented an AI from deleting data it wasn't supposed to – something that might have happened if we had given it a broad API key." Community feedback will refine the approach (for example, we might add more standardized ext conditions for common patterns like read-only, or a registry of action verbs for common tool types to encourage consistency).

8. Conclusion

This extension proposal has presented a comprehensive blueprint for integrating UCAN-style object capabilities into the Model Context Protocol. By doing so, MCP can leverage state-of-the-art authorization techniques to ensure AI tools and agents operate safely, with the least privilege necessary, and with robust mechanisms for delegation and accountability. We described how a capability conveys a noun and verb (resource and action) with optional fine-grained constraints ￼, how such capabilities are encoded, transmitted, and validated in MCP's JSON-RPC framework, and how they compare favorably to traditional bearer tokens in granularity and auditability.

We also outlined a dual-mode strategy where both legacy bearer tokens and UCAN capabilities can coexist, enabling gradual adoption without breaking existing systems. Over time, as comfort with object capabilities grows, MCP could transition to a more capability-driven model for authorization – aligning with broader industry moves towards decentralized, user-controlled auth. Crucially, this design maintains interoperability: UCAN tokens can ride over JSON-RPC and HTTP just as existing tokens do ￼, and can interoperate with libraries like ucanto (which represents RPC calls as UCAN invocations in a similar spirit to our approach) ￼.

We recommend MCP implementations and the standards committee evaluate this proposal, experiment with prototype implementations, and iterate on the details (such as exact JSON fields or discovery metadata) as needed. The end result will be a more secure MCP ecosystem where users can trust that AI agents have explicit, limited permissions and where those permissions are easy to reason about and manage. This capability-oriented approach aligns with the long-term vision of agentic computing that is both powerful and safe by construction ￼ ￼.

References and Footnotes:
	•	The UCAN Specification and related sub-specs (Delegation, Invocation, etc.) provide the formal definitions of the fields and behaviors referenced ￼ ￼ ￼.
	•	MCP Specification (2025-03-26) – Authorization section for existing OAuth flows ￼.
	•	Brooklyn Zelenka's talk on decentralized auth – for conceptual explanations of capabilities vs ACLs ￼ ￼.
	•	Bluesky's AT Protocol and ucanto library – real-world usage of UCAN for a distributed social network (demonstrating viability at scale).
	•	W3C DID and Verifiable Credentials – complementary standards that play well with UCAN (for identity and credential format, respectively).