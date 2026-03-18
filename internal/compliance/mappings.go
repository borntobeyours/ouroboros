package compliance

import "github.com/borntobeyours/ouroboros/pkg/types"

// cweToMappings maps normalised CWE identifiers (e.g. "CWE-89") to the
// compliance requirements that cover that weakness class.
var cweToMappings = map[string][]types.ComplianceMapping{

	// ── Injection ─────────────────────────────────────────────────────────────

	"CWE-79": { // Cross-site Scripting (XSS)
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "XSS is a form of injection where untrusted data is rendered in a browser."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent injection attacks including cross-site scripting."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Establish secure development practices to prevent XSS."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate and sanitise all user-supplied inputs."},
	},

	"CWE-89": { // SQL Injection
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "SQL injection allows attackers to interfere with database queries."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent SQL injection through parameterised queries."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Use parameterised queries and ORMs to prevent SQL injection."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate and sanitise database inputs."},
	},

	"CWE-94": { // Code Injection
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "Code injection allows execution of attacker-controlled code."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent code injection through input validation."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Disallow dynamic code execution from user inputs."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate and reject inputs that could be executed as code."},
	},

	"CWE-77": { // Command Injection
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "Command injection allows execution of OS commands."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent OS command injection through input validation."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Avoid passing user input to OS command interpreters."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate inputs to prevent command injection."},
	},

	"CWE-78": { // OS Command Injection
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "OS command injection allows shell command execution."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent OS command injection."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Sanitise all data passed to shell commands."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate and sanitise inputs before OS command usage."},
	},

	"CWE-90": { // LDAP Injection
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "LDAP injection modifies directory service queries."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent LDAP injection through input encoding."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Use safe LDAP libraries that escape special characters."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate inputs to LDAP query components."},
	},

	"CWE-643": { // XPath Injection
		{Framework: types.FrameworkOWASP, RequirementID: "A03:2021", RequirementName: "Injection", Description: "XPath injection allows manipulation of XML queries."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent XPath injection through parameterised queries."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Use parameterised XPath to prevent injection."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Sanitise inputs used in XPath expressions."},
	},

	// ── Access Control ─────────────────────────────────────────────────────────

	"CWE-22": { // Path Traversal
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "Path traversal allows access to files outside the intended directory."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent path traversal via canonicalisation of file paths."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Validate and canonicalise file paths before access."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate file path inputs to prevent traversal attacks."},
	},

	"CWE-284": { // Improper Access Control
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "Improper access control allows unauthorised operations."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "7.2", RequirementName: "Access Control Systems", Description: "Implement access control systems to restrict access based on least privilege."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-6", RequirementName: "Access Control Management", Description: "Establish and maintain an access granting process."},
		{Framework: types.FrameworkNIST, RequirementID: "AC-3", RequirementName: "Access Enforcement", Description: "Enforce approved authorisations for access to systems and data."},
	},

	"CWE-285": { // Improper Authorisation
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "Improper authorisation allows attackers to perform restricted actions."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "7.2", RequirementName: "Access Control Systems", Description: "Enforce authorisation checks for all sensitive operations."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-6", RequirementName: "Access Control Management", Description: "Enforce authorisation before executing sensitive operations."},
		{Framework: types.FrameworkNIST, RequirementID: "AC-3", RequirementName: "Access Enforcement", Description: "Enforce authorisation policies on all access requests."},
	},

	"CWE-862": { // Missing Authorisation
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "Missing authorisation check allows unauthenticated access to resources."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "7.2", RequirementName: "Access Control Systems", Description: "Ensure all endpoints perform authorisation checks."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-6", RequirementName: "Access Control Management", Description: "Ensure all functions verify user authorisation."},
		{Framework: types.FrameworkNIST, RequirementID: "AC-3", RequirementName: "Access Enforcement", Description: "Enforce authorisation checks for every access decision."},
	},

	"CWE-863": { // Incorrect Authorisation
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "Incorrect authorisation grants access to the wrong principals."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "7.2", RequirementName: "Access Control Systems", Description: "Verify authorisation logic correctly maps users to permissions."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-6", RequirementName: "Access Control Management", Description: "Review authorisation logic to prevent privilege confusion."},
		{Framework: types.FrameworkNIST, RequirementID: "AC-3", RequirementName: "Access Enforcement", Description: "Ensure authorisation correctly reflects intended access policies."},
	},

	"CWE-639": { // Insecure Direct Object Reference (IDOR)
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "IDOR allows access to objects belonging to other users."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "7.2", RequirementName: "Access Control Systems", Description: "Use indirect object references or validate object ownership."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-6", RequirementName: "Access Control Management", Description: "Validate that users can only access their own resources."},
		{Framework: types.FrameworkNIST, RequirementID: "AC-3", RequirementName: "Access Enforcement", Description: "Enforce object-level authorisation on every request."},
	},

	"CWE-352": { // Cross-Site Request Forgery (CSRF)
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "CSRF tricks authenticated users into executing unwanted actions."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Implement CSRF tokens to prevent cross-site request forgery."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Use synchroniser tokens or SameSite cookies to prevent CSRF."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-23", RequirementName: "Session Authenticity", Description: "Protect session integrity against cross-site request forgery."},
	},

	"CWE-601": { // Open Redirect
		{Framework: types.FrameworkOWASP, RequirementID: "A01:2021", RequirementName: "Broken Access Control", Description: "Open redirect forwards users to attacker-controlled URLs."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Validate redirect targets against an allowlist."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Validate redirect destinations before forwarding users."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate URL parameters used for redirects."},
	},

	// ── Authentication & Session Management ───────────────────────────────────

	"CWE-287": { // Improper Authentication
		{Framework: types.FrameworkOWASP, RequirementID: "A07:2021", RequirementName: "Identification and Authentication Failures", Description: "Improper authentication allows access without valid credentials."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "8.2", RequirementName: "User Identification and Authentication", Description: "Implement strong authentication for all users."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-5", RequirementName: "Account Management", Description: "Manage user authentication with strong controls."},
		{Framework: types.FrameworkNIST, RequirementID: "IA-2", RequirementName: "Identification and Authentication", Description: "Uniquely identify and authenticate users before granting access."},
	},

	"CWE-306": { // Missing Authentication for Critical Function
		{Framework: types.FrameworkOWASP, RequirementID: "A07:2021", RequirementName: "Identification and Authentication Failures", Description: "Critical function lacks authentication, allowing unauthenticated access."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "8.2", RequirementName: "User Identification and Authentication", Description: "Require authentication for all critical functions."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-5", RequirementName: "Account Management", Description: "Ensure all privileged functions require authentication."},
		{Framework: types.FrameworkNIST, RequirementID: "IA-2", RequirementName: "Identification and Authentication", Description: "Require authentication for all access to sensitive functions."},
	},

	"CWE-798": { // Use of Hardcoded Credentials
		{Framework: types.FrameworkOWASP, RequirementID: "A07:2021", RequirementName: "Identification and Authentication Failures", Description: "Hardcoded credentials can be extracted and misused by attackers."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "8.2.2", RequirementName: "Account Credential Security", Description: "Do not use hardcoded credentials; use secrets management."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-5", RequirementName: "Account Management", Description: "Use unique, dynamically managed credentials instead of hardcoded values."},
		{Framework: types.FrameworkNIST, RequirementID: "IA-5", RequirementName: "Authenticator Management", Description: "Manage authenticators to prevent use of hardcoded credentials."},
	},

	"CWE-521": { // Weak Password Requirements
		{Framework: types.FrameworkOWASP, RequirementID: "A07:2021", RequirementName: "Identification and Authentication Failures", Description: "Weak password policies allow credential attacks."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "8.3", RequirementName: "Strong Authentication", Description: "Enforce strong password complexity and change requirements."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-5", RequirementName: "Account Management", Description: "Enforce a strong password policy across all accounts."},
		{Framework: types.FrameworkNIST, RequirementID: "IA-5", RequirementName: "Authenticator Management", Description: "Establish and enforce minimum password complexity requirements."},
	},

	"CWE-384": { // Session Fixation
		{Framework: types.FrameworkOWASP, RequirementID: "A07:2021", RequirementName: "Identification and Authentication Failures", Description: "Session fixation allows an attacker to hijack an authenticated session."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "8.2", RequirementName: "User Identification and Authentication", Description: "Regenerate session identifiers after successful authentication."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-5", RequirementName: "Account Management", Description: "Invalidate pre-authentication session tokens upon login."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-23", RequirementName: "Session Authenticity", Description: "Protect session tokens from fixation attacks."},
	},

	"CWE-613": { // Insufficient Session Expiration
		{Framework: types.FrameworkOWASP, RequirementID: "A07:2021", RequirementName: "Identification and Authentication Failures", Description: "Long-lived sessions increase the window for session hijacking."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "8.2.8", RequirementName: "Session Timeout", Description: "Enforce session timeout after a period of inactivity."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-5", RequirementName: "Account Management", Description: "Configure session expiry to reduce exposure from abandoned sessions."},
		{Framework: types.FrameworkNIST, RequirementID: "AC-12", RequirementName: "Session Termination", Description: "Terminate sessions after inactivity or defined period."},
	},

	// ── Cryptographic Failures ─────────────────────────────────────────────────

	"CWE-326": { // Inadequate Encryption Strength
		{Framework: types.FrameworkOWASP, RequirementID: "A02:2021", RequirementName: "Cryptographic Failures", Description: "Weak encryption keys can be broken by attackers."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "4.2.1", RequirementName: "Cryptographic Standards", Description: "Use strong cryptography for transmission and storage of sensitive data."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-3", RequirementName: "Data Protection", Description: "Use industry-accepted algorithms with sufficient key lengths."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-13", RequirementName: "Cryptographic Protection", Description: "Use NIST-approved cryptographic algorithms and key sizes."},
	},

	"CWE-327": { // Use of a Broken or Risky Cryptographic Algorithm
		{Framework: types.FrameworkOWASP, RequirementID: "A02:2021", RequirementName: "Cryptographic Failures", Description: "Broken algorithms (MD5, RC4, DES) offer no meaningful security."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "4.2.1", RequirementName: "Cryptographic Standards", Description: "Replace deprecated cryptographic algorithms with modern equivalents."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-3", RequirementName: "Data Protection", Description: "Retire broken cryptographic algorithms from all systems."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-13", RequirementName: "Cryptographic Protection", Description: "Use only approved, non-deprecated cryptographic algorithms."},
	},

	"CWE-328": { // Use of Weak Hash
		{Framework: types.FrameworkOWASP, RequirementID: "A02:2021", RequirementName: "Cryptographic Failures", Description: "Weak hashes (MD5, SHA-1) allow preimage and collision attacks."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "4.2.1", RequirementName: "Cryptographic Standards", Description: "Use strong hashing algorithms for password storage and integrity."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-3", RequirementName: "Data Protection", Description: "Use strong hashing algorithms (SHA-256+) for all integrity checks."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-13", RequirementName: "Cryptographic Protection", Description: "Use NIST-approved hash algorithms."},
	},

	"CWE-319": { // Cleartext Transmission of Sensitive Information
		{Framework: types.FrameworkOWASP, RequirementID: "A02:2021", RequirementName: "Cryptographic Failures", Description: "Transmitting sensitive data in cleartext exposes it to interception."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "4.2", RequirementName: "Encryption in Transit", Description: "Encrypt all cardholder data transmitted over open, public networks."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-3", RequirementName: "Data Protection", Description: "Encrypt sensitive data in transit using TLS 1.2+."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-8", RequirementName: "Transmission Confidentiality and Integrity", Description: "Implement cryptographic mechanisms to protect data in transit."},
	},

	"CWE-311": { // Missing Encryption of Sensitive Data
		{Framework: types.FrameworkOWASP, RequirementID: "A02:2021", RequirementName: "Cryptographic Failures", Description: "Sensitive data stored or transmitted without encryption."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "3.5", RequirementName: "Protection of Stored Account Data", Description: "Protect stored sensitive data using strong cryptography."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-3", RequirementName: "Data Protection", Description: "Encrypt sensitive data at rest and in transit."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-28", RequirementName: "Protection of Information at Rest", Description: "Protect the confidentiality and integrity of information at rest."},
	},

	// ── Information Disclosure ─────────────────────────────────────────────────

	"CWE-200": { // Exposure of Sensitive Information
		{Framework: types.FrameworkOWASP, RequirementID: "A02:2021", RequirementName: "Cryptographic Failures", Description: "Sensitive data exposed to unauthorised actors."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Prevent information leakage through application responses."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-14", RequirementName: "Security Awareness and Skills Training", Description: "Train developers on data classification and minimisation."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-28", RequirementName: "Protection of Information at Rest", Description: "Protect sensitive information from unauthorised disclosure."},
	},

	"CWE-209": { // Error Message Information Disclosure
		{Framework: types.FrameworkOWASP, RequirementID: "A05:2021", RequirementName: "Security Misconfiguration", Description: "Verbose error messages reveal stack traces or internal paths."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Configure applications to return generic error messages in production."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Suppress detailed error messages in production environments."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-28", RequirementName: "Protection of Information at Rest", Description: "Prevent disclosure of sensitive information through error messages."},
	},

	"CWE-532": { // Inclusion of Sensitive Information in Log Files
		{Framework: types.FrameworkOWASP, RequirementID: "A09:2021", RequirementName: "Security Logging and Monitoring Failures", Description: "Sensitive data written to logs can be accessed by unauthorised parties."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "10.2", RequirementName: "Audit Log Implementation", Description: "Ensure logs do not capture sensitive authentication data."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-8", RequirementName: "Audit Log Management", Description: "Exclude sensitive data from audit logs."},
		{Framework: types.FrameworkNIST, RequirementID: "AU-3", RequirementName: "Content of Audit Records", Description: "Ensure audit records do not contain sensitive personal data."},
	},

	// ── SSRF ──────────────────────────────────────────────────────────────────

	"CWE-918": { // Server-Side Request Forgery (SSRF)
		{Framework: types.FrameworkOWASP, RequirementID: "A10:2021", RequirementName: "Server-Side Request Forgery", Description: "SSRF allows attackers to make the server issue requests to internal resources."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Validate and restrict outbound URL destinations to prevent SSRF."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-12", RequirementName: "Network Infrastructure Management", Description: "Enforce egress filtering to restrict server-initiated connections."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-7", RequirementName: "Boundary Protection", Description: "Monitor and control communications at external boundaries to prevent SSRF."},
	},

	// ── XXE ───────────────────────────────────────────────────────────────────

	"CWE-611": { // XML External Entity (XXE)
		{Framework: types.FrameworkOWASP, RequirementID: "A05:2021", RequirementName: "Security Misconfiguration", Description: "XXE allows attackers to read server files or perform SSRF via XML parsers."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Disable XML external entity processing in all XML parsers."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Disable DTD and external entity processing in XML libraries."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate and sanitise XML input; disable external entity processing."},
	},

	// ── Insecure Deserialization ───────────────────────────────────────────────

	"CWE-502": { // Deserialization of Untrusted Data
		{Framework: types.FrameworkOWASP, RequirementID: "A08:2021", RequirementName: "Software and Data Integrity Failures", Description: "Deserializing untrusted data can lead to remote code execution."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Implement integrity checks and allowlists before deserialisation."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Avoid native serialisation of untrusted data; use safe formats."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-10", RequirementName: "Information Input Validation", Description: "Validate all data before deserialisation."},
	},

	// ── Security Misconfiguration ─────────────────────────────────────────────

	"CWE-614": { // Sensitive Cookie Without 'Secure' Attribute
		{Framework: types.FrameworkOWASP, RequirementID: "A05:2021", RequirementName: "Security Misconfiguration", Description: "Cookies without the Secure flag can be transmitted over HTTP."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Set the Secure attribute on all sensitive cookies."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Configure cookies with Secure and SameSite attributes."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-23", RequirementName: "Session Authenticity", Description: "Protect session cookies with appropriate security attributes."},
	},

	"CWE-1004": { // Sensitive Cookie Without 'HttpOnly' Attribute
		{Framework: types.FrameworkOWASP, RequirementID: "A05:2021", RequirementName: "Security Misconfiguration", Description: "Cookies without HttpOnly are accessible to JavaScript and XSS attacks."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.2.4", RequirementName: "Software Attack Prevention", Description: "Set the HttpOnly attribute on session and sensitive cookies."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-16", RequirementName: "Application Software Security", Description: "Set HttpOnly on all session cookies to mitigate XSS impact."},
		{Framework: types.FrameworkNIST, RequirementID: "SC-23", RequirementName: "Session Authenticity", Description: "Restrict cookie access to HTTP to prevent script-based theft."},
	},

	"CWE-16": { // Configuration
		{Framework: types.FrameworkOWASP, RequirementID: "A05:2021", RequirementName: "Security Misconfiguration", Description: "Insecure default configuration leaves systems exposed."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "2.2", RequirementName: "System Configuration Standards", Description: "Develop configuration standards for all system components."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-4", RequirementName: "Secure Configuration", Description: "Establish and maintain secure configuration of enterprise assets."},
		{Framework: types.FrameworkNIST, RequirementID: "CM-6", RequirementName: "Configuration Settings", Description: "Establish and document configuration settings for systems."},
	},

	// ── Logging & Monitoring ──────────────────────────────────────────────────

	"CWE-778": { // Insufficient Logging
		{Framework: types.FrameworkOWASP, RequirementID: "A09:2021", RequirementName: "Security Logging and Monitoring Failures", Description: "Insufficient logging hinders incident detection and response."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "10.2", RequirementName: "Audit Log Implementation", Description: "Implement audit logs for all system components."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-8", RequirementName: "Audit Log Management", Description: "Enable detailed audit logging across all critical systems."},
		{Framework: types.FrameworkNIST, RequirementID: "AU-2", RequirementName: "Event Logging", Description: "Identify events that require logging and implement appropriate logging."},
	},

	// ── Components with Known Vulnerabilities ─────────────────────────────────

	"CWE-1104": { // Use of Unmaintained Third-Party Components
		{Framework: types.FrameworkOWASP, RequirementID: "A06:2021", RequirementName: "Vulnerable and Outdated Components", Description: "Unmaintained components may contain unpatched security vulnerabilities."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.3", RequirementName: "Security Vulnerabilities Addressed", Description: "Identify and address security vulnerabilities in system components."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-2", RequirementName: "Inventory and Control of Software Assets", Description: "Maintain an inventory of all third-party components and their versions."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-2", RequirementName: "Flaw Remediation", Description: "Identify, report, and remediate flaws in third-party components."},
	},

	// ── Software Integrity ─────────────────────────────────────────────────────

	"CWE-345": { // Insufficient Verification of Data Authenticity
		{Framework: types.FrameworkOWASP, RequirementID: "A08:2021", RequirementName: "Software and Data Integrity Failures", Description: "Lack of integrity verification allows supply chain attacks."},
		{Framework: types.FrameworkPCIDSS, RequirementID: "6.3.3", RequirementName: "Software Integrity", Description: "Verify integrity of all software packages and updates."},
		{Framework: types.FrameworkCIS, RequirementID: "CIS-2", RequirementName: "Inventory and Control of Software Assets", Description: "Verify software integrity using checksums and code signing."},
		{Framework: types.FrameworkNIST, RequirementID: "SI-7", RequirementName: "Software, Firmware, and Information Integrity", Description: "Employ integrity verification tools for software."},
	},
}
