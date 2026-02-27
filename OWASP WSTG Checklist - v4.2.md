

> **Source:** Web Security Testing Guide v4.2, Chapter 4  
> **Format:** Obsidian-compatible checklist — copy per engagement and track progress  
> **ID Format:** `WSTG-<category>-<number>` (e.g. `WSTG-INFO-01`)

---

## How to Use This Checklist

- **Copy** this file for each new engagement (e.g. `WSTG-Checklist-TargetName.md`)
- **Check off** items as you test them: `- [ ]` → `- [x]`
- **Add notes** beneath any item inline — Obsidian will preserve them
- Items are grouped by category, then individual test. Each test shows its **objectives** as sub-checks.

---

## 4.1 Information Gathering

### WSTG-INFO-01 — Conduct Search Engine Discovery Reconnaissance for Information Leakage

- [ ] Identify sensitive design and configuration information exposed directly (on the org's website) or indirectly (via third-party services)
    - [ ] Search for network diagrams, configurations, archived admin emails
    - [ ] Search for logon procedures, username formats, passwords, private keys
    - [ ] Search for cloud/third-party config files and revealing error messages
    - [ ] Search for dev/test/UAT/staging versions of the site
    - [ ] Use Google dorks / `site:`, `inurl:`, `intitle:`, `filetype:`, `cache:` operators
    - [ ] Check Google Hacking Database (GHDB) for relevant dorks
    - [ ] Try multiple search engines (Google, Bing, DuckDuckGo, Shodan)

**Notes:**

---

### WSTG-INFO-02 — Fingerprint Web Server

- [ ] Determine the version and type of the running web server to identify known vulnerabilities
    - [ ] Banner grabbing (HTTP response headers)
    - [ ] Elicit responses to malformed/non-standard requests
    - [ ] Use automated tools (e.g. `whatweb`, `nmap -sV`, `wappalyzer`)
    - [ ] Check `Server:` and `X-Powered-By:` headers
    - [ ] Note default error pages and their formatting

**Notes:**

---

### WSTG-INFO-03 — Review Webserver Metafiles for Information Leakage

- [ ] Identify hidden or obfuscated paths and functionality via metadata files
- [ ] Extract and map info that leads to better understanding of the system
    - [ ] Check `/robots.txt` for disallowed paths
    - [ ] Check `/sitemap.xml` for enumerated pages
    - [ ] Check `<META>` tags in HTML for sensitive info
    - [ ] Check security policy files (e.g. `/.well-known/security.txt`)

**Notes:**

---

### WSTG-INFO-04 — Enumerate Applications on Webserver

- [ ] Enumerate all applications within scope that exist on the web server
    - [ ] Identify virtual hosting / multiple apps on same IP
    - [ ] Check non-standard ports (80, 443, 8080, 8443, etc.)
    - [ ] Look for apps accessible via different hostnames on same server
    - [ ] Check DNS records for subdomains pointing to same IP

**Notes:**

---

### WSTG-INFO-05 — Review Webpage Content for Information Leakage

- [ ] Review webpage comments and metadata for information leakage
- [ ] Gather JavaScript files and review JS code for information leakage
- [ ] Identify if source map files or other front-end debug files exist
    - [ ] Check HTML source comments
    - [ ] Check `.js.map` source map files
    - [ ] Review JS for hardcoded API keys, credentials, internal URLs
    - [ ] Check `<meta>` tags for generator/version info

**Notes:**

---

### WSTG-INFO-06 — Identify Application Entry Points

- [ ] Identify possible entry and injection points through request and response analysis
    - [ ] Map all GET/POST parameters
    - [ ] Identify headers used as input (e.g. `Cookie`, `Referer`, `X-Forwarded-For`)
    - [ ] Note all form fields including hidden fields
    - [ ] Document all file upload endpoints
    - [ ] Map API endpoints

**Notes:**

---

### WSTG-INFO-07 — Map Execution Paths Through Application

- [ ] Map the target application and understand the principal workflows
    - [ ] Walk through all user-facing functionality
    - [ ] Document authentication and authorization paths
    - [ ] Identify multi-step processes (checkout, password reset, etc.)
    - [ ] Note state-dependent transitions

**Notes:**

---

### WSTG-INFO-08 — Fingerprint Web Application Framework

- [ ] Fingerprint the components being used by the web application
    - [ ] Check HTTP headers for framework signatures
    - [ ] Check cookies for framework-specific names (e.g. `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`)
    - [ ] Check HTML source for framework-specific comments, classes, or file paths
    - [ ] Use Wappalyzer or BuiltWith
    - [ ] Check `/.well-known/`, error pages, and default files

**Notes:**

---

### WSTG-INFO-09 — Fingerprint Web Application

- [ ] Identify the web application and its version
    - [ ] Check for version strings in HTML, JS, headers
    - [ ] Compare page structure against known CMS/framework signatures
    - [ ] Check for known default pages or installation artifacts

**Notes:**

---

### WSTG-INFO-10 — Map Application Architecture

- [ ] Generate a map of the application based on research conducted
    - [ ] Identify load balancers, WAFs, CDNs, reverse proxies
    - [ ] Map backend languages/frameworks
    - [ ] Identify database types (from error messages, headers, behavior)
    - [ ] Document third-party integrations

**Notes:**

---

## 4.2 Configuration and Deployment Management Testing

### WSTG-CONF-01 — Test Network Infrastructure Configuration

- [ ] Review application configurations across the network for vulnerabilities
- [ ] Validate that frameworks and systems are not susceptible to known vulnerabilities
    - [ ] Check for unpatched software versions
    - [ ] Review firewall/network segmentation
    - [ ] Test for unnecessary open ports/services

**Notes:**

---

### WSTG-CONF-02 — Test Application Platform Configuration

- [ ] Ensure that defaults and known files have been removed
- [ ] Validate no debugging code or extensions are left in production
- [ ] Review logging mechanisms
    - [ ] Check for default credentials on admin interfaces
    - [ ] Look for sample/default/test files left on server
    - [ ] Check if stack traces are exposed in errors
    - [ ] Verify logging is active and appropriate

**Notes:**

---

### WSTG-CONF-03 — Test File Extensions Handling for Sensitive Information

- [ ] Dirbust sensitive file extensions (scripts, raw data, credentials)
- [ ] Validate that no system framework bypasses exist
    - [ ] Test access to `.bak`, `.old`, `.swp`, `.tmp`, `.log`, `.conf` files
    - [ ] Test for source code disclosure (`.php.bak`, `.asp~`, etc.)
    - [ ] Verify extension-based access controls work correctly

**Notes:**

---

### WSTG-CONF-04 — Review Old Backup and Unreferenced Files for Sensitive Information

- [ ] Find and analyze unreferenced files that might contain sensitive information
    - [ ] Dirbust for backup files (`.zip`, `.tar`, `.gz`, `backup.*`)
    - [ ] Check for old versions of files
    - [ ] Look for source code archives

**Notes:**

---

### WSTG-CONF-05 — Enumerate Infrastructure and Application Admin Interfaces

- [ ] Identify hidden administrator interfaces and functionality
    - [ ] Dirbust for common admin paths (`/admin`, `/manager`, `/console`, `/phpmyadmin`)
    - [ ] Check for admin interfaces on alternate ports
    - [ ] Test if admin interfaces are accessible without authentication

**Notes:**

---

### WSTG-CONF-06 — Test HTTP Methods

- [ ] Enumerate supported HTTP methods
- [ ] Test for access control bypass
- [ ] Test XST (Cross-Site Tracing) vulnerabilities
- [ ] Test HTTP method overriding techniques
    - [ ] Use `OPTIONS` to list allowed methods
    - [ ] Test `PUT`, `DELETE`, `TRACE`, `CONNECT` if listed
    - [ ] Test `X-HTTP-Method-Override` header bypass

**Notes:**

---

### WSTG-CONF-07 — Test HTTP Strict Transport Security

- [ ] Review the HSTS header and its validity
    - [ ] Check for `Strict-Transport-Security` header presence
    - [ ] Verify `max-age` is sufficiently long (≥ 1 year = 31536000)
    - [ ] Check for `includeSubDomains` and `preload` directives
    - [ ] Verify HTTPS is enforced and HTTP redirects to HTTPS

**Notes:**

---

### WSTG-CONF-08 — Test RIA Cross Domain Policy

- [ ] Review and validate cross-domain policy files
    - [ ] Check `/crossdomain.xml` (Flash)
    - [ ] Check `/clientaccesspolicy.xml` (Silverlight)
    - [ ] Evaluate if policies are overly permissive (e.g. `allow-access-from domain="*"`)

**Notes:**

---

### WSTG-CONF-09 — Test File Permission

- [ ] Review and identify any rogue file permissions
    - [ ] Check web root for world-writable files/directories
    - [ ] Verify config files are not world-readable
    - [ ] Check for improper permissions on uploaded files

**Notes:**

---

### WSTG-CONF-10 — Test for Subdomain Takeover

- [ ] Enumerate all possible domains (previous and current)
- [ ] Identify forgotten or misconfigured domains
    - [ ] Enumerate subdomains (Amass, subfinder, dnsx, crt.sh)
    - [ ] Check DNS CNAME records pointing to deprovisioned cloud services
    - [ ] Test dangling DNS entries (e.g. pointing to unclaimed S3, GitHub Pages, Heroku)

**Notes:**

---

### WSTG-CONF-11 — Test Cloud Storage

- [ ] Assess that access control configuration for storage services is properly in place
    - [ ] Check for publicly accessible S3 buckets, Azure Blobs, GCS buckets
    - [ ] Test for unauthenticated read/write access
    - [ ] Look for bucket names via JS, HTML source, error messages

**Notes:**

---

## 4.3 Identity Management Testing

### WSTG-IDNT-01 — Test Role Definitions

- [ ] Identify and document roles used by the application
- [ ] Attempt to switch, change, or access another role
- [ ] Review the granularity of roles and permissions
    - [ ] Map all roles (admin, user, moderator, etc.)
    - [ ] Test if roles can be modified client-side
    - [ ] Check for privilege escalation between roles

**Notes:**

---

### WSTG-IDNT-02 — Test User Registration Process

- [ ] Verify identity requirements for user registration align with business/security requirements
- [ ] Validate the registration process
    - [ ] Test with duplicate usernames/emails
    - [ ] Check if registration requires email verification
    - [ ] Test for weak or predictable default passwords assigned at registration
    - [ ] Check if admin can be registered via the normal flow

**Notes:**

---

### WSTG-IDNT-03 — Test Account Provisioning Process

- [ ] Verify which accounts may provision other accounts and of what type
    - [ ] Test if regular users can create other accounts
    - [ ] Check if account creation requires approval
    - [ ] Verify that provisioning flows enforce appropriate access controls

**Notes:**

---

### WSTG-IDNT-04 — Testing for Account Enumeration and Guessable User Account

- [ ] Review processes that pertain to user identification (registration, login, etc.)
- [ ] Enumerate users where possible through response analysis
    - [ ] Test login with valid vs. invalid usernames — compare responses
    - [ ] Test password reset flow for username enumeration
    - [ ] Test registration flow for username enumeration
    - [ ] Check response time differences for valid vs. invalid users

**Notes:**

---

### WSTG-IDNT-05 — Testing for Weak or Unenforced Username Policy

- [ ] Determine whether consistent account name structure enables account enumeration
- [ ] Determine whether error messages permit account enumeration
    - [ ] Check if usernames follow a predictable pattern (e.g. `firstname.lastname`)
    - [ ] Verify error messages are generic (don't reveal if username exists)

**Notes:**

---

## 4.4 Authentication Testing

### WSTG-ATHN-01 — Testing for Credentials Transported over an Encrypted Channel

- [ ] Assess whether credentials are exchanged without encryption
    - [ ] Verify login form submits over HTTPS
    - [ ] Check that HTTP login pages redirect to HTTPS before credential submission
    - [ ] Inspect for mixed content on login pages
    - [ ] Test if session tokens are sent over HTTP

**Notes:**

---

### WSTG-ATHN-02 — Testing for Default Credentials

- [ ] Enumerate the application for default credentials and validate if they still exist
- [ ] Review if new user accounts are created with defaults or identifiable patterns
    - [ ] Try default creds for identified frameworks/technologies (admin/admin, admin/password, etc.)
    - [ ] Check admin interfaces, network devices, management consoles
    - [ ] Test credentials found via OSINT

**Notes:**

---

### WSTG-ATHN-03 — Testing for Weak Lock Out Mechanism

- [ ] Evaluate the lockout mechanism's ability to mitigate brute force
- [ ] Evaluate the unlock mechanism's resistance to unauthorized unlocking
    - [ ] Test account lockout threshold (how many failed attempts before lockout)
    - [ ] Test if lockout can be bypassed (IP rotation, case variation, whitespace)
    - [ ] Assess unlock mechanism (time-based, email link, admin reset)
    - [ ] Test if lockout can be used for account enumeration or DoS

**Notes:**

---

### WSTG-ATHN-04 — Testing for Bypassing Authentication Schema

- [ ] Ensure that authentication is applied across all services that require it
    - [ ] Access authenticated pages directly without logging in
    - [ ] Try parameter manipulation (e.g. `?admin=true`, `?authenticated=1`)
    - [ ] Check for forced browsing to protected resources
    - [ ] Test SQL injection in login fields
    - [ ] Test for authentication bypass via header manipulation

**Notes:**

---

### WSTG-ATHN-05 — Testing for Vulnerable Remember Password

- [ ] Validate that the generated session is managed securely and does not expose credentials
    - [ ] Inspect "remember me" cookie contents
    - [ ] Check if credential or other sensitive data is stored in cookie
    - [ ] Assess cookie lifetime and whether it can be forged
    - [ ] Test if remember me token remains valid after password change/logout

**Notes:**

---

### WSTG-ATHN-06 — Testing for Browser Cache Weaknesses

- [ ] Review if the application stores sensitive information on the client-side
- [ ] Review if access can occur without authorization
    - [ ] Check `Cache-Control` and `Pragma` headers on authenticated pages
    - [ ] Use browser back button after logout to see if cached pages are accessible
    - [ ] Check if sensitive data is stored in `localStorage` / `sessionStorage`

**Notes:**

---

### WSTG-ATHN-07 — Testing for Weak Password Policy

- [ ] Determine the application's resistance against brute force using available password dictionaries
    - [ ] Check minimum password length
    - [ ] Check for complexity requirements (upper, lower, number, special char)
    - [ ] Test if common/breached passwords are rejected
    - [ ] Review password policy documentation vs. actual enforcement

**Notes:**

---

### WSTG-ATHN-08 — Testing for Weak Security Question Answer

- [ ] Determine the complexity and straightforwardness of security questions
- [ ] Assess possible user answers and brute force capabilities
    - [ ] Evaluate if security questions can be answered with public info (OSINT)
    - [ ] Test if answers are case-sensitive and checked server-side
    - [ ] Check for rate limiting on security question attempts

**Notes:**

---

### WSTG-ATHN-09 — Testing for Weak Password Change or Reset Functionalities

- [ ] Determine the resistance of the application to subversion of the account change process
- [ ] Determine the resistance of the password reset functionality against guessing or bypassing
    - [ ] Test password reset token entropy (is it guessable/predictable?)
    - [ ] Check token expiry time
    - [ ] Test if reset token is invalidated after use
    - [ ] Test for account enumeration via password reset form
    - [ ] Check if old password is required for password change
    - [ ] Test if password change requires re-authentication

**Notes:**

---

### WSTG-ATHN-10 — Testing for Weaker Authentication in Alternative Channel

- [ ] Identify alternative authentication channels
- [ ] Assess the security measures and if any bypasses exist on alternative channels
    - [ ] Identify mobile app, API, and legacy login paths
    - [ ] Test if alternative channels enforce same security controls (MFA, lockout, etc.)
    - [ ] Check for authentication downgrade possibilities

**Notes:**

---

## 4.5 Authorization Testing

### WSTG-ATHZ-01 — Testing Directory Traversal / File Include

- [ ] Identify injection points that pertain to path traversal
- [ ] Assess bypassing techniques and identify the extent of path traversal
    - [ ] Test `../` sequences in file path parameters
    - [ ] Test URL-encoded variants (`%2e%2e%2f`, `%252e%252e%252f`)
    - [ ] Test OS-specific traversal (`..\\`, `....//`)
    - [ ] Test for Local File Inclusion (LFI) and Remote File Inclusion (RFI)

**Notes:**

---

### WSTG-ATHZ-02 — Testing for Bypassing Authorization Schema

- [ ] Assess if horizontal or vertical access is possible
    - [ ] Test horizontal privilege escalation (access other users' resources)
    - [ ] Test vertical privilege escalation (access higher-privilege functions)
    - [ ] Manipulate user IDs, account numbers, filenames in requests
    - [ ] Test forced browsing to admin/privileged URLs
    - [ ] Test parameter manipulation for role changes

**Notes:**

---

### WSTG-ATHZ-03 — Testing for Privilege Escalation

- [ ] Identify injection points related to privilege manipulation
- [ ] Fuzz or otherwise attempt to bypass security measures
    - [ ] Test if user role can be changed via request parameter
    - [ ] Check for mass assignment vulnerabilities
    - [ ] Test if API returns more data than the UI shows (over-fetching)

**Notes:**

---

### WSTG-ATHZ-04 — Testing for Insecure Direct Object References (IDOR)

- [ ] Identify points where object references may occur
- [ ] Assess the access control measures and if they're vulnerable to IDOR
    - [ ] Enumerate IDs in URLs, body params, headers
    - [ ] Test sequential IDs, GUIDs, hashes
    - [ ] Test access to other users' objects by substituting their IDs
    - [ ] Test indirect references (filenames, account numbers, emails)

**Notes:**

---

## 4.6 Session Management Testing

### WSTG-SESS-01 — Testing for Session Management Schema

- [ ] Gather session tokens for same and different users
- [ ] Analyze for sufficient randomness to stop session forging attacks
- [ ] Modify unsigned cookies that contain manipulable information
    - [ ] Analyze session token entropy and length
    - [ ] Check if token contains predictable patterns (timestamp, username, etc.)
    - [ ] Test token validity after logout
    - [ ] Compare tokens across multiple sessions for the same user

**Notes:**

---

### WSTG-SESS-02 — Testing for Cookies Attributes

- [ ] Ensure proper security configuration is set for cookies
    - [ ] Check `Secure` flag (cookie only sent over HTTPS)
    - [ ] Check `HttpOnly` flag (cookie inaccessible to JS)
    - [ ] Check `SameSite` attribute (`Strict` or `Lax`)
    - [ ] Check `Domain` and `Path` scope
    - [ ] Check cookie expiry — are session cookies persistent?

**Notes:**

---

### WSTG-SESS-03 — Testing for Session Fixation

- [ ] Analyze the authentication mechanism and its flow
- [ ] Force cookies and assess the impact
    - [ ] Obtain a pre-auth session token
    - [ ] Authenticate and check if the session token changes
    - [ ] Test if pre-auth token can be accepted post-auth
    - [ ] Test if session ID can be set via URL parameter

**Notes:**

---

### WSTG-SESS-04 — Testing for Exposed Session Variables

- [ ] Ensure that proper encryption is implemented
- [ ] Review the caching configuration
- [ ] Assess the channel and methods' security
    - [ ] Check if session tokens appear in URL parameters
    - [ ] Check if session tokens appear in logs or Referer headers
    - [ ] Verify session tokens are not in page source

**Notes:**

---

### WSTG-SESS-05 — Testing for Cross-Site Request Forgery (CSRF)

- [ ] Determine whether it is possible to initiate requests on a user's behalf without user initiation
    - [ ] Check for CSRF tokens on all state-changing requests
    - [ ] Test if CSRF token is validated server-side
    - [ ] Test if CSRF token is tied to user session
    - [ ] Test `SameSite` cookie attribute as CSRF defense
    - [ ] Test `Origin`/`Referer` header validation
    - [ ] Craft a PoC CSRF page for impactful endpoints

**Notes:**

---

### WSTG-SESS-06 — Testing for Logout Functionality

- [ ] Assess the logout UI
- [ ] Analyze session timeout and if the session is properly killed after logout
    - [ ] Verify logout button exists and is visible
    - [ ] After logout, check if session token is invalidated server-side
    - [ ] Test if old session token can be replayed after logout
    - [ ] Verify logout invalidates all active sessions (if applicable)

**Notes:**

---

### WSTG-SESS-07 — Testing Session Timeout

- [ ] Validate that a hard session timeout exists
    - [ ] Measure idle session timeout
    - [ ] Measure absolute session timeout (max session duration)
    - [ ] Verify timeout is enforced server-side
    - [ ] Test if timeout resets on every request (sliding vs. fixed)

**Notes:**

---

### WSTG-SESS-08 — Testing for Session Puzzling

- [ ] Identify all session variables
- [ ] Break the logical flow of session generation
    - [ ] Map all session variables used across the application
    - [ ] Test if session variables from one context can affect another
    - [ ] Test for session variable overloading attacks

**Notes:**

---

### WSTG-SESS-09 — Testing for Session Hijacking

- [ ] Identify vulnerable session cookies
- [ ] Hijack vulnerable cookies and assess the risk level
    - [ ] Test for XSS that could be used to steal session cookies
    - [ ] Test for network sniffing risk (HTTP, mixed content)
    - [ ] Assess if `HttpOnly` would prevent JS-based theft

**Notes:**

---

## 4.7 Input Validation Testing

### WSTG-INPV-01 — Testing for Reflected Cross-Site Scripting (XSS)

- [ ] Identify variables that are reflected in responses
- [ ] Assess the input they accept and encoding applied on return
    - [ ] Test all input parameters (GET, POST, headers, cookies)
    - [ ] Test with basic payloads: `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
    - [ ] Test in different contexts (HTML body, attributes, JS, URL)
    - [ ] Check encoding/sanitization effectiveness
    - [ ] Test for filter bypass techniques

**Notes:**

---

### WSTG-INPV-02 — Testing for Stored Cross-Site Scripting (XSS)

- [ ] Identify stored input that is reflected on the client-side
- [ ] Assess the input they accept and encoding applied on return
    - [ ] Identify all fields where data is stored and later displayed
    - [ ] Test profile fields, comments, usernames, messages
    - [ ] Verify output is properly encoded in all display contexts
    - [ ] Test stored XSS in admin panels (second-order XSS)

**Notes:**

---

### WSTG-INPV-03 — Testing for HTTP Verb Tampering

- [ ] Test if application behaves differently with different HTTP methods
    - [ ] Use `GET` instead of `POST` (and vice versa) on all endpoints
    - [ ] Test `HEAD`, `PUT`, `DELETE`, `PATCH` on sensitive endpoints
    - [ ] Check if verb tampering bypasses authentication or CSRF controls

**Notes:**

---

### WSTG-INPV-04 — Testing for HTTP Parameter Pollution (HPP)

- [ ] Identify the backend and the parsing method used
- [ ] Assess injection points and try bypassing input filters using HPP
    - [ ] Duplicate parameters in requests: `param=val1&param=val2`
    - [ ] Test both client-side and server-side HPP
    - [ ] Check how different backends handle duplicate parameters

**Notes:**

---

### WSTG-INPV-05 — Testing for SQL Injection

- [ ] Identify SQL injection points
- [ ] Assess the severity and level of access achievable
    - [ ] Test with `'`, `"`, `)`, `--`, `; DROP TABLE` style payloads
    - [ ] Test for blind SQLi (boolean-based, time-based)
    - [ ] Test all input parameters (GET, POST, cookies, headers)
    - [ ] Use sqlmap for automated verification
    - [ ] Test for second-order SQLi
    - [ ] Assess OOB (Out-of-Band) exfiltration

**Notes:**

---

### WSTG-INPV-06 — Testing for LDAP Injection

- [ ] Identify LDAP injection points
- [ ] Assess the severity of the injection
    - [ ] Test with `*`, `)`, `(`, `\00`, `|`, `&` characters
    - [ ] Attempt to bypass authentication via LDAP injection
    - [ ] Test for information disclosure via wildcard injection

**Notes:**

---

### WSTG-INPV-07 — Testing for XML Injection

- [ ] Identify XML injection points
- [ ] Assess the types of exploits and their severity
    - [ ] Test for XXE (XML External Entity) injection
    - [ ] Test for blind XXE (out-of-band data exfiltration)
    - [ ] Test for XPath injection
    - [ ] Test DOCTYPE-based XXE

**Notes:**

---

### WSTG-INPV-08 — Testing for SSI Injection (Server-Side Includes)

- [ ] Identify SSI injection points
- [ ] Assess the severity of the injection
    - [ ] Test with `<!--#echo var="DATE_LOCAL" -->` and `<!--#exec cmd="id" -->`
    - [ ] Look for `.shtml` or SSI-enabled extensions
    - [ ] Check for reflected SSI in error pages, headers

**Notes:**

---

### WSTG-INPV-09 — Testing for XPath Injection

- [ ] Identify XPath injection points
    - [ ] Test inputs used in XML/XPath queries with `'`, `"`, `or '1'='1`
    - [ ] Test for blind XPath injection
    - [ ] Attempt to extract data from the XML store

**Notes:**

---

### WSTG-INPV-10 — Testing for IMAP/SMTP Injection

- [ ] Identify IMAP/SMTP injection points
- [ ] Understand the data flow and deployment structure
- [ ] Assess the injection impacts
    - [ ] Test email fields with CRLF injection (`%0d%0a`)
    - [ ] Test for header injection in `To:`, `From:`, `Subject:` fields
    - [ ] Test for mail relay abuse

**Notes:**

---

### WSTG-INPV-11 — Testing for Code Injection

- [ ] Identify injection points where code can be injected into the application
- [ ] Assess the injection severity
    - [ ] Test for `eval()` injection in JS-based backends
    - [ ] Test for PHP code injection (`<?php ...?>`)
    - [ ] Test for Python/Ruby eval injection
    - [ ] Test for template injection (see WSTG-INPV-18)

**Notes:**

---

### WSTG-INPV-12 — Testing for Command Injection

- [ ] Identify and assess command injection points
    - [ ] Test with `; id`, `| id`, `` `id` ``, `$(id)`, `& whoami`
    - [ ] Test in parameters that appear to trigger system commands (ping, DNS lookup, file conversion)
    - [ ] Test for blind command injection via time delays (`sleep 5`)
    - [ ] Test for OOB command injection

**Notes:**

---

### WSTG-INPV-13 — Testing for Buffer Overflow

- [ ] Test for buffer overflow conditions in application inputs
    - [ ] Test very long strings in all input fields
    - [ ] Check for binary/native code exposure

**Notes:**

---

### WSTG-INPV-14 — Testing for Format String Injection

- [ ] Assess if injecting format string specifiers causes undesired behavior
    - [ ] Test with `%s`, `%d`, `%x`, `%n` in input fields
    - [ ] Check for memory disclosure or crashes

**Notes:**

---

### WSTG-INPV-15 — Testing for Incubated Vulnerability

- [ ] Identify injections stored and requiring a recall step
- [ ] Understand how a recall step could occur
- [ ] Set listeners or activate the recall step if possible
    - [ ] Identify log files, batch jobs, import functions that process stored data
    - [ ] Test for delayed/second-order injection in those paths

**Notes:**

---

### WSTG-INPV-16 — Testing for HTTP Splitting/Smuggling

- [ ] Assess if the application is vulnerable to HTTP response splitting
- [ ] Assess if the chain of communication is vulnerable to HTTP request smuggling
    - [ ] Test CRLF injection in HTTP headers
    - [ ] Test for HTTP request smuggling (CL.TE, TE.CL, TE.TE)
    - [ ] Use Burp Suite HTTP Request Smuggler extension

**Notes:**

---

### WSTG-INPV-17 — Testing for HTTP Incoming Requests

- [ ] Monitor all incoming and outgoing HTTP requests to the web server for suspicious requests
- [ ] Monitor HTTP traffic without changes to end user browser proxy or client-side application
    - [ ] Review server-side logs for anomalies
    - [ ] Use passive monitoring techniques

**Notes:**

---

### WSTG-INPV-18 — Testing for Server-Side Template Injection (SSTI)

- [ ] Detect template injection vulnerability points
- [ ] Identify the templating engine
- [ ] Build the exploit
    - [ ] Test with `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`
    - [ ] Identify engine from error messages or behavior
    - [ ] Escalate to RCE via engine-specific payloads (Jinja2, Twig, Freemarker, etc.)

**Notes:**

---

### WSTG-INPV-19 — Testing for Server-Side Request Forgery (SSRF)

- [ ] Identify SSRF injection points
- [ ] Test if injection points are exploitable
- [ ] Assess the severity of the vulnerability
    - [ ] Test URL parameters, webhook endpoints, file import features, PDF/image generators
    - [ ] Test for access to internal services (`http://127.0.0.1`, `http://169.254.169.254`)
    - [ ] Test for blind SSRF via OOB (Burp Collaborator, interactsh)
    - [ ] Attempt to bypass SSRF filters (redirects, DNS rebinding, IPv6, encoded IPs)

**Notes:**

---

## 4.8 Testing for Error Handling

### WSTG-ERRH-01 — Testing for Improper Error Handling

- [ ] Identify existing error output
- [ ] Analyze the different output returned
    - [ ] Trigger errors by sending invalid input to all entry points
    - [ ] Check if error messages reveal stack traces, DB queries, file paths, internal IPs
    - [ ] Test with malformed requests, unexpected data types, oversized inputs

**Notes:**

---

### WSTG-ERRH-02 — Testing for Stack Traces

- [ ] Identify stack traces in error responses
    - [ ] Trigger exceptions and review full response body
    - [ ] Check HTTP 500 pages for technology disclosure
    - [ ] Review error messages in debug/verbose modes

**Notes:**

---

## 4.9 Testing for Weak Cryptography

### WSTG-CRYP-01 — Testing for Weak Transport Layer Security

- [ ] Validate the service TLS configuration
- [ ] Review the digital certificate's cryptographic strength and validity
- [ ] Ensure TLS security is not bypassable and is properly implemented
    - [ ] Test with `testssl.sh` or SSLLabs
    - [ ] Check for support of deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - [ ] Check for weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)
    - [ ] Verify certificate validity (expiry, hostname match, chain)
    - [ ] Test for BEAST, CRIME, POODLE, HEARTBLEED, ROBOT
    - [ ] Check for HSTS (see WSTG-CONF-07)

**Notes:**

---

### WSTG-CRYP-02 — Testing for Padding Oracle

- [ ] Identify encrypted messages that rely on padding
- [ ] Attempt to break the padding and analyze error messages
    - [ ] Identify CBC-encrypted tokens in cookies, parameters
    - [ ] Test for padding oracle responses (timing or error differences)
    - [ ] Use padbuster or Burp intruder for automated testing

**Notes:**

---

### WSTG-CRYP-03 — Testing for Sensitive Information Sent via Unencrypted Channels

- [ ] Identify sensitive information transmitted through various channels
- [ ] Assess the privacy and security of the channels used
    - [ ] Check if any sensitive data (credentials, tokens, PII) sent over HTTP
    - [ ] Check for mixed content (HTTPS page loading HTTP resources)
    - [ ] Test email delivery for sensitive data over SMTP

**Notes:**

---

### WSTG-CRYP-04 — Testing for Weak Encryption

- [ ] Identify weak encryption or hashing uses and implementations
    - [ ] Check if MD5 or SHA-1 used for password hashing
    - [ ] Check if passwords stored without salt
    - [ ] Identify use of custom/homebrew crypto algorithms
    - [ ] Check for weak random number generation in security-critical contexts

**Notes:**

---

## 4.10 Business Logic Testing

### WSTG-BUSL-01 — Test Business Logic Data Validation

- [ ] Identify data injection points
- [ ] Validate that all checks occur on the back end and can't be bypassed
- [ ] Attempt to break the format of expected data
    - [ ] Test negative numbers, zero values, very large values in numeric fields
    - [ ] Test empty values, null, and special characters
    - [ ] Intercept and modify client-side validation controls

**Notes:**

---

### WSTG-BUSL-02 — Test Ability to Forge Requests

- [ ] Review project documentation for guessable, predictable, or hidden fields
- [ ] Insert logically valid data to bypass normal business logic workflow
    - [ ] Replay legitimate requests with modified parameters
    - [ ] Test if price, quantity, discount fields can be manipulated
    - [ ] Test if hidden fields affect business logic

**Notes:**

---

### WSTG-BUSL-03 — Test Integrity Checks

- [ ] Review components of the system that move, store, or handle data
- [ ] Determine who should be allowed to modify or read that data in each component
- [ ] Attempt to insert, update, or delete data values that should not be allowed
    - [ ] Test if order totals can be manipulated
    - [ ] Test if item quantities can be set to negative values for credits
    - [ ] Verify server-side re-validation of all critical data

**Notes:**

---

### WSTG-BUSL-04 — Test for Process Timing

- [ ] Review functionality that may be impacted by time
- [ ] Develop and execute misuse cases
    - [ ] Test for race conditions (send simultaneous requests)
    - [ ] Test time-sensitive operations (token expiry, TOCTOU)
    - [ ] Test for time-based attacks on comparison functions

**Notes:**

---

### WSTG-BUSL-05 — Test Number of Times a Function Can Be Used Limits

- [ ] Identify functions that must set limits on how many times they can be called
- [ ] Assess if there is a logical limit set and if it is properly validated
    - [ ] Test coupon codes, vouchers, referral codes for unlimited use
    - [ ] Test API rate limits
    - [ ] Test vote/like/rating functions for repeat exploitation

**Notes:**

---

### WSTG-BUSL-06 — Testing for the Circumvention of Workflows

- [ ] Review documentation for methods to skip steps or reorder process steps
- [ ] Develop a misuse case and try to circumvent every logic flow identified
    - [ ] Test multi-step checkout — skip payment step
    - [ ] Test if onboarding steps can be skipped
    - [ ] Test if approval workflows can be bypassed

**Notes:**

---

### WSTG-BUSL-07 — Test Defenses Against Application Misuse

- [ ] Review which tests had different functionality based on aggressive input
- [ ] Understand defenses in place and verify if they protect against bypassing
    - [ ] Verify WAF / rate limiting is in place
    - [ ] Test for alerting when abuse is detected
    - [ ] Assess if misuse is logged and monitored

**Notes:**

---

### WSTG-BUSL-08 — Test Upload of Unexpected File Types

- [ ] Review file types that are rejected by the system
- [ ] Verify that unwelcome file types are rejected and handled safely
    - [ ] Attempt to upload executable files (`.php`, `.asp`, `.jsp`, `.py`)
    - [ ] Test if extension check can be bypassed (double extensions, null bytes)
    - [ ] Test batch upload functionality

**Notes:**

---

### WSTG-BUSL-09 — Test Upload of Malicious Files

- [ ] Identify the file upload functionality
- [ ] Determine how uploaded files are processed
- [ ] Try to upload malicious files and check if accepted/processed
    - [ ] Upload EICAR test file for AV detection
    - [ ] Upload malicious Office documents (with macros)
    - [ ] Upload files with embedded web shells
    - [ ] Test image upload with embedded payloads (polyglots, `exiftool` injections)
    - [ ] Check where files are stored and if they're accessible via URL

**Notes:**

---

## 4.11 Client-Side Testing

### WSTG-CLNT-01 — Testing for DOM-Based Cross-Site Scripting

- [ ] Identify DOM sinks
- [ ] Build payloads that pertain to every sink type
    - [ ] Review JS source for dangerous sinks: `innerHTML`, `document.write`, `eval`, `location.href`
    - [ ] Test `#fragment` and URL-sourced data flowing into sinks
    - [ ] Test with DOM XSS payloads in URL hash, query params
    - [ ] Use tools: DOM Invader (Burp), DOMinator

**Notes:**

---

### WSTG-CLNT-02 — Testing for JavaScript Execution

- [ ] Identify sinks and possible JavaScript injection points
    - [ ] Look for `javascript:` URI handlers
    - [ ] Test for injection into `setTimeout`, `setInterval`, `Function()` calls
    - [ ] Check for unsafe `JSON.parse` usage with user input

**Notes:**

---

### WSTG-CLNT-03 — Testing for HTML Injection

- [ ] Identify HTML injection points and assess the severity
    - [ ] Test for HTML injection where XSS is filtered (e.g. `<b>`, `<h1>`, `<a href>`)
    - [ ] Check for content injection that could be used for phishing
    - [ ] Test in reflected, stored, and DOM contexts

**Notes:**

---

### WSTG-CLNT-04 — Testing for Client-Side URL Redirect

- [ ] Identify injection points that handle URLs or paths
- [ ] Assess the locations the system could redirect to
    - [ ] Test `redirect=`, `url=`, `next=`, `return_to=` parameters
    - [ ] Test for open redirect to external domains
    - [ ] Test bypass techniques (`//evil.com`, `https://evil.com`, `\/\/evil.com`)

**Notes:**

---

### WSTG-CLNT-05 — Testing for CSS Injection

- [ ] Identify CSS injection points
- [ ] Assess the impact of the injection
    - [ ] Test for CSS injection in style attributes or CSS files
    - [ ] Assess if CSS injection can be used for data exfiltration (attribute selectors)
    - [ ] Test for `expression()` injection in legacy IE contexts

**Notes:**

---

### WSTG-CLNT-06 — Testing for Client-Side Resource Manipulation

- [ ] Identify sinks with weak input validation
- [ ] Assess the impact of resource manipulation
    - [ ] Check if JS loads resources from user-controlled URLs
    - [ ] Test for script `src`, image `src`, iframe `src` manipulation
    - [ ] Test for JSONP callback parameter manipulation

**Notes:**

---

### WSTG-CLNT-07 — Testing Cross-Origin Resource Sharing (CORS)

- [ ] Identify endpoints that implement CORS
- [ ] Ensure the CORS configuration is secure or harmless
    - [ ] Check `Access-Control-Allow-Origin` header values
    - [ ] Test if `Origin: null` or `Origin: evil.com` is reflected
    - [ ] Check if `Access-Control-Allow-Credentials: true` is combined with permissive origin
    - [ ] Craft a PoC for CORS-based data theft where applicable

**Notes:**

---

### WSTG-CLNT-08 — Testing for Cross-Site Flashing

- [ ] Decompile and analyze the Flash application's code
- [ ] Assess sinks inputs and unsafe method usages
    - [ ] Decompile SWF files with JPEXS or similar
    - [ ] Check for `loadMovie`, `getURL`, `ExternalInterface.call` with user input
    - [ ] Test for Flash-based XSS

**Notes:**

---

### WSTG-CLNT-09 — Testing for Clickjacking

- [ ] Understand security measures in place
- [ ] Assess how strict they are and if they are bypassable
    - [ ] Check for `X-Frame-Options` header (`DENY` or `SAMEORIGIN`)
    - [ ] Check for `Content-Security-Policy: frame-ancestors` directive
    - [ ] Test if the page can be framed in an iframe
    - [ ] Test if frame-busting JS can be bypassed with `sandbox` attribute

**Notes:**

---

### WSTG-CLNT-10 — Testing WebSockets

- [ ] Identify the usage of WebSockets
- [ ] Assess its implementation using the same tests applied to HTTP channels
    - [ ] Inspect WebSocket handshake headers
    - [ ] Check for authentication on WebSocket upgrade request
    - [ ] Test for injection (XSS, SQLi, etc.) via WebSocket messages
    - [ ] Test for CSRF on WebSocket handshake (no `SameSite`/`Origin` check)
    - [ ] Test for authorization — can you access other users' WS channels?

**Notes:**

---

### WSTG-CLNT-11 — Testing Web Messaging

- [ ] Assess the security of the message's origin
- [ ] Validate that safe methods are used and input is validated
    - [ ] Review `addEventListener('message', ...)` handlers for origin validation
    - [ ] Test if `postMessage` origin is properly checked (`event.origin`)
    - [ ] Test for XSS via malicious `postMessage` data

**Notes:**

---

### WSTG-CLNT-12 — Testing Browser Storage

- [ ] Determine if the website stores sensitive data in client-side storage
- [x] Examine code handling storage objects for injection possibilities
    - [ ] Review `localStorage` and `sessionStorage` for sensitive data (tokens, credentials, PII)
    - [x] Test for XSS via unsanitized data retrieved from storage
    - [ ] Check `IndexedDB` for sensitive data
    - [ ] Review Service Worker cache for sensitive content

**Notes:**

---

### WSTG-CLNT-13 — Testing for Cross-Site Script Inclusion (XSSI)

- [ ] Locate sensitive data across the system
- [ ] Assess the leakage of sensitive data through various techniques
    - [ ] Identify JSON/JS endpoints that return sensitive data
    - [ ] Test if endpoints return data when accessed cross-origin via `<script src>`
    - [ ] Test for JSONP endpoints that may leak data

**Notes:**

---

## 4.12 API Testing

### WSTG-APIT-01 — Testing GraphQL

- [ ] Assess that a secure and production-ready configuration is deployed
- [ ] Validate all input fields against generic attacks
- [ ] Ensure that proper access controls are applied
    - [ ] Check if introspection is enabled in production (`__schema` query)
    - [ ] Test for authentication and authorization on all queries/mutations
    - [ ] Test for IDOR via object IDs in GraphQL queries
    - [ ] Test for injection (SQLi, NoSQLi, SSTI) via GraphQL arguments
    - [ ] Test for batch query attacks (query complexity limits)
    - [ ] Test for GraphQL-specific vulnerabilities (alias-based brute force, field suggestions)
    - [ ] Use tools: InQL (Burp plugin), GraphQL Voyager

**Notes:**

---

## Summary Progress

| Category                          | Tests  | Done  |
| --------------------------------- | ------ | ----- |
| INFO — Information Gathering      | 10     | 0     |
| CONF — Configuration & Deployment | 11     | 0     |
| IDNT — Identity Management        | 5      | 0     |
| ATHN — Authentication             | 10     | 0     |
| ATHZ — Authorization              | 4      | 0     |
| SESS — Session Management         | 9      | 0     |
| INPV — Input Validation           | 19     | 0     |
| ERRH — Error Handling             | 2      | 0     |
| CRYP — Weak Cryptography          | 4      | 0     |
| BUSL — Business Logic             | 9      | 0     |
| CLNT — Client-Side                | 13     | 0     |
| APIT — API Testing                | 1      | 0     |
| **TOTAL**                         | **97** | **0** |

---

_Generated from OWASP Web Security Testing Guide v4.2, Chapter 4. See https://owasp.org/www-project-web-security-testing-guide/ for full documentation._
