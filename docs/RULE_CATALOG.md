# Built-in Rule Catalog

## 1. General detector rules

- Built-in patterns are code, not configuration.
- Compile patterns once.
- Use bounded lengths and explicit character classes.
- Avoid a generic `sk-...` detector without context or provider-specific constraints.
- Provider-specific findings suppress overlapping generic findings.
- Every rule has a stable lowercase kebab-case ID.
- Confidence is an integer from `0` through `100`.
- Exact regex text may evolve during implementation, but the positive and negative examples in tests define behavior.

## 2. Rules

`secret-guard rules list` exposes one static catalog severity for each rule ID. For rules whose findings can have different severities, that catalog value describes the rule entry and does not replace the severity calculated for an individual finding:

- `generic-secret-assignment` is listed as `high`, while individual findings are `medium` or `high` according to the score below;
- `suspicious-file-path` is listed as `medium`, while individual findings are `medium`, `high`, or `critical` according to the matched path group below.

### `private-key-pem`

- Severity: `critical`
- Family: `private-key`
- Detect complete or started PEM private-key blocks beginning with one of:
  - `BEGIN PRIVATE KEY`
  - `BEGIN ENCRYPTED PRIVATE KEY`
  - `BEGIN RSA PRIVATE KEY`
  - `BEGIN EC PRIVATE KEY`
  - `BEGIN DSA PRIVATE KEY`
  - `BEGIN OPENSSH PRIVATE KEY`
- A missing end marker still produces a finding because the material may be truncated in the changed range.
- Public keys and certificates are not findings.

### `github-token`

- Severity: `high`
- Family: `provider-token`
- Recognize currently documented GitHub token prefix families such as classic `gh*` forms and fine-grained `github_pat_` forms with strict length and allowed-character bounds.
- Do not match a prefix without a sufficiently long token body.

### `gitlab-token`

- Severity: `high`
- Family: `provider-token`
- Recognize `glpat-` tokens with strict body bounds.

### `slack-token`

- Severity: `high`
- Family: `provider-token`
- Recognize `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, and `xoxs-` token families with structured numeric/alphanumeric segments.

### `slack-webhook`

- Severity: `high`
- Family: `webhook`
- Recognize Slack incoming-webhook URLs with all required path segments.
- Redaction must not reveal the final segment.

### `stripe-live-secret-key`

- Severity: `high`
- Family: `provider-token`
- Recognize `sk_live_` and restricted `rk_live_` forms.

### `stripe-test-secret-key`

- Severity: `medium`
- Family: `provider-token`
- Recognize `sk_test_` and `rk_test_` forms.
- Kept below the default threshold but still reported.

### `openai-api-key`

- Severity: `high`
- Family: `provider-token`
- Recognize modern OpenAI secret-key structures with a sufficiently specific prefix and bounded URL-safe body.
- The implementation must avoid treating every arbitrary `sk-` value as OpenAI.
- Add negative tests for Stripe and unrelated `sk-` identifiers.

### `google-api-key`

- Severity: `high`
- Family: `provider-token`
- Recognize Google API key structures beginning with `AIza` and the expected bounded body length.

### `npm-token`

- Severity: `high`
- Family: `provider-token`
- Recognize modern npm access tokens beginning with `npm_` and a bounded alphanumeric body.

### `aws-access-key-id`

- Severity: `medium`
- Family: `cloud-credential-id`
- Recognize known AWS access-key identifier prefixes and exact expected identifier length.
- It is an identifier rather than sufficient authentication material, so it does not block at the default threshold by itself.

### `aws-secret-access-key`

- Severity: `high`
- Family: `cloud-secret`
- Requires sensitive context such as `aws_secret_access_key`, `secretAccessKey`, or equivalent plus a 40-character base64-like literal.

### `azure-storage-account-key`

- Severity: `high`
- Family: `cloud-secret`
- Recognize `AccountKey=<base64-like-value>` inside an Azure Storage connection string.

### `basic-auth-url`

- Severity: `high`
- Family: `url-credential`
- Recognize URLs containing non-placeholder `user:password@host` credentials.
- Do not flag `https://user@example.test` without a password.

### `database-connection-password`

- Severity: `high`
- Family: `connection-string`
- Recognize non-placeholder password fields inside common semicolon-delimited database connection strings, including `Password=`, `Pwd=`, and URI password forms.
- Require nearby database context to avoid matching arbitrary prose.

### `http-credential-header`

- Severity: `high`
- Family: `http-header`
- Recognize literal credential values in:
  - `Authorization` and `Proxy-Authorization` using Bearer, Basic, Token, APIKey, or API-Key schemes;
  - `X-API-Key`, `Api-Key`, `X-Auth-Token`, `X-Access-Token`, `X-Auth-Key`, `X-Client-Secret`, `Private-Token`, `X-GitLab-Token`, `X-GitHub-Token`, `X-Vault-Token`, `X-Amz-Security-Token`, and `X-Goog-Api-Key`;
  - `Cookie` and `Set-Cookie` entries whose cookie name contains `session`, `auth`, `token`, `jwt`, or `secret`.
- Recognize raw header lines, quoted object/configuration entries, and common quoted header name/value calls.
- Report every non-empty literal credential value regardless of length.
- Treat a recognized authorization scheme without a credential value, such as `Authorization: Bearer`, as empty and do not report it.
- Reject documented placeholders and environment references before reporting.
- Report only the credential portion, never the header's complete source line.

### `jwt-token`

- Severity: `medium`
- Family: `structured-token`
- Recognize three base64url-like segments separated by dots, with a header segment that decodes conceptually as a JSON object. Full JSON decoding is optional; strict segment bounds are required.
- JWT presence is a warning because not every JWT is a reusable credential.

### `generic-secret-assignment`

- Severity: computed `medium` or `high`
- Static `rules list` severity: `high`
- Family: `generic-context`
- Sensitive key names include normalized variants of:
  - password, passwd, pwd;
  - secret, client_secret;
  - api_key, apikey;
  - access_token, refresh_token, auth_token, bearer_token;
  - private_key;
  - connection_string.
- Assignment separators include `=`, `:`, and common quoted configuration syntax.
- Score candidates as follows:
  - sensitive key name: `+40`;
  - length at least 12: `+10`;
  - length at least 20: an additional `+10`;
  - entropy at least 3.5: `+15`;
  - entropy at least 4.2: an additional `+10`;
  - at least three character classes: `+10`;
  - quoted literal: `+5`;
  - documentation or fixture path: `-15`.
- Severity thresholds:
  - score at least 70: `high`;
  - score from 50 through 69: `medium`;
  - score below 50: no finding.
- Reject placeholders, environment references, and unquoted runtime call or index expressions before scoring. Quoted values remain literals even when their text resembles an expression.

### `suspicious-file-path`

- Severity: path-dependent
- Static `rules list` severity: `medium`
- Family: `path`

Path groups:

Critical:

```text
id_rsa
id_dsa
id_ecdsa
id_ed25519
*.pem when name suggests private key
*.key when name suggests private key
```

High:

```text
.env.production
.env.prod
credentials.json
service-account.json
service_account.json
*.p12
*.pfx
```

Medium:

```text
.env
.env.local
.env.development
.env.test
```

Exceptions:

```text
.env.example
.env.sample
*.example
*.template
```

A suspicious path finding does not claim content is definitely secret. The message must say the staged path commonly contains credentials.

## 3. Rule overlap

When a provider-specific span overlaps a generic assignment span:

- retain the provider-specific finding;
- suppress the generic finding for that candidate;
- retain a separate generic finding only when it refers to a distinct value.

When `azure-storage-account-key` overlaps `database-connection-password`, retain the more specific Azure rule.

Header overlap precedence:

- retain a provider-specific finding when its candidate overlaps `http-credential-header`;
- otherwise retain `http-credential-header` over an overlapping `jwt-token` or `generic-secret-assignment`;
- a literal Bearer JWT is therefore high severity and blocks at the default threshold;
- retain separate findings for distinct header values.

## 4. Pattern maintenance

Rule changes require:

1. positive and negative tests;
2. source/reference update in `docs/SOURCES.md` when based on a provider format;
3. changelog entry if behavior changes after v0.1 release;
4. no weakening of redaction or safe test-data policy.
