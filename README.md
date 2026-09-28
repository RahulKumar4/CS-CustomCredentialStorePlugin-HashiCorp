# HashiCorp Vault (Lockbox AD) credential store — UiPath Disconnected Credentials Proxy

An `ISecureStore` plugin that resolves Active Directory service-account credentials through the
Lockbox `ad-details` API, which fronts HashiCorp Vault's Active Directory secrets engine.

Built against the interface documented in
[UiPath/Orchestrator-CredentialStorePlugins](https://github.com/UiPath/Orchestrator-CredentialStorePlugins).

| | |
|---|---|
| Assembly | `UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox.dll` |
| Store type (`SecureStoreConfigurations[].Type`) | `HashiCorpVaultLockbox` |
| Target framework | `netstandard2.0`, so you can build on any OS and deploy to the Windows proxy |
| Packages | `UiPath.Orchestrator.Extensibility` 1.0.4, `Newtonsoft.Json` 13.0.3 |
| Mode | **Read-only**: Vault owns the password and its rotation |
| Authentication | OAuth2 bearer token from ADFS, using `private_key_jwt` (RFC 7523) |

**Full documentation is in [`docs/`](docs/README.md):**
[Architecture](docs/ARCHITECTURE.md) ·
[Configuration](docs/CONFIGURATION.md) ·
[Deployment](docs/DEPLOYMENT.md) ·
[Code reference](docs/CODE-REFERENCE.md) ·
[Operations & troubleshooting](docs/OPERATIONS.md).
A Word version is in `docs/HashiCorpVaultLockbox-SecureStore-Documentation.docx`.

> **You may not need this plugin**
>
> UiPath's built-in **Hashicorp Vault – Read Only** store already supports Vault's Active
> Directory secrets engine. This plugin exists only because your credentials have to come through
> the **Lockbox HTTP wrapper** (`POST /ad-details` with an ADFS-issued bearer token) rather than
> from Vault directly. If the proxy host can authenticate to Vault itself (AppRole or token), use
> the built-in store instead. That way there's no custom code to build, sign or maintain.

---

## How it works

```text
Robot ──▶ Credentials Proxy (Disconnected, IIS) ──▶ this plugin
                                                     │
                                                     ├─(1) client_credentials + RS256 JWT signed by the cert ──▶ ADFS /oauth2/token
                                                     │                                                          ◀── access_token
                                                     └─(2) POST {"ad_dn":"CN=A112580,OU=..."}  Bearer <token> ──▶ Lockbox /ad-details ──▶ Vault AD engine
                                                                                                                ◀── ad_details {username, password, ...}
```

1. The robot asks the proxy for a credential. Orchestrator passes the store **context** (JSON)
   and a **key** (the asset's External Name, or the robot's `DOMAIN\user`).
2. The key becomes an AD distinguished name through `AdDnTemplate`. A key that is already a DN is
   used as-is.
3. The plugin signs a JWT client assertion with the X.509 certificate's private key and exchanges
   it at ADFS for an access token. The token is cached until shortly before it expires.
4. It POSTs `{"ad_dn": ...}` to Lockbox with that bearer token and parses `ad_details`.
5. What it returns depends on the request:
   - **Credential asset** (`GetCredentialsAsync`): a username built from `UsernameFormat`, plus
     the password.
   - **Robot credential** (`GetValueAsync`): the password only. Orchestrator supplies the
     username. If `VerifyRobotUsername` is on, the returned identity is checked against the
     requested account.

The certificate **signs the JWT**. It isn't used for mutual TLS unless
`SendClientCertificateToEndpoint=true`. An earlier mTLS-only version was rejected by the Envoy
gateway in front of Lockbox with a bodiless 401.

In disconnected mode the credential goes from the proxy straight to the robot and never passes
through Orchestrator. This requires Robot 23.10+, System Activities 24.3+, Credentials Proxy
2.0.1+ and an Enterprise-Advanced licence.

---

## Files

| File | Role |
|---|---|
| `HashiCorpVaultLockboxSecureStore.cs` | The `ISecureStore` implementation: metadata, config form, validation, reads, refused writes |
| `LockboxContext.cs` | Store context model and validation; `AdDnResolver` (key → `ad_dn`, username format, identity check) |
| `Configuration.cs` | Context key constants (`ConfigKeys`), host-setting keys and parsing (`HostOptions`) |
| `LockboxClient.cs` | HTTP client for Lockbox: pooling, retries, status-code mapping, response parsing, optional cache |
| `TokenProvider.cs` | OAuth2 `private_key_jwt`: builds and signs the assertion, gets and caches the access token |
| `ClientCertificateResolver.cs` | Loads the X.509 certificate from the Windows store, a pfx file, or base64 |
| `CredentialCache.cs` | Bounded, self-evicting TTL cache; delayed disposal of HTTP clients and certificates |
| `EventLogWriter.cs` | Windows Event Viewer sink, bound at runtime by reflection |
| `ExceptionHelper.cs` | Every `SecureStoreException` is built here; SHA-256 helper |
| `AssemblyInfo.cs` | `InternalsVisibleTo` for the harness and a test project |
| `samples/appsettings.Production.merge.json` | **Current** strict-JSON merge fragment, copied to the build output |
| `samples/appsettings.Production.json` | Annotated reference and alternative certificate examples (main context lacks the OAuth keys, see below) |
| `samples/DEPLOY.txt` | Operator runbook and rollback, copied to the build output |
| `tools/make-context.py` | Turns readable context JSON into the escaped `Context` string, and lints it |
| `tools/Harness/` | 42 offline checks for DN, username, host-setting and cache logic |
| `build.ps1` / `build.sh` | Build, harness and deploy helpers (Windows / macOS or Linux) |
| `.vscode/` | Build tasks and a "Debug harness" launch configuration |

---

## Build

```powershell
.\build.ps1                 # clean + restore + Release build
.\build.ps1 -RunHarness     # + run the offline logic checks
.\build.ps1 -Deploy         # + copy the DLL into the proxy plugins folder (run elevated)
```

```bash
brew install --cask dotnet-sdk    # macOS, first time only
./build.sh --harness
```

Or on any platform: `dotnet restore && dotnet build -c Release`.

Output is in `bin/Release/`:

```text
UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox.dll   -> plugins\
appsettings.Production.merge.json                                       -> MERGE into proxy config
appsettings.Production.json                                             -> annotated reference
DEPLOY.txt                                                              -> steps + rollback
```

Check these before you build:

1. **Extensibility version.** The `.csproj` pins `UiPath.Orchestrator.Extensibility` 1.0.4. If your
   proxy ships a newer version, change it to match, or the plugin may fail to load.
2. **`SecureStoreException.Type` members.** The code uses `SecretNotFound`,
   `InvalidConfiguration` and `UnauthorizedOperation`. If your package names them differently,
   only `ExceptionHelper.cs` needs changing.
3. **Newtonsoft.Json.** `CopyLocalLockFileAssemblies=false`, so it isn't copied to the output. The
   proxy normally provides it. Don't put a second copy in `plugins\`.

**No prebuilt DLL is shipped, on purpose.** Build it yourself from source you've reviewed, inside
your own controls, and put it through your scanning and signing pipeline.

Build troubleshooting: `CS0579 Duplicate attribute` or `CS8805 top-level statements` mean there's
a stale `obj/` from the nested harness project. Run
`rm -rf obj bin tools/Harness/obj tools/Harness/bin` (the build scripts already do this).

On a Mac, `CertificateSource: Store` isn't available. Use `File` or `Base64` locally and keep
`Store` in the deployed config.

---

## Deploy

> **Never overwrite the proxy's `appsettings.Production.json`.** It holds your `Jwt:Keys` and
> `SigningCredentialSettings`. Merge into it: `Plugins.SecureStores` is a CSV string, so append
> to it. `SecureStoreConfigurations` is an array, so append an entry with a unique `Key`.

1. Back up `C:\Program Files\UiPath\OrchestratorCredentialsProxy\appsettings.Production.json`.
2. Copy the DLL to `...\OrchestratorCredentialsProxy\plugins\`.
3. Merge the keys from `appsettings.Production.merge.json`. Generate the `Context` string with
   `python3 tools/make-context.py my-context.json --entry LockboxAdServiceAccounts`.
4. Give the proxy app pool identity **Read access to the certificate's private key**
   (`certlm.msc` → certificate → All Tasks → Manage Private Keys).
5. Optional: `New-EventLog -LogName Application -Source 'UiPath HashiCorpVaultLockbox'` (elevated).
6. Restart the site in IIS.
7. Verify: `GET api/v1/Health` returns 200, the proxy log is clean, and Event Viewer shows events
   1000 and 1100. **Then run a real test read.** By default startup doesn't contact ADFS or Lockbox.

Rollback: restore the backup, delete the DLL, restart the site. The full runbook is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Configuration reference

### Store context (`SecureStoreConfigurations[].Context`, a JSON string)

| Key | Required | Default / notes |
|---|---|---|
| `EndpointUrl` | **yes** | Absolute https URL of `/ad-details` |
| `TokenEndpoint` | **yes** | Absolute https URL of the ADFS token endpoint |
| `ClientId` | **yes** | OAuth2 client id. Also the JWT `iss` and `sub`. |
| `Resource` / `Scope` | **one of** | ADFS `resource`, or `scope` |
| `Audience` | no | JWT `aud`. Defaults to `TokenEndpoint`. |
| `CertKidHeaderName` | no | `kid` (default) or `x5t` |
| `CertKid` | no | Key id value. Defaults to the **hex** thumbprint. For a real `x5t`, set the base64url SHA-1 here. |
| `JwtId` | no | Fixed `jti`. Default is a fresh GUID per assertion. |
| `AssertionLifetimeSeconds` | no | 300 (max 3600) |
| `TokenRefreshSkewSeconds` | no | 60 |
| `SendClientCertificateToEndpoint` | no | `false`. Also send the certificate as a TLS client certificate to Lockbox. |
| `CertificateSource` | no | `Store` / `File` / `Base64`. Inferred if omitted. |
| `CertificateThumbprint` | if `Store` | Spaces and hidden characters are stripped |
| `CertificateStoreName` / `CertificateStoreLocation` | no | `My` / `LocalMachine` |
| `CertificateFilePath` | if `File` | `.pfx` path |
| `CertificateBase64` | if `Base64` | `[Convert]::ToBase64String([IO.File]::ReadAllBytes('client.pfx'))` |
| `CertificatePassword` | no | For `File` / `Base64` |
| `AdDnTemplate` | unless keys are full DNs | Must contain `{key}` |
| `UsernameFormat` | no | `{cn}` |
| `UseLastPasswordFallback` | no | `false` |
| `VerifyRobotUsername` | no | `false`. Recommended `true`. |
| `AllowedDomainQualifiers` | no | e.g. `ADDEV,ADPROD` |
| `ValidateEndpointAtStartup` | no | `false`. If true, POSTs `{}` at startup and fails only on 401/403/407. |
| `ValidationAdDn` | no | Probe DN for a full end-to-end read at startup |

### Host settings (`AppSettings`, fully qualified `Plugins.SecureStores.HashiCorpVaultLockbox.<Name>`)

| Name | Default | Range |
|---|---|---|
| `RequestTimeoutSeconds` | 30 | 5–300 |
| `RetryCount` | 2 | 0–5 (retries transport errors, 429 and 5xx) |
| `CacheSeconds` | 0 (off) | 0–3600 |
| `ExpectedTokenLength` | 0 (any) | 0–65536 |
| `TokenLengthRetryAttempts` | 3 | 0–10 |
| `AllowInsecureTls` | false | lab only |
| `EventLogEnabled` | false | |
| `EventLogLevel` | Error | Off / Error / Warning / Information / Verbose |
| `EventLogName` | Application | |
| `EventLogSource` | UiPath HashiCorpVaultLockbox | |

The platform strips the prefix before calling `Initialize`. The plugin accepts both the qualified
and the bare name. A bad numeric or boolean value stops the plugin from loading (event 1002). A
bad event-log value is ignored with a warning (event 1001).

### How a key becomes an `ad_dn`

- If the key already looks like a DN (`CN=`, `OU=`, `DC=`, `UID=`), it's used as-is.
- Otherwise the `QUALIFIER\` prefix and `@upn` suffix are stripped, the qualifier is checked
  against `AllowedDomainQualifiers`, and the account is substituted into `AdDnTemplate`. For
  example, `A112580` becomes `CN=A112580,OU=Service Accounts,OU=ENT,DC=addev,DC=jpmorganchase,DC=com`.

Robot keys fall back to `{Domain}\{user}` **or** `{machine}\{user}`, which look the same.
Without an allow-list, `ROBOTVM01\svc-batch` would resolve to the AD account of the same name.
Set `AllowedDomainQualifiers` and give robots and assets explicit External Names.

### `UsernameFormat` (credential assets only)

For an echoed DN `cn=a112580,...,dc=addev,dc=jpmorganchase,dc=com` and a username of
`A112580/a112580/REQ39729624`:

| Placeholder | Value |
|---|---|
| `{cn}` | `a112580` (from the DN Lockbox echoes back, which is lowercased) |
| `{response}` | `A112580/a112580/REQ39729624` |
| `{segment0}`…`{segment4}` | `A112580`, `a112580`, `REQ39729624`, empty, empty |
| `{domain}` | `addev.jpmorganchase.com` |
| `{netbios}` | `ADDEV` |

For example, `"{netbios}\\{cn}"` gives `ADDEV\a112580` and `"{segment1}@{domain}"` gives
`a112580@addev.jpmorganchase.com`. Unknown placeholders are rejected at validation. Confirm with
your AD team which form the target systems expect.

---

## Startup validation

The disconnected proxy calls `ValidateContextAsync` for every store at startup and **refuses to
start** if any of them throws. For each store, this plugin:

- parses and validates the context (URLs, required OAuth keys, certificate-source fields,
  placeholders, `{key}`);
- loads the certificate, checking the thumbprint, private-key access and validity window;
- if `ValidationAdDn` is set, does a real end-to-end read;
- otherwise, if `ValidateEndpointAtStartup` is true, POSTs `{}` and fails only on 401/403/407;
- otherwise makes **no network call**. That's the default, so one store's network or entitlement
  problem can't take down every store the proxy serves.

---

## Event Viewer logging

Off by default. Event IDs: **1000** initialized · **1001** host setting ignored · **1002** host
settings rejected · **1100/1101** validation succeeded/failed · **1200** requested (Verbose) ·
**1201** served · **1202** denied/not found · **1203** failed · **1300** write refused. Passwords
are never logged. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for levels, alerting and
troubleshooting by symptom.

---

## Operational cautions

- **Empty password**: the plugin raises `SecretNotFound` instead of returning `""`. The usual
  causes are that the client isn't entitled to that account's password, or the account hasn't
  been rotated into Vault yet.
- **`CacheSeconds`**: leave it at 0 unless your controls allow rotated passwords to be held in
  proxy memory.
- **`AllowInsecureTls`**: lab use only. Install the issuing CA instead.
- **`EventLogLevel=Verbose`**: writes a record for every request. Use it only while diagnosing.
- **Private-key ACL**: missing Read access for the app pool identity is the most common reason a
  deployment works in test but fails in production.
- **Encrypt the `Context`** with `appSettings:SigningCredentialSettings`.
- **`samples/appsettings.Production.json`**: its main context is missing `TokenEndpoint`,
  `ClientId` and `Resource`, so it won't pass validation as written. Use
  `appsettings.Production.merge.json` as the template.
