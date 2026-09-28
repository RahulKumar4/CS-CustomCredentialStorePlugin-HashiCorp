using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using UiPath.Orchestrator.Extensibility.Configuration;
using UiPath.Orchestrator.Extensibility.SecureStores;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// Read-only credential store that resolves AD service-account credentials through the Lockbox
    /// ad-details API, which fronts HashiCorp Vault's Active Directory secrets engine.
    ///
    /// Designed for the UiPath Orchestrator Credentials Proxy in DISCONNECTED mode: the robot asks the
    /// proxy for a credential, the proxy calls Lockbox over mutual TLS, and the credential is returned
    /// straight to the robot without transiting Orchestrator.
    ///
    /// The store is read-only by design. Vault owns the password and its rotation schedule
    /// (rotation_period / ttl in the response), so create, update and delete are refused rather than
    /// silently doing nothing.
    /// </summary>
    public class HashiCorpVaultLockboxSecureStore : ISecureStore
    {
        /// <summary>
        /// The store type name. This is the value you put in
        /// AppSettings:SecureStoreConfigurations[].Type, and what appears in the Orchestrator
        /// "Type" drop-down when the store is loaded by a connected proxy or on-prem Orchestrator.
        /// </summary>
        public const string NameIdentifier = "HashiCorpVaultLockbox";

        private readonly ILockboxClientFactory _clientFactory;

        public HashiCorpVaultLockboxSecureStore()
            : this(new LockboxClientFactory())
        {
        }

        /// <summary>Test seam - inject a fake client.</summary>
        internal HashiCorpVaultLockboxSecureStore(ILockboxClientFactory clientFactory)
        {
            _clientFactory = clientFactory ?? throw new ArgumentNullException(nameof(clientFactory));
        }

        public SecureStoreInfo GetStoreInfo() => new SecureStoreInfo
        {
            Identifier = NameIdentifier,
            IsReadOnly = true,
        };

        public void Initialize(Dictionary<string, string> hostSettings)
        {
            // Throwing here means the plugin is not offered for new stores and the failure is logged at
            // startup, which is exactly what we want for a malformed host setting.
            try
            {
                HostOptions.Load(hostSettings);
            }
            catch (Exception ex)
            {
                // Load configures the event sink before it validates anything else, so this still
                // reaches Event Viewer when event logging is switched on.
                EventLogWriter.Error(
                    PluginEventIds.ConfigurationRejected,
                    "Host settings were rejected; the plugin will not load.",
                    ex);
                throw;
            }

            var options = HostOptions.Current;
            EventLogWriter.Information(
                PluginEventIds.Initialized,
                "Plugin initialized. " +
                $"RequestTimeoutSeconds={options.RequestTimeoutSeconds}, " +
                $"RetryCount={options.RetryCount}, " +
                $"ExpectedTokenLength={options.ExpectedTokenLength}, " +
                $"TokenLengthRetryAttempts={options.TokenLengthRetryAttempts}, " +
                $"CacheSeconds={options.CacheSeconds}, " +
                $"AllowInsecureTls={options.AllowInsecureTls}, " +
                $"EventLogLevel={options.EventLogLevel}.");
        }

        public IEnumerable<ConfigurationEntry> GetConfiguration() => new List<ConfigurationEntry>
        {
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.EndpointUrl,
                DisplayName = "Lockbox ad-details endpoint",
                IsMandatory = true,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.TokenEndpoint,
                DisplayName = "OAuth2 token endpoint",
                IsMandatory = true,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.ClientId,
                DisplayName = "OAuth2 client id",
                IsMandatory = true,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.Resource,
                DisplayName = "OAuth2 resource",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.Audience,
                DisplayName = "JWT audience (defaults to the token endpoint)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.CertKid,
                DisplayName = "JWT key id (defaults to the certificate thumbprint)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Choice)
            {
                Key = ConfigKeys.CertKidHeaderName,
                DisplayName = "JWT header claim carrying the key id",
                IsMandatory = false,
                PossibleValues = new[] { "kid", "x5t" },
            },
            new ConfigurationValue(ConfigurationValueType.Choice)
            {
                Key = ConfigKeys.CertificateSource,
                DisplayName = "Certificate source",
                IsMandatory = false,
                PossibleValues = Enum.GetNames(typeof(CertificateSource)),
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.CertificateThumbprint,
                DisplayName = "Client certificate thumbprint",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.CertificateStoreName,
                DisplayName = "Certificate store name (default My)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Choice)
            {
                Key = ConfigKeys.CertificateStoreLocation,
                DisplayName = "Certificate store location",
                IsMandatory = false,
                PossibleValues = new[] { "LocalMachine", "CurrentUser" },
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.CertificateFilePath,
                DisplayName = "Client certificate pfx path",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Secret)
            {
                Key = ConfigKeys.CertificateBase64,
                DisplayName = "Client certificate pfx (base64)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Secret)
            {
                Key = ConfigKeys.CertificatePassword,
                DisplayName = "Client certificate password",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.AdDnTemplate,
                DisplayName = "AD DN template, e.g. CN={key},OU=Service Accounts,OU=ENT,DC=addev,DC=example,DC=com",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.UsernameFormat,
                DisplayName = "Username format (default {cn})",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Boolean)
            {
                Key = ConfigKeys.UseLastPasswordFallback,
                DisplayName = "Fall back to last_password when password is empty",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.ValidationAdDn,
                DisplayName = "Probe AD DN used at startup validation (optional)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Boolean)
            {
                Key = ConfigKeys.ValidateEndpointAtStartup,
                DisplayName = "Probe the endpoint during startup validation (can block proxy startup)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.Boolean)
            {
                Key = ConfigKeys.VerifyRobotUsername,
                DisplayName = "Verify the returned identity matches the requested account (robot flow)",
                IsMandatory = false,
            },
            new ConfigurationValue(ConfigurationValueType.String)
            {
                Key = ConfigKeys.AllowedDomainQualifiers,
                DisplayName = "Allowed domain qualifiers, comma-separated, e.g. ADDEV,ADPROD (optional)",
                IsMandatory = false,
            },
        };

        public async Task ValidateContextAsync(string context)
        {
            LockboxContext ctx = null;

            try
            {
                ctx = LockboxContext.FromJson(context);
                var client = _clientFactory.Create(ctx);

                // In disconnected mode the proxy calls this during startup for every entry in
                // SecureStoreConfigurations. A throw here stops the service from starting with a broken store.
                await client.VerifyConnectivityAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Startup validation failures terminate the proxy, so this is the single most useful
                // event to have in Event Viewer - by the time anyone looks, the service is down.
                EventLogWriter.Error(
                    PluginEventIds.ValidationFailed,
                    $"Startup validation failed for store {Describe(ctx)}.",
                    ex);
                throw;
            }

            EventLogWriter.Information(
                PluginEventIds.ValidationSucceeded,
                $"Startup validation succeeded for store {Describe(ctx)}.");
        }

        // ---------------- read APIs ----------------

        /// <summary>
        /// Robot credentials and password-style assets. Returns the password only; the username is
        /// already known to Orchestrator in this flow.
        /// </summary>
        public async Task<string> GetValueAsync(string context, string key)
        {
            LockboxContext ctx = null;

            try
            {
                ctx = LockboxContext.FromJson(context);

                var adKey = AdDnResolver.Resolve(ctx, key);
                EventLogWriter.Verbose(
                    PluginEventIds.CredentialRequested,
                    $"GetValue requested. Key='{key}', resolved ad_dn='{adKey.AdDn}'.");

                var details = await _clientFactory.Create(ctx)
                    .GetAdDetailsAsync(adKey.AdDn).ConfigureAwait(false);

                // This flow returns a password only - Orchestrator supplies the username from the robot
                // definition and the plugin never sees it. So a mismatch cannot be corrected here, only
                // detected. UsernameFormat is deliberately NOT applied on this path.
                if (ctx.VerifyRobotUsername)
                {
                    AdDnResolver.VerifyIdentity(
                        adKey,
                        string.IsNullOrWhiteSpace(details.Dn) ? adKey.AdDn : details.Dn,
                        details.Username);
                }

                var password = ExtractPassword(ctx, details, adKey.AdDn);

                EventLogWriter.Information(
                    PluginEventIds.CredentialServed,
                    $"Password served for ad_dn='{adKey.AdDn}' (requested key '{key}'). " +
                    $"Vault ttl={details.Ttl}s.");

                return password;
            }
            catch (Exception ex)
            {
                LogReadFailure("GetValue", key, ctx, ex);
                throw;
            }
        }

        /// <summary>Credential assets. Returns the username/password pair.</summary>
        public async Task<Credential> GetCredentialsAsync(string context, string key)
        {
            LockboxContext ctx = null;

            try
            {
                ctx = LockboxContext.FromJson(context);

                var adKey = AdDnResolver.Resolve(ctx, key);
                EventLogWriter.Verbose(
                    PluginEventIds.CredentialRequested,
                    $"GetCredentials requested. Key='{key}', resolved ad_dn='{adKey.AdDn}'.");

                var details = await _clientFactory.Create(ctx)
                    .GetAdDetailsAsync(adKey.AdDn).ConfigureAwait(false);

                // Prefer the DN echoed back by Lockbox, since it is authoritative and normalized.
                var dnForFormatting = string.IsNullOrWhiteSpace(details.Dn) ? adKey.AdDn : details.Dn;

                var credential = new Credential
                {
                    Username = AdDnResolver.FormatUsername(ctx, dnForFormatting, details.Username),
                    Password = ExtractPassword(ctx, details, adKey.AdDn),
                };

                // Usernames are identifiers, not secrets, and knowing which account was actually
                // served is the whole point of the record. The password never reaches this sink.
                EventLogWriter.Information(
                    PluginEventIds.CredentialServed,
                    $"Credential served for ad_dn='{adKey.AdDn}' (requested key '{key}') " +
                    $"as username '{credential.Username}'. Vault ttl={details.Ttl}s.");

                return credential;
            }
            catch (Exception ex)
            {
                LogReadFailure("GetCredentials", key, ctx, ex);
                throw;
            }
        }

        /// <summary>
        /// One shape for every read failure. An authorization refusal is a Warning rather than an
        /// Error: it is an expected outcome of an entitlement boundary and would otherwise drown the
        /// genuine faults in an operator's error filter.
        /// </summary>
        private static void LogReadFailure(string operation, string key, LockboxContext ctx, Exception ex)
        {
            var message =
                $"{operation} failed for key '{key}' against {Describe(ctx)}.";

            if (ex is SecureStoreException sse &&
                (sse.ErrorType == SecureStoreException.Type.UnauthorizedOperation ||
                 sse.ErrorType == SecureStoreException.Type.SecretNotFound))
            {
                EventLogWriter.Warning(PluginEventIds.CredentialDenied, message, ex);
                return;
            }

            EventLogWriter.Error(PluginEventIds.CredentialFailed, message, ex);
        }

        /// <summary>
        /// Identifies a store in an event without echoing its context: the endpoint plus a short
        /// fingerprint of the configuration, which is enough to tell two stores apart in the log.
        /// </summary>
        private static string Describe(LockboxContext ctx)
        {
            if (ctx == null)
            {
                return "(the store context could not be parsed)";
            }

            string endpoint;
            try
            {
                endpoint = ctx.ResolvedEndpoint.ToString();
            }
            catch
            {
                endpoint = ctx.EndpointUrl ?? "(unset)";
            }

            return $"'{endpoint}' [config {ctx.CacheKey().Substring(0, 8)}]";
        }

        /// <summary>
        /// Picks the password to hand back, and fails loudly when Lockbox returned an empty one.
        ///
        /// An empty password is the single most confusing failure mode here: handing "" to a robot
        /// produces an opaque login failure at the far end, whereas a SecureStoreException surfaces in
        /// the proxy logs and the job error with a usable message.
        /// </summary>
        private static string ExtractPassword(LockboxContext ctx, AdDetails details, string adDn)
        {
            if (!string.IsNullOrEmpty(details.Password))
            {
                return details.Password;
            }

            if (ctx.UseLastPasswordFallback && !string.IsNullOrEmpty(details.LastPassword))
            {
                return details.LastPassword;
            }

            var rotation = details.LastVaultRotation.HasValue
                ? $" Last Vault rotation: {details.LastVaultRotation:u}."
                : string.Empty;

            throw ExceptionHelper.SecretNotFound(
                $"Lockbox returned an empty password for '{adDn}'. The account exists but no password was " +
                "released - this usually means the client certificate is not entitled to read this " +
                $"account's password, or the account has not been rotated into the vault yet.{rotation}");
        }

        // ---------------- write APIs: refused ----------------

        public Task<string> CreateValueAsync(string context, string key, string value) =>
            throw Refuse(nameof(CreateValueAsync));

        public Task<string> UpdateValueAsync(string context, string key, string oldAugumentedKey, string value) =>
            throw Refuse(nameof(UpdateValueAsync));

        public Task<string> CreateCredentialsAsync(string context, string key, Credential value) =>
            throw Refuse(nameof(CreateCredentialsAsync));

        public Task<string> UpdateCredentialsAsync(
            string context, string key, string oldAugumentedKey, Credential value) =>
            throw Refuse(nameof(UpdateCredentialsAsync));

        public Task RemoveValueAsync(string context, string key) =>
            throw Refuse(nameof(RemoveValueAsync));

        /// <summary>
        /// Refuses a write and records it. Worth an event: an attempted write means someone expects
        /// this store to be read-write, and that misunderstanding is easier to spot in the log than
        /// in a single job's error message.
        /// </summary>
        private static SecureStoreException Refuse(string operation)
        {
            var exception = ExceptionHelper.NotSupported(operation);
            EventLogWriter.Warning(
                PluginEventIds.WriteRefused,
                $"Refused '{operation}': the Lockbox AD credential store is read-only.");
            return exception;
        }
    }
}
