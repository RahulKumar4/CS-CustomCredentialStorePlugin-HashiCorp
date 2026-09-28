using System;
using System.Collections.Generic;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// Instance-level configuration keys.
    ///
    /// These exact strings are the JSON property names you must use in
    /// AppSettings:SecureStoreConfigurations[].Context (disconnected proxy), and they are also the keys
    /// Orchestrator uses to render the dynamic "Add credential store" form (connected proxy / on-prem).
    /// </summary>
    internal static class ConfigKeys
    {
        /// <summary>Full Lockbox endpoint, e.g. https://lockbox-app.../ad-details</summary>
        public const string EndpointUrl = "EndpointUrl";

        /// <summary>Where to obtain the X509 client certificate: Store | File | Base64</summary>
        public const string CertificateSource = "CertificateSource";

        /// <summary>Certificate thumbprint. Used when CertificateSource = Store.</summary>
        public const string CertificateThumbprint = "CertificateThumbprint";

        /// <summary>Certificate store name (default My). Used when CertificateSource = Store.</summary>
        public const string CertificateStoreName = "CertificateStoreName";

        /// <summary>Certificate store location: LocalMachine | CurrentUser (default LocalMachine).</summary>
        public const string CertificateStoreLocation = "CertificateStoreLocation";

        /// <summary>Path to a .pfx/.p12 file. Used when CertificateSource = File.</summary>
        public const string CertificateFilePath = "CertificateFilePath";

        /// <summary>Base64 of a .pfx/.p12. Used when CertificateSource = Base64.</summary>
        public const string CertificateBase64 = "CertificateBase64";

        /// <summary>Password protecting the pfx. Used for File and Base64 sources.</summary>
        public const string CertificatePassword = "CertificatePassword";

        // ---- OAuth2 private_key_jwt (the certificate SIGNS an assertion; it is not used for mTLS) ----

        /// <summary>Token endpoint, e.g. https://idauatg2.example.com/adfs/oauth2/token</summary>
        public const string TokenEndpoint = "TokenEndpoint";

        /// <summary>OAuth2 client_id registered with the identity provider.</summary>
        public const string ClientId = "ClientId";

        /// <summary>The 'resource' form parameter, e.g. JPMC:URI:RS-...-GSMFederated-UAT</summary>
        public const string Resource = "Resource";

        /// <summary>Optional 'scope' form parameter, if the provider uses scopes instead of resource.</summary>
        public const string Scope = "Scope";

        /// <summary>JWT 'aud' claim. Defaults to TokenEndpoint, which is the usual value.</summary>
        public const string Audience = "Audience";

        /// <summary>
        /// Key identifier placed in the JWT header. Defaults to the certificate thumbprint.
        /// </summary>
        public const string CertKid = "CertKid";

        /// <summary>
        /// Name of the JWT header claim carrying the key id: "kid" (default) or "x5t".
        /// ADFS commonly expects x5t; confirm against a working token before changing.
        /// </summary>
        public const string CertKidHeaderName = "CertKidHeaderName";

        /// <summary>Fixed JWT 'jti'. Leave empty to generate a fresh GUID per assertion (recommended).</summary>
        public const string JwtId = "JwtId";

        /// <summary>Lifetime of the client assertion in seconds. Default 300.</summary>
        public const string AssertionLifetimeSeconds = "AssertionLifetimeSeconds";

        /// <summary>Refresh the access token this many seconds before it expires. Default 60.</summary>
        public const string TokenRefreshSkewSeconds = "TokenRefreshSkewSeconds";

        /// <summary>
        /// Also present the certificate as a TLS client certificate on the Lockbox call. Default false:
        /// the gateway authenticates the bearer token, not the transport.
        /// </summary>
        public const string SendClientCertificateToEndpoint = "SendClientCertificateToEndpoint";

        /// <summary>
        /// Template used to build the ad_dn when the incoming key is not already a distinguished name.
        /// Use {key} as the placeholder, e.g.
        /// CN={key},OU=Service Accounts,OU=ENT,DC=addev,DC=jpmorganchase,DC=com
        /// </summary>
        public const string AdDnTemplate = "AdDnTemplate";

        /// <summary>
        /// Template used to build the username handed to the robot. Placeholders:
        /// {cn} {response} {segment0} {segment1} {segment2} {domain} {netbios}. Default "{cn}".
        /// </summary>
        public const string UsernameFormat = "UsernameFormat";

        /// <summary>
        /// When true, fall back to ad_details.last_password if ad_details.password is empty.
        /// Useful during a rotation window. Default false.
        /// </summary>
        public const string UseLastPasswordFallback = "UseLastPasswordFallback";

        /// <summary>
        /// Optional ad_dn used only by ValidateContextAsync so that proxy startup performs a real
        /// end-to-end read. Leave empty to validate connectivity and mTLS only.
        /// </summary>
        public const string ValidationAdDn = "ValidationAdDn";

        /// <summary>
        /// When true, GetValueAsync cross-checks the account in the requested key against the identity
        /// Lockbox returned, and fails if they disagree.
        ///
        /// This matters because the robot-credential flow returns a password ONLY - the username comes
        /// from the robot definition in Orchestrator and the plugin never sees it. Without this check, a
        /// mismatch hands the robot a valid password for the wrong account, which surfaces as an opaque
        /// authentication failure on the target system rather than a diagnosable error here. Default false.
        /// </summary>
        public const string VerifyRobotUsername = "VerifyRobotUsername";

        /// <summary>
        /// When true, ValidateContextAsync sends a probe request to the endpoint at startup and fails
        /// if the client certificate is rejected.
        ///
        /// Default FALSE, deliberately. The disconnected proxy treats a validation exception as fatal
        /// and terminates the process, so making startup depend on a remote endpoint lets one store's
        /// entitlement or network problem take down every store the proxy serves. Certificate loading
        /// is validated regardless - that check is local and cannot be affected by the endpoint.
        /// </summary>
        public const string ValidateEndpointAtStartup = "ValidateEndpointAtStartup";

        /// <summary>
        /// Optional comma-separated allow-list of domain / NetBIOS qualifiers accepted in a key,
        /// e.g. "ADDEV,ADPROD".
        ///
        /// Robot keys default to {Domain}\{user} OR {machineName}\{user}. Those are indistinguishable by
        /// shape, so without an allow-list a local machine account such as ROBOTVM01\svc-batch would
        /// silently resolve to the AD account of the same name. Leave empty to accept any qualifier.
        /// </summary>
        public const string AllowedDomainQualifiers = "AllowedDomainQualifiers";
    }

    /// <summary>
    /// Host-level settings.
    ///
    /// IMPORTANT - key form. The values are written in configuration fully qualified:
    ///   Plugins.SecureStores.HashiCorpVaultLockbox.RequestTimeoutSeconds
    /// but the platform STRIPS that prefix before injecting the dictionary into
    /// <c>ISecureStore.Initialize</c>. The repo's Example2.SqlPass sample proves it: it deserializes
    /// the dictionary straight onto a POCO whose property is <c>Driver</c>, and its unit test seeds
    /// the dictionary with the bare key "Driver" while the docs describe the setting as living under
    /// Plugins.SecureStores.{Plugin}.{SettingName}.
    ///
    /// So lookups must use the BARE name. <see cref="HostOptions.Load"/> tries the qualified key
    /// first (more specific, and harmless if the host ever passes full keys) and then falls back to
    /// the bare name, which is what actually arrives today.
    /// </summary>
    internal static class HostSettingKeys
    {
        /// <summary>The prefix used in appsettings.Production.json / web.config.</summary>
        public const string Prefix =
            "Plugins.SecureStores." + HashiCorpVaultLockboxSecureStore.NameIdentifier + ".";

        // Bare setting names - the form that actually arrives in the Initialize dictionary.
        public const string RequestTimeoutSeconds = "RequestTimeoutSeconds";
        public const string CacheSeconds = "CacheSeconds";
        public const string AllowInsecureTls = "AllowInsecureTls";
        public const string RetryCount = "RetryCount";
        public const string ExpectedTokenLength = "ExpectedTokenLength";
        public const string TokenLengthRetryAttempts = "TokenLengthRetryAttempts";

        // ---- Windows event log (Event Viewer) ----
        public const string EventLogEnabled = "EventLogEnabled";
        public const string EventLogLevel = "EventLogLevel";
        public const string EventLogName = "EventLogName";
        public const string EventLogSource = "EventLogSource";

        /// <summary>The fully qualified form, for configuration docs and error messages.</summary>
        public static string Qualified(string bareName) => Prefix + bareName;
    }

    internal sealed class HostOptions
    {
        public static HostOptions Current { get; private set; } = new HostOptions();

        /// <summary>HTTP timeout for Lockbox calls, in seconds. Default 30.</summary>
        public int RequestTimeoutSeconds { get; private set; } = 30;

        /// <summary>
        /// In-memory retention for a fetched credential, in seconds. 0 (default) disables caching, so
        /// every robot request hits Lockbox. Raise it only if you are comfortable holding rotated
        /// service-account passwords in the proxy's memory for that long.
        /// </summary>
        public int CacheSeconds { get; private set; }

        /// <summary>
        /// Disables TLS validation of the Lockbox server certificate. Lab use only - prefer installing the
        /// issuing CA into the machine trust store.
        /// </summary>
        public bool AllowInsecureTls { get; private set; }

        /// <summary>Retries for transient failures (timeouts, 429, 5xx). Default 2.</summary>
        public int RetryCount { get; private set; } = 2;

        /// <summary>
        /// Exact length a usable access_token must have, e.g. 1187. A token of any other length is
        /// discarded and a new one requested. 0 (default) accepts any length.
        /// </summary>
        public int ExpectedTokenLength { get; private set; }

        /// <summary>
        /// Extra token requests made when the access_token length does not match
        /// <see cref="ExpectedTokenLength"/>. Default 3, maximum 10.
        /// </summary>
        public int TokenLengthRetryAttempts { get; private set; } = 3;

        /// <summary>
        /// Writes plugin events to the Windows event log (Event Viewer). Default false.
        ///
        /// The disconnected proxy's own log is the primary record; this exists because credential
        /// failures are usually investigated by a Windows operator on the proxy host, who has Event
        /// Viewer in front of them and no access to the proxy's log files.
        /// </summary>
        public bool EventLogEnabled { get; private set; }

        /// <summary>
        /// How much detail reaches the event log: Off | Error | Warning | Information | Verbose.
        /// Default Error. Ignored when <see cref="EventLogEnabled"/> is false.
        /// </summary>
        public EventLogLevel EventLogLevel { get; private set; } = EventLogLevel.Error;

        /// <summary>Event log to write to. Default "Application".</summary>
        public string EventLogName { get; private set; } = "Application";

        /// <summary>
        /// Event source shown in the Source column. Default "UiPath HashiCorpVaultLockbox".
        /// Registering a new source needs administrative rights; when the proxy identity does not
        /// have them the plugin falls back to the always-present "Application" source rather than
        /// losing the events.
        /// </summary>
        public string EventLogSource { get; private set; } = "UiPath HashiCorpVaultLockbox";

        public static void Load(IReadOnlyDictionary<string, string> hostSettings)
        {
            var options = new HostOptions();

            if (hostSettings != null)
            {
                // Diagnostics are read FIRST and leniently. A bad value here must not be the reason
                // the operator loses the event that would have explained the strict failures below,
                // so these fall back to their defaults and report themselves instead of throwing.
                var warnings = ReadEventLogSettings(hostSettings, options);
                EventLogWriter.Configure(options);

                foreach (var warning in warnings)
                {
                    EventLogWriter.Warning(PluginEventIds.HostSettingIgnored, warning);
                }

                options.RequestTimeoutSeconds =
                    ReadInt(hostSettings, HostSettingKeys.RequestTimeoutSeconds, 30, 5, 300);
                options.CacheSeconds =
                    ReadInt(hostSettings, HostSettingKeys.CacheSeconds, 0, 0, 3600);
                options.RetryCount =
                    ReadInt(hostSettings, HostSettingKeys.RetryCount, 2, 0, 5);
                options.ExpectedTokenLength =
                    ReadInt(hostSettings, HostSettingKeys.ExpectedTokenLength, 0, 0, 65536);
                options.TokenLengthRetryAttempts =
                    ReadInt(hostSettings, HostSettingKeys.TokenLengthRetryAttempts, 3, 0, 10);
                options.AllowInsecureTls =
                    ReadBool(hostSettings, HostSettingKeys.AllowInsecureTls, false);
            }
            else
            {
                EventLogWriter.Configure(options);
            }

            Current = options;
        }

        /// <summary>
        /// Reads the event-log settings without throwing, returning a message for every value that
        /// was ignored so the caller can log them once the sink is up.
        /// </summary>
        private static List<string> ReadEventLogSettings(
            IReadOnlyDictionary<string, string> settings, HostOptions options)
        {
            var warnings = new List<string>();

            if (TryRead(settings, HostSettingKeys.EventLogEnabled, out var enabledRaw))
            {
                if (bool.TryParse(enabledRaw.Trim(), out var enabled))
                {
                    options.EventLogEnabled = enabled;
                }
                else
                {
                    warnings.Add(
                        $"Host setting '{HostSettingKeys.Qualified(HostSettingKeys.EventLogEnabled)}' " +
                        $"must be 'true' or 'false' but was '{enabledRaw}'. Event logging stays off.");
                }
            }

            if (TryRead(settings, HostSettingKeys.EventLogLevel, out var levelRaw))
            {
                if (Enum.TryParse<EventLogLevel>(levelRaw.Trim(), ignoreCase: true, result: out var level) &&
                    Enum.IsDefined(typeof(EventLogLevel), level))
                {
                    options.EventLogLevel = level;
                }
                else
                {
                    warnings.Add(
                        $"Host setting '{HostSettingKeys.Qualified(HostSettingKeys.EventLogLevel)}' " +
                        $"must be one of {string.Join(" | ", Enum.GetNames(typeof(EventLogLevel)))} " +
                        $"but was '{levelRaw}'. Falling back to {options.EventLogLevel}.");
                }
            }

            if (TryRead(settings, HostSettingKeys.EventLogName, out var logName))
            {
                options.EventLogName = logName.Trim();
            }

            if (TryRead(settings, HostSettingKeys.EventLogSource, out var source))
            {
                options.EventLogSource = source.Trim();
            }

            return warnings;
        }

        /// <summary>
        /// Resolves a host setting, accepting either the bare name (what the platform injects) or the
        /// fully qualified name (what appears in configuration), so the plugin works either way.
        /// </summary>
        private static bool TryRead(
            IReadOnlyDictionary<string, string> settings, string bareName, out string value)
        {
            if (settings.TryGetValue(HostSettingKeys.Qualified(bareName), out value) &&
                !string.IsNullOrWhiteSpace(value))
            {
                return true;
            }

            if (settings.TryGetValue(bareName, out value) && !string.IsNullOrWhiteSpace(value))
            {
                return true;
            }

            value = null;
            return false;
        }

        private static bool ReadBool(IReadOnlyDictionary<string, string> settings, string key, bool fallback)
        {
            if (!TryRead(settings, key, out var raw))
            {
                return fallback;
            }

            if (!bool.TryParse(raw.Trim(), out var parsed))
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"Host setting '{HostSettingKeys.Qualified(key)}' must be 'true' or 'false' " +
                    $"but was '{raw}'.");
            }

            return parsed;
        }

        private static int ReadInt(
            IReadOnlyDictionary<string, string> settings, string key, int fallback, int min, int max)
        {
            if (!TryRead(settings, key, out var raw))
            {
                return fallback;
            }

            if (!int.TryParse(raw.Trim(), out var parsed) || parsed < min || parsed > max)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"Host setting '{HostSettingKeys.Qualified(key)}' must be an integer between " +
                    $"{min} and {max} but was '{raw}'.");
            }

            return parsed;
        }
    }
}
