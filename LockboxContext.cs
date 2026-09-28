using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    internal enum CertificateSource
    {
        Store = 0,
        File = 1,
        Base64 = 2,
    }

    /// <summary>
    /// Strongly typed view over the <c>context</c> string handed to every ISecureStore call.
    /// It is the JSON serialization of the fields declared in
    /// <see cref="HashiCorpVaultLockboxSecureStore.GetConfiguration"/>.
    /// </summary>
    internal sealed class LockboxContext
    {
        [JsonProperty(ConfigKeys.EndpointUrl)]
        public string EndpointUrl { get; set; }

        [JsonProperty(ConfigKeys.CertificateSource)]
        public string CertificateSourceRaw { get; set; }

        [JsonProperty(ConfigKeys.CertificateThumbprint)]
        public string CertificateThumbprint { get; set; }

        [JsonProperty(ConfigKeys.CertificateStoreName)]
        public string CertificateStoreName { get; set; }

        [JsonProperty(ConfigKeys.CertificateStoreLocation)]
        public string CertificateStoreLocation { get; set; }

        [JsonProperty(ConfigKeys.CertificateFilePath)]
        public string CertificateFilePath { get; set; }

        [JsonProperty(ConfigKeys.CertificateBase64)]
        public string CertificateBase64 { get; set; }

        [JsonProperty(ConfigKeys.CertificatePassword)]
        public string CertificatePassword { get; set; }

        [JsonProperty(ConfigKeys.TokenEndpoint)]
        public string TokenEndpoint { get; set; }

        [JsonProperty(ConfigKeys.ClientId)]
        public string ClientId { get; set; }

        [JsonProperty(ConfigKeys.Resource)]
        public string Resource { get; set; }

        [JsonProperty(ConfigKeys.Scope)]
        public string Scope { get; set; }

        [JsonProperty(ConfigKeys.Audience)]
        public string Audience { get; set; }

        [JsonProperty(ConfigKeys.CertKid)]
        public string CertKid { get; set; }

        [JsonProperty(ConfigKeys.CertKidHeaderName)]
        public string CertKidHeaderName { get; set; }

        [JsonProperty(ConfigKeys.JwtId)]
        public string JwtId { get; set; }

        [JsonProperty(ConfigKeys.AssertionLifetimeSeconds)]
        public int? AssertionLifetimeSeconds { get; set; }

        [JsonProperty(ConfigKeys.TokenRefreshSkewSeconds)]
        public int? TokenRefreshSkewSeconds { get; set; }

        [JsonProperty(ConfigKeys.SendClientCertificateToEndpoint)]
        public bool SendClientCertificateToEndpoint { get; set; }

        [JsonProperty(ConfigKeys.AdDnTemplate)]
        public string AdDnTemplate { get; set; }

        [JsonProperty(ConfigKeys.UsernameFormat)]
        public string UsernameFormat { get; set; }

        [JsonProperty(ConfigKeys.UseLastPasswordFallback)]
        public bool UseLastPasswordFallback { get; set; }

        [JsonProperty(ConfigKeys.ValidationAdDn)]
        public string ValidationAdDn { get; set; }

        [JsonProperty(ConfigKeys.ValidateEndpointAtStartup)]
        public bool ValidateEndpointAtStartup { get; set; }

        [JsonProperty(ConfigKeys.VerifyRobotUsername)]
        public bool VerifyRobotUsername { get; set; }

        [JsonProperty(ConfigKeys.AllowedDomainQualifiers)]
        public string AllowedDomainQualifiers { get; set; }

        // ---------------- derived ----------------

        /// <summary>Parsed <see cref="AllowedDomainQualifiers"/>. Empty means "accept any qualifier".</summary>
        public IReadOnlyCollection<string> ResolvedAllowedQualifiers =>
            string.IsNullOrWhiteSpace(AllowedDomainQualifiers)
                ? Array.Empty<string>()
                : AllowedDomainQualifiers
                    .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => s.Length > 0)
                    .ToArray();

        public Uri ResolvedEndpoint
        {
            get
            {
                if (string.IsNullOrWhiteSpace(EndpointUrl))
                {
                    throw ExceptionHelper.InvalidConfiguration($"'{ConfigKeys.EndpointUrl}' is mandatory.");
                }

                if (!Uri.TryCreate(EndpointUrl.Trim(), UriKind.Absolute, out var uri) ||
                    uri.Scheme != Uri.UriSchemeHttps)
                {
                    throw ExceptionHelper.InvalidConfiguration(
                        $"'{ConfigKeys.EndpointUrl}' must be an absolute https URL, " +
                        "e.g. https://lockbox-app.example.internal/ad-details.");
                }

                return uri;
            }
        }

        public CertificateSource ResolvedCertificateSource
        {
            get
            {
                if (string.IsNullOrWhiteSpace(CertificateSourceRaw))
                {
                    // Infer from whichever field was populated.
                    if (!string.IsNullOrWhiteSpace(CertificateBase64)) return CertificateSource.Base64;
                    if (!string.IsNullOrWhiteSpace(CertificateFilePath)) return CertificateSource.File;
                    return CertificateSource.Store;
                }

                switch (CertificateSourceRaw.Trim().ToLowerInvariant())
                {
                    case "store":
                    case "certstore":
                    case "windowsstore":
                        return CertificateSource.Store;
                    case "file":
                    case "pfx":
                        return CertificateSource.File;
                    case "base64":
                    case "inline":
                        return CertificateSource.Base64;
                    default:
                        throw ExceptionHelper.InvalidConfiguration(
                            $"'{ConfigKeys.CertificateSource}' must be Store, File or Base64 " +
                            $"but was '{CertificateSourceRaw}'.");
                }
            }
        }

        public Uri ResolvedTokenEndpoint
        {
            get
            {
                if (string.IsNullOrWhiteSpace(TokenEndpoint))
                {
                    throw ExceptionHelper.InvalidConfiguration(
                        $"'{ConfigKeys.TokenEndpoint}' is mandatory. Lockbox is fronted by a gateway " +
                        "that authenticates a bearer token; the certificate signs the client assertion " +
                        "used to obtain it.");
                }

                if (!Uri.TryCreate(TokenEndpoint.Trim(), UriKind.Absolute, out var uri) ||
                    uri.Scheme != Uri.UriSchemeHttps)
                {
                    throw ExceptionHelper.InvalidConfiguration(
                        $"'{ConfigKeys.TokenEndpoint}' must be an absolute https URL.");
                }

                return uri;
            }
        }

        public string ResolvedAudience =>
            string.IsNullOrWhiteSpace(Audience) ? ResolvedTokenEndpoint.AbsoluteUri : Audience.Trim();

        public string ResolvedCertKidHeaderName =>
            string.IsNullOrWhiteSpace(CertKidHeaderName) ? "kid" : CertKidHeaderName.Trim();

        public int ResolvedAssertionLifetimeSeconds =>
            AssertionLifetimeSeconds.HasValue && AssertionLifetimeSeconds.Value > 0
                ? Math.Min(AssertionLifetimeSeconds.Value, 3600)
                : 300;

        public int ResolvedTokenRefreshSkewSeconds =>
            TokenRefreshSkewSeconds.HasValue && TokenRefreshSkewSeconds.Value >= 0
                ? TokenRefreshSkewSeconds.Value
                : 60;

        /// <summary>Key id for the JWT header; defaults to the certificate thumbprint.</summary>
        public string ResolvedCertKid(System.Security.Cryptography.X509Certificates.X509Certificate2 cert) =>
            string.IsNullOrWhiteSpace(CertKid) ? cert?.Thumbprint : CertKid.Trim();

        public string ResolvedUsernameFormat =>
            string.IsNullOrWhiteSpace(UsernameFormat) ? "{cn}" : UsernameFormat.Trim();

        public static LockboxContext FromJson(string context)
        {
            if (string.IsNullOrWhiteSpace(context))
            {
                throw ExceptionHelper.InvalidConfiguration("The credential store context is empty.");
            }

            LockboxContext ctx;
            try
            {
                ctx = JsonConvert.DeserializeObject<LockboxContext>(context);
            }
            catch (JsonException ex)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    "The credential store context is not valid JSON: " + ex.Message);
            }

            if (ctx == null)
            {
                throw ExceptionHelper.InvalidConfiguration("The credential store context could not be parsed.");
            }

            ctx.Validate();
            return ctx;
        }

        public void Validate()
        {
            var _ = ResolvedEndpoint;
            var token = ResolvedTokenEndpoint;

            if (string.IsNullOrWhiteSpace(ClientId))
            {
                throw ExceptionHelper.InvalidConfiguration($"'{ConfigKeys.ClientId}' is mandatory.");
            }

            if (string.IsNullOrWhiteSpace(Resource) && string.IsNullOrWhiteSpace(Scope))
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"Either '{ConfigKeys.Resource}' or '{ConfigKeys.Scope}' must be set, " +
                    "depending on what the identity provider expects.");
            }

            if (!string.Equals(ResolvedCertKidHeaderName, "kid", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ResolvedCertKidHeaderName, "x5t", StringComparison.OrdinalIgnoreCase))
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"'{ConfigKeys.CertKidHeaderName}' must be 'kid' or 'x5t'.");
            }

            switch (ResolvedCertificateSource)
            {
                case CertificateSource.Store:
                    if (string.IsNullOrWhiteSpace(CertificateThumbprint))
                    {
                        throw ExceptionHelper.InvalidConfiguration(
                            $"'{ConfigKeys.CertificateThumbprint}' is mandatory when " +
                            $"'{ConfigKeys.CertificateSource}' is 'Store'.");
                    }

                    break;

                case CertificateSource.File:
                    if (string.IsNullOrWhiteSpace(CertificateFilePath))
                    {
                        throw ExceptionHelper.InvalidConfiguration(
                            $"'{ConfigKeys.CertificateFilePath}' is mandatory when " +
                            $"'{ConfigKeys.CertificateSource}' is 'File'.");
                    }

                    break;

                case CertificateSource.Base64:
                    if (string.IsNullOrWhiteSpace(CertificateBase64))
                    {
                        throw ExceptionHelper.InvalidConfiguration(
                            $"'{ConfigKeys.CertificateBase64}' is mandatory when " +
                            $"'{ConfigKeys.CertificateSource}' is 'Base64'.");
                    }

                    break;
            }

            AdDnResolver.ValidateUsernameFormat(ResolvedUsernameFormat);

            if (!string.IsNullOrWhiteSpace(AdDnTemplate) &&
                AdDnTemplate.IndexOf("{key}", StringComparison.OrdinalIgnoreCase) < 0)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"'{ConfigKeys.AdDnTemplate}' must contain the '{{key}}' placeholder.");
            }
        }

        /// <summary>
        /// Fingerprint of the connection identity. Used to key the pooled HttpClient and the credential
        /// cache. Secret material is hashed, never stored in the key itself.
        /// </summary>
        public string CacheKey() => Hashing.Sha256(string.Join("|",
            ResolvedEndpoint.AbsoluteUri,
            ResolvedCertificateSource.ToString(),
            CertificateThumbprint ?? string.Empty,
            CertificateStoreName ?? string.Empty,
            CertificateStoreLocation ?? string.Empty,
            CertificateFilePath ?? string.Empty,
            Hashing.Sha256(CertificateBase64 ?? string.Empty),
            Hashing.Sha256(CertificatePassword ?? string.Empty),
            TokenEndpoint ?? string.Empty,
            ClientId ?? string.Empty,
            Resource ?? string.Empty,
            Scope ?? string.Empty));
    }

    /// <summary>The outcome of turning an Orchestrator key into a Lockbox <c>ad_dn</c>.</summary>
    internal sealed class ResolvedAdKey
    {
        /// <summary>The value sent as <c>ad_dn</c>.</summary>
        public string AdDn { get; set; }

        /// <summary>The bare account name (sAMAccountName), or the CN when the key was a full DN.</summary>
        public string Account { get; set; }

        /// <summary>The domain or machine qualifier stripped from the key, or null if there was none.</summary>
        public string Qualifier { get; set; }

        /// <summary>True when the key was already a distinguished name and bypassed the template.</summary>
        public bool KeyWasDistinguishedName { get; set; }

        /// <summary>The key exactly as Orchestrator supplied it, for use in error messages.</summary>
        public string OriginalKey { get; set; }
    }

    /// <summary>
    /// Turns the key that Orchestrator supplies into the <c>ad_dn</c> the Lockbox API expects, and turns
    /// the API response into the username the robot should log in with.
    /// </summary>
    internal static class AdDnResolver
    {
        /// <summary>
        /// Builds the ad_dn and reports what it derived along the way.
        ///
        /// The key is the asset's external name (or the asset name when external name is blank); for robot
        /// credentials it is the external name, or {Domain}\{user} / {machineName}\{user}.
        ///
        /// If the key already looks like a distinguished name it is passed through verbatim, so an asset
        /// can carry the full DN. Otherwise the qualifier and any UPN suffix are stripped and the
        /// remainder is substituted into AdDnTemplate.
        /// </summary>
        public static ResolvedAdKey Resolve(LockboxContext context, string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw ExceptionHelper.SecretNotFound("The credential key is empty.");
            }

            var originalKey = key.Trim();

            if (LooksLikeDn(originalKey))
            {
                return new ResolvedAdKey
                {
                    AdDn = originalKey,
                    Account = GetDnComponent(originalKey, "CN"),
                    Qualifier = null,
                    KeyWasDistinguishedName = true,
                    OriginalKey = originalKey,
                };
            }

            var account = originalKey;
            string qualifier = null;

            // Split a domain or machine qualifier: ADDEV\a112580 -> ADDEV + a112580
            var backslash = account.LastIndexOf('\\');
            if (backslash >= 0)
            {
                qualifier = account.Substring(0, backslash).Trim();
                account = account.Substring(backslash + 1).Trim();

                // A key such as "ADDEV\" leaves nothing to resolve. Previously this produced a
                // malformed DN; now it fails with something actionable.
                if (account.Length == 0)
                {
                    throw ExceptionHelper.SecretNotFound(
                        $"The credential key '{originalKey}' has a domain qualifier but no account name. " +
                        "Set the external name on the robot or asset explicitly.");
                }
            }

            // Strip a UPN suffix: a112580@addev.jpmorganchase.com -> a112580
            var at = account.IndexOf('@');
            if (at > 0)
            {
                account = account.Substring(0, at);
            }

            // Guard against a local machine account resolving to a same-named AD account.
            var allowed = context.ResolvedAllowedQualifiers;
            if (allowed.Count > 0 &&
                qualifier != null &&
                !allowed.Any(a => string.Equals(a, qualifier, StringComparison.OrdinalIgnoreCase)))
            {
                throw ExceptionHelper.SecretNotFound(
                    $"The credential key '{originalKey}' is qualified with '{qualifier}', which is not in " +
                    $"'{ConfigKeys.AllowedDomainQualifiers}' ({string.Join(", ", allowed)}). " +
                    "For a robot credential this usually means the key fell back to " +
                    "{machineName}\\{userName}; set the robot's external name explicitly.");
            }

            if (string.IsNullOrWhiteSpace(context.AdDnTemplate))
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The key '{originalKey}' is not a distinguished name and '{ConfigKeys.AdDnTemplate}' " +
                    "is not configured. Either set the external name to the full AD DN, or configure a " +
                    "template such as: CN={key},OU=Service Accounts,OU=ENT,DC=addev,DC=example,DC=com");
            }

            return new ResolvedAdKey
            {
                AdDn = ReplaceCaseInsensitive(context.AdDnTemplate.Trim(), "{key}", account),
                Account = account,
                Qualifier = qualifier,
                KeyWasDistinguishedName = false,
                OriginalKey = originalKey,
            };
        }

        /// <summary>
        /// Confirms the identity Lockbox returned actually corresponds to the account that was requested.
        ///
        /// Used by the robot-credential flow, where the plugin returns only a password and so cannot
        /// correct a username mismatch. A match against the CN of the returned DN, or against any
        /// slash-delimited segment of ad_details.username, is accepted.
        /// </summary>
        public static void VerifyIdentity(ResolvedAdKey key, string returnedDn, string returnedUsername)
        {
            if (string.IsNullOrWhiteSpace(key.Account))
            {
                return;
            }

            var candidates = new List<string>();

            var cn = GetDnComponent(returnedDn, "CN");
            if (!string.IsNullOrWhiteSpace(cn))
            {
                candidates.Add(cn);
            }

            if (!string.IsNullOrWhiteSpace(returnedUsername))
            {
                candidates.AddRange(returnedUsername.Split('/').Select(s => s.Trim()));
                var at = returnedUsername.IndexOf('@');
                if (at > 0)
                {
                    candidates.Add(returnedUsername.Substring(0, at).Trim());
                }
            }

            if (candidates.Any(c => string.Equals(c, key.Account, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            throw ExceptionHelper.SecretNotFound(
                $"Identity mismatch for key '{key.OriginalKey}': the request resolved to account " +
                $"'{key.Account}' but Lockbox returned dn '{returnedDn}' / username '{returnedUsername}'. " +
                "The password was discarded rather than returned against the wrong account. Check the " +
                $"external name and '{ConfigKeys.AdDnTemplate}', or set " +
                $"'{ConfigKeys.VerifyRobotUsername}' to false if this pairing is intentional.");
        }

        private static bool LooksLikeDn(string value) =>
            value.IndexOf('=') > 0 &&
            (value.StartsWith("CN=", StringComparison.OrdinalIgnoreCase) ||
             value.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) ||
             value.StartsWith("DC=", StringComparison.OrdinalIgnoreCase) ||
             value.StartsWith("UID=", StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Renders the configured UsernameFormat.
        ///
        /// Available placeholders, given
        ///   ad_dn    = CN=A112580,OU=Service Accounts,OU=ENT,DC=addev,DC=example,DC=com
        ///   response = A112580/a112580/REQ39729624
        ///
        ///   {cn}        A112580          - the CN component of the DN
        ///   {response}  A112580/a112580/REQ39729624 - ad_details.username exactly as returned
        ///   {segment0}  A112580          - slash-delimited pieces of ad_details.username
        ///   {segment1}  a112580
        ///   {segment2}  REQ39729624
        ///   {domain}    addev.example.com - DC components joined with dots
        ///   {netbios}   addev             - first DC component, uppercased
        /// </summary>
        public static string FormatUsername(LockboxContext context, string adDn, string responseUsername)
        {
            var segments = (responseUsername ?? string.Empty)
                .Split('/')
                .Select(s => s.Trim())
                .ToArray();

            var result = context.ResolvedUsernameFormat;
            result = ReplaceCaseInsensitive(result, "{response}", responseUsername ?? string.Empty);
            result = ReplaceCaseInsensitive(result, "{cn}", GetDnComponent(adDn, "CN") ?? string.Empty);
            result = ReplaceCaseInsensitive(result, "{domain}", GetDomain(adDn));
            result = ReplaceCaseInsensitive(result, "{netbios}", GetNetbios(adDn));

            for (var i = 0; i < MaxSegments; i++)
            {
                var value = i < segments.Length ? segments[i] : string.Empty;
                result = ReplaceCaseInsensitive(result, "{segment" + i + "}", value);
            }

            // A placeholder we do not recognise must never leak through as a literal - that would hand
            // the robot a username containing braces and fail authentication for no visible reason.
            var unresolved = PlaceholderPattern.Match(result);
            if (unresolved.Success)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"'{ConfigKeys.UsernameFormat}' contains the unknown placeholder " +
                    $"'{unresolved.Value}'. Supported placeholders: {string.Join(", ", KnownPlaceholders)}.");
            }

            if (string.IsNullOrWhiteSpace(result))
            {
                // Every placeholder resolved to empty. Never hand the robot a blank username -
                // fall back to whatever the API returned.
                result = responseUsername ?? string.Empty;
            }

            return result;
        }

        private const int MaxSegments = 5;

        private static readonly Regex PlaceholderPattern =
            new Regex(@"\{[^{}]*\}", RegexOptions.Compiled);

        /// <summary>Every placeholder <see cref="FormatUsername"/> understands.</summary>
        public static readonly string[] KnownPlaceholders =
            Enumerable.Range(0, MaxSegments).Select(i => "{segment" + i + "}")
                .Concat(new[] { "{cn}", "{response}", "{domain}", "{netbios}" })
                .ToArray();

        /// <summary>
        /// Validates a format string without needing a response. Called from
        /// <see cref="LockboxContext.Validate"/> so a typo fails at proxy startup rather than on the
        /// first robot request.
        /// </summary>
        public static void ValidateUsernameFormat(string format)
        {
            if (string.IsNullOrWhiteSpace(format))
            {
                return;
            }

            foreach (Match match in PlaceholderPattern.Matches(format))
            {
                if (!KnownPlaceholders.Any(
                        p => string.Equals(p, match.Value, StringComparison.OrdinalIgnoreCase)))
                {
                    throw ExceptionHelper.InvalidConfiguration(
                        $"'{ConfigKeys.UsernameFormat}' contains the unknown placeholder " +
                        $"'{match.Value}'. Supported placeholders: {string.Join(", ", KnownPlaceholders)}.");
                }
            }
        }

        private static string GetDomain(string dn)
        {
            var parts = SplitDn(dn)
                .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Substring(3).Trim())
                .Where(p => p.Length > 0)
                .ToList();

            return parts.Count == 0 ? string.Empty : string.Join(".", parts);
        }

        private static string GetNetbios(string dn)
        {
            var first = SplitDn(dn)
                .FirstOrDefault(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase));

            return first == null ? string.Empty : first.Substring(3).Trim().ToUpperInvariant();
        }

        private static string GetDnComponent(string dn, string attribute)
        {
            var prefix = attribute + "=";
            var match = SplitDn(dn)
                .FirstOrDefault(p => p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

            return match?.Substring(prefix.Length).Trim();
        }

        /// <summary>
        /// Splits a DN on unescaped commas. Handles "OU=Service Accounts" and escaped "\," values.
        /// </summary>
        private static IEnumerable<string> SplitDn(string dn)
        {
            if (string.IsNullOrWhiteSpace(dn))
            {
                yield break;
            }

            var current = new System.Text.StringBuilder();
            for (var i = 0; i < dn.Length; i++)
            {
                var c = dn[i];

                if (c == '\\' && i + 1 < dn.Length)
                {
                    current.Append(dn[i + 1]);
                    i++;
                    continue;
                }

                if (c == ',')
                {
                    yield return current.ToString().Trim();
                    current.Clear();
                    continue;
                }

                current.Append(c);
            }

            if (current.Length > 0)
            {
                yield return current.ToString().Trim();
            }
        }

        private static string ReplaceCaseInsensitive(string input, string token, string replacement)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            var index = input.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                input = input.Substring(0, index) + replacement + input.Substring(index + token.Length);
                index = input.IndexOf(
                    token, index + replacement.Length, StringComparison.OrdinalIgnoreCase);
            }

            return input;
        }
    }
}
