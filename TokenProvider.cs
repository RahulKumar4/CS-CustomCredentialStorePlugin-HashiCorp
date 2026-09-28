using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// Obtains the OAuth2 bearer token that Lockbox requires, using the
    /// <c>private_key_jwt</c> client-authentication method (RFC 7523).
    ///
    /// The X509 certificate is used to SIGN a client assertion - it is not presented as a TLS client
    /// certificate. That distinction matters: an earlier version of this plugin used the certificate
    /// for mTLS and was rejected with a bodiless 401 by the Envoy gateway in front of Lockbox, because
    /// the request carried no bearer token at all.
    ///
    /// Token request body (application/x-www-form-urlencoded):
    ///   grant_type            = client_credentials
    ///   client_id             = {ClientId}
    ///   client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
    ///   client_assertion      = {signed JWT}
    ///   resource              = {Resource}
    /// </summary>
    internal sealed class TokenProvider
    {
        public const string ClientAssertionType =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>Tokens are cached per store configuration and evicted before they expire.</summary>
        private static readonly CredentialCache<string> TokenCache = new CredentialCache<string>();

        /// <summary>
        /// One gate per configuration, so a burst of robot requests triggers a single token fetch
        /// rather than a stampede against the token endpoint.
        /// </summary>
        private static readonly ConcurrentDictionary<string, SemaphoreSlim> Gates =
            new ConcurrentDictionary<string, SemaphoreSlim>();

        private static readonly ConcurrentDictionary<string, HttpClient> TokenClients =
            new ConcurrentDictionary<string, HttpClient>();

        private readonly LockboxContext _context;

        public TokenProvider(LockboxContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async Task<string> GetAccessTokenAsync(bool forceRefresh = false)
        {
            var configKey = _context.CacheKey();

            if (forceRefresh)
            {
                TokenCache.InvalidateConfig(configKey);
            }
            else if (TokenCache.TryGet(configKey, "access_token", out var cached))
            {
                return cached;
            }

            var gate = Gates.GetOrAdd(configKey, _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync().ConfigureAwait(false);

            try
            {
                // Another caller may have populated it while we waited on the gate.
                if (!forceRefresh && TokenCache.TryGet(configKey, "access_token", out var raced))
                {
                    return raced;
                }

                var (token, lifetimeSeconds) = await RequestTokenAsync().ConfigureAwait(false);

                // Expire the cached copy early so a request never sets off with a token that dies
                // in flight.
                var ttl = lifetimeSeconds - _context.ResolvedTokenRefreshSkewSeconds;
                if (ttl > 0)
                {
                    TokenCache.Set(configKey, "access_token", token, ttl);
                }

                return token;
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>Drops the cached token for this configuration (used after a 401 from Lockbox).</summary>
        public void Invalidate() => TokenCache.InvalidateConfig(_context.CacheKey());

        /// <summary>
        /// Requests a token, and when the host setting <see cref="HostSettingKeys.ExpectedTokenLength"/>
        /// is set, keeps
        /// requesting (each time with a freshly signed assertion) until the token has exactly that
        /// length or the host setting <see cref="HostSettingKeys.TokenLengthRetryAttempts"/> is
        /// exhausted. A token of the wrong length is never cached or returned.
        /// </summary>
        private async Task<(string Token, int LifetimeSeconds)> RequestTokenAsync()
        {
            var expected = HostOptions.Current.ExpectedTokenLength;
            var attempts = HostOptions.Current.TokenLengthRetryAttempts + 1;

            for (var attempt = 1; ; attempt++)
            {
                var result = await RequestTokenOnceAsync().ConfigureAwait(false);

                if (expected <= 0 || result.Token.Length == expected)
                {
                    return result;
                }

                if (attempt >= attempts)
                {
                    throw ExceptionHelper.Unauthorized(
                        $"Unable to get a valid token after {attempts} attempt(s): the last access_token " +
                        $"had length {result.Token.Length}, expected {expected} " +
                        $"({HostSettingKeys.Qualified(HostSettingKeys.ExpectedTokenLength)}).");
                }

                EventLogWriter.Warning(
                    PluginEventIds.CredentialFailed,
                    $"Token attempt {attempt}/{attempts}: access_token length {result.Token.Length}, " +
                    $"expected {expected}. Retrying.");

                // iat has one-second resolution; wait so the next assertion is not byte-identical.
                await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
        }

        private async Task<(string Token, int LifetimeSeconds)> RequestTokenOnceAsync()
        {
            var assertion = BuildClientAssertion();

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _context.ClientId,
                ["client_assertion_type"] = ClientAssertionType,
                ["client_assertion"] = assertion,
            };

            if (!string.IsNullOrWhiteSpace(_context.Resource))
            {
                form["resource"] = _context.Resource;
            }

            if (!string.IsNullOrWhiteSpace(_context.Scope))
            {
                form["scope"] = _context.Scope;
            }

            var client = TokenClients.GetOrAdd(_context.CacheKey(), _ => CreateTokenClient());

            HttpResponseMessage response;
            try
            {
                using (var content = new FormUrlEncodedContent(form))
                {
                    response = await client
                        .PostAsync(_context.ResolvedTokenEndpoint, content)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
            {
                throw ExceptionHelper.Generic(
                    $"Could not reach the token endpoint {_context.ResolvedTokenEndpoint}. " +
                    "Check network egress from the Credentials Proxy host. Details: " + ex.Message,
                    ex);
            }

            using (response)
            {
                var body = response.Content == null
                    ? string.Empty
                    : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    // The OAuth error response is the most useful diagnostic available here: ADFS
                    // reports assertion problems as invalid_client with a description naming the cause.
                    throw ExceptionHelper.Unauthorized(
                        $"Token request failed with {(int)response.StatusCode} " +
                        $"({response.StatusCode}). This is the client assertion being rejected, not " +
                        $"Lockbox. Verify {ConfigKeys.ClientId}, {ConfigKeys.Resource}, " +
                        $"{ConfigKeys.Audience} and the signing certificate. Response: " +
                        Truncate(body));
                }

                JObject parsed;
                try
                {
                    parsed = JObject.Parse(body);
                }
                catch (JsonException ex)
                {
                    throw ExceptionHelper.Generic(
                        "The token endpoint returned a response that is not valid JSON: " + ex.Message);
                }

                var token = parsed.Value<string>("access_token");
                if (string.IsNullOrWhiteSpace(token))
                {
                    throw ExceptionHelper.Unauthorized(
                        "The token endpoint returned no access_token. Response: " + Truncate(body));
                }

                var lifetime = parsed.Value<int?>("expires_in") ?? 3600;
                return (token, lifetime);
            }
        }

        /// <summary>
        /// Builds and signs the client assertion.
        ///
        /// Header:  { "alg": "RS256", "typ": "JWT", &lt;key id claim&gt;: &lt;CertKid&gt; }
        /// Payload: { "iss", "sub", "aud", "jti", "iat", "nbf", "exp" }
        ///
        /// The key-id claim name is configurable because identity providers differ: ADFS commonly
        /// expects <c>x5t</c> (the base64url SHA-1 thumbprint), while others take a literal <c>kid</c>.
        /// See <see cref="ConfigKeys.CertKidHeaderName"/>.
        /// </summary>
        internal string BuildClientAssertion()
        {
            var certificate = ClientCertificateResolver.Resolve(_context);
            var now = DateTimeOffset.UtcNow;

            var header = new Dictionary<string, object>
            {
                ["alg"] = "RS256",
                ["typ"] = "JWT",
            };

            var keyId = _context.ResolvedCertKid(certificate);
            if (!string.IsNullOrWhiteSpace(keyId))
            {
                header[_context.ResolvedCertKidHeaderName] = keyId;
            }

            var payload = new Dictionary<string, object>
            {
                ["iss"] = _context.ClientId,
                ["sub"] = _context.ClientId,
                ["aud"] = _context.ResolvedAudience,
                // A fixed JwtId is honoured if configured, since some providers key replay detection
                // on a registered value; otherwise a fresh GUID per assertion is the correct default.
                ["jti"] = string.IsNullOrWhiteSpace(_context.JwtId)
                    ? Guid.NewGuid().ToString("N")
                    : _context.JwtId,
                ["iat"] = now.ToUnixTimeSeconds(),
                ["nbf"] = now.ToUnixTimeSeconds(),
                ["exp"] = now.AddSeconds(_context.ResolvedAssertionLifetimeSeconds).ToUnixTimeSeconds(),
            };

            var signingInput =
                Base64Url(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header))) + "." +
                Base64Url(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));

            var rsa = certificate.GetRSAPrivateKey();
            if (rsa == null)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The certificate '{certificate.Subject}' has no usable RSA private key, so the " +
                    "client assertion cannot be signed.");
            }

            byte[] signature;
            try
            {
                signature = rsa.SignData(
                    Encoding.UTF8.GetBytes(signingInput),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException ex)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    "Signing the client assertion failed. The account running the Credentials Proxy " +
                    "most likely lacks read access to the certificate's private key. Details: " +
                    ex.Message);
            }

            return signingInput + "." + Base64Url(signature);
        }

        private HttpClient CreateTokenClient()
        {
            var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
            };

            try
            {
                handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            }
            catch (PlatformNotSupportedException)
            {
                // Host runtime manages this itself.
            }

            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(HostOptions.Current.RequestTimeoutSeconds),
            };
        }

        internal static string Base64Url(byte[] input) =>
            Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

        private static string Truncate(string body)
        {
            if (string.IsNullOrWhiteSpace(body))
            {
                return "(empty)";
            }

            body = body.Replace("\r", " ").Replace("\n", " ").Trim();
            return body.Length <= 400 ? body : body.Substring(0, 400) + "...";
        }
    }
}
