using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    internal interface ILockboxClient
    {
        /// <summary>Fetches the AD details for a distinguished name.</summary>
        Task<AdDetails> GetAdDetailsAsync(string adDn);

        /// <summary>
        /// Confirms the endpoint is reachable and that the client certificate is accepted.
        /// Called by ValidateContextAsync, which the disconnected proxy runs at startup.
        /// </summary>
        Task VerifyConnectivityAsync();
    }

    internal interface ILockboxClientFactory
    {
        ILockboxClient Create(LockboxContext context);
    }

    /// <summary>The subset of the ad_details payload this plugin consumes.</summary>
    internal sealed class AdDetails
    {
        public string Dn { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public string LastPassword { get; set; }

        public long Ttl { get; set; }

        public DateTimeOffset? LastVaultRotation { get; set; }
    }

    internal sealed class LockboxClientFactory : ILockboxClientFactory
    {
        public ILockboxClient Create(LockboxContext context) => new LockboxClient(context);
    }

    internal sealed class LockboxClient : ILockboxClient
    {
        /// <summary>
        /// One HttpClient per distinct configuration, kept alive for the process lifetime.
        /// Creating an HttpClient per request exhausts sockets and re-does the TLS handshake every time.
        /// </summary>
        private static readonly ConcurrentDictionary<string, HttpClient> Clients =
            new ConcurrentDictionary<string, HttpClient>();

        /// <summary>
        /// Bounded, self-evicting. See CredentialCache for why a plain dictionary was not adequate.
        /// </summary>
        private static readonly CredentialCache<AdDetails> ResponseCache = new CredentialCache<AdDetails>();

        private readonly LockboxContext _context;
        private readonly TokenProvider _tokens;

        public LockboxClient(LockboxContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _tokens = new TokenProvider(_context);
        }

        public async Task<AdDetails> GetAdDetailsAsync(string adDn)
        {
            if (string.IsNullOrWhiteSpace(adDn))
            {
                throw ExceptionHelper.SecretNotFound("The resolved AD distinguished name is empty.");
            }

            var cacheSeconds = HostOptions.Current.CacheSeconds;
            var configKey = _context.CacheKey();
            var itemKey = adDn.ToLowerInvariant();

            if (cacheSeconds > 0 && ResponseCache.TryGet(configKey, itemKey, out var cached))
            {
                return cached;
            }

            var details = await FetchAsync(adDn).ConfigureAwait(false);

            // Set is a no-op when caching is off, and also clears any entry left over from a period
            // when it was on, so lowering CacheSeconds takes effect without a restart.
            ResponseCache.Set(configKey, itemKey, details, cacheSeconds);

            return details;
        }

        public async Task VerifyConnectivityAsync()
        {
            // Loading the certificate up front turns "wrong thumbprint" and "no private key access" into
            // a clear configuration error at startup rather than a robot failure at 2am.
            // Loading the certificate proves the thumbprint resolves and the private key is readable -
            // both local checks, and both needed to sign the client assertion.
            ClientCertificateResolver.Resolve(_context);

            if (!string.IsNullOrWhiteSpace(_context.ValidationAdDn))
            {
                // Full end-to-end check: the operator opted in by naming a probe account.
                await FetchAsync(_context.ValidationAdDn.Trim()).ConfigureAwait(false);
                return;
            }

            if (!_context.ValidateEndpointAtStartup)
            {
                // Default path: certificate validated above, no network call.
                //
                // The disconnected proxy treats a validation exception as FATAL and terminates the
                // process, so one store's entitlement gap or a transient network fault would stop the
                // proxy serving every other store. Endpoint problems therefore surface on the first
                // credential request - where they affect one job - rather than at startup, where they
                // affect everything. This matches the official Hashicorp read-only store, which
                // validates its context and makes no health call.
                return;
            }

            // No probe DN configured. Send a deliberately incomplete request. The only thing worth
            // failing startup over here is a rejected client certificate, because that is a
            // configuration fault that will not fix itself.
            //
            // A 5xx is NOT treated as fatal. The body we sent is knowingly invalid, so a 5xx may say
            // more about that than about the service; and even a genuine outage is transient, whereas
            // the disconnected proxy refuses to start when validation throws. Blocking startup on it
            // would turn a passing outage into a manual restart. Set ValidationAdDn if you do want a
            // strict end-to-end check at startup.
            using (var response = await SendAsync("{}").ConfigureAwait(false))
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized ||
                    response.StatusCode == HttpStatusCode.Forbidden ||
                    response.StatusCode == HttpStatusCode.ProxyAuthenticationRequired)
                {
                    throw ExceptionHelper.Unauthorized(
                        $"Lockbox rejected the client certificate ({(int)response.StatusCode} " +
                        $"{response.StatusCode}). Confirm the certificate is registered with the Lockbox " +
                        "service and is presented from the correct source.");
                }
            }
        }

        private async Task<AdDetails> FetchAsync(string adDn)
        {
            var payload = JsonConvert.SerializeObject(new { ad_dn = adDn });

            using (var response = await SendAsync(payload).ConfigureAwait(false))
            {
                var body = response.Content == null
                    ? string.Empty
                    : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        break;

                    case HttpStatusCode.NotFound:
                        throw ExceptionHelper.SecretNotFound(
                            $"Lockbox has no AD details for '{adDn}'. Check the asset's external name and " +
                            $"the '{ConfigKeys.AdDnTemplate}' setting.");

                    case HttpStatusCode.Unauthorized:
                    case HttpStatusCode.Forbidden:
                        // Surface WWW-Authenticate and the body: with mTLS working, a 401 almost always
                        // means an authorization/entitlement decision, and the scheme named in that
                        // header tells you whether the service wanted something beyond the certificate.
                        // A renewed or replaced certificate is a common cause. Drop the cached
                        // certificate, the pooled client bound to it, and every credential fetched
                        // under that identity - otherwise they linger unreachable for the process
                        // lifetime once the configuration fingerprint changes.
                        InvalidateConfiguration(_context);
                        throw ExceptionHelper.Unauthorized(
                            $"Lockbox denied the request for '{adDn}' ({(int)response.StatusCode}). " +
                            "Either the client certificate is not authorized, or it is not entitled to " +
                            $"this account.{DescribeChallenge(response)} Response: {Trim(body)}");

                    case HttpStatusCode.BadRequest:
                        throw ExceptionHelper.SecretNotFound(
                            $"Lockbox rejected the ad_dn '{adDn}' as malformed. Response: {Trim(body)}");

                    default:
                        if ((int)response.StatusCode >= 500)
                        {
                            throw ExceptionHelper.Generic(
                                $"Lockbox returned {(int)response.StatusCode} ({response.StatusCode}) " +
                                $"for '{adDn}' after {HostOptions.Current.RetryCount + 1} attempt(s). " +
                                "A 503 from a Kubernetes/OpenShift route commonly means no healthy " +
                                "backend behind it, or that the route rejected the request before it " +
                                "reached the service - it does not necessarily indicate a problem with " +
                                $"this plugin's configuration. Response: {Trim(body)}");
                        }

                        throw ExceptionHelper.Generic(
                            $"Lockbox returned {(int)response.StatusCode} ({response.StatusCode}) for " +
                            $"'{adDn}'. Response: {Trim(body)}");
                }

                return Parse(body, adDn);
            }
        }

        /// <summary>
        /// Parses the documented response shape:
        /// { "ad_details": { "dn", "username", "password", "last_password", "ttl",
        ///                   "last_vault_rotation", ... }, "ad_dn": "..." }
        /// </summary>
        private AdDetails Parse(string body, string adDn)
        {
            JObject root;
            try
            {
                root = JObject.Parse(body);
            }
            catch (JsonException ex)
            {
                throw ExceptionHelper.Generic(
                    $"Lockbox returned a response for '{adDn}' that is not valid JSON: {ex.Message}");
            }

            var node = root["ad_details"] as JObject;
            if (node == null)
            {
                throw ExceptionHelper.SecretNotFound(
                    $"The Lockbox response for '{adDn}' contained no 'ad_details' object.");
            }

            var details = new AdDetails
            {
                Dn = node.Value<string>("dn"),
                Username = node.Value<string>("username"),
                Password = node.Value<string>("password"),
                LastPassword = node.Value<string>("last_password"),
                Ttl = node.Value<long?>("ttl") ?? 0,
            };

            var rotation = node.Value<string>("last_vault_rotation");
            if (!string.IsNullOrWhiteSpace(rotation) &&
                DateTimeOffset.TryParse(rotation, out var parsedRotation))
            {
                details.LastVaultRotation = parsedRotation;
            }

            return details;
        }

        private async Task<HttpResponseMessage> SendAsync(string payload)
        {
            var client = Clients.GetOrAdd(_context.CacheKey(), _ => CreateHttpClient(_context));
            var attempts = HostOptions.Current.RetryCount + 1;
            var refreshedToken = false;

            for (var attempt = 1; ; attempt++)
            {
                HttpResponseMessage response = null;
                Exception transport = null;

                try
                {
                    var accessToken = await _tokens.GetAccessTokenAsync().ConfigureAwait(false);

                    using (var request = new HttpRequestMessage(HttpMethod.Post, _context.ResolvedEndpoint))
                    {
                        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        request.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", accessToken);

                        response = await client.SendAsync(request).ConfigureAwait(false);
                    }
                }
                catch (TaskCanceledException ex)
                {
                    transport = ex;
                }
                catch (HttpRequestException ex)
                {
                    transport = ex;
                }

                // A 401 after a previously valid token usually means it expired early or was revoked.
                // Try exactly once with a freshly minted token before giving up, so a clock skew or a
                // provider-side rotation does not fail a robot needlessly.
                if (transport == null &&
                    response.StatusCode == HttpStatusCode.Unauthorized &&
                    !refreshedToken)
                {
                    refreshedToken = true;
                    response.Dispose();
                    await _tokens.GetAccessTokenAsync(forceRefresh: true).ConfigureAwait(false);
                    continue;
                }

                var retryable = transport != null ||
                                (int)response.StatusCode == 429 ||
                                (int)response.StatusCode >= 500;

                if (!retryable || attempt >= attempts)
                {
                    if (transport != null)
                    {
                        throw ExceptionHelper.Generic(
                            $"Could not reach the Lockbox endpoint {_context.ResolvedEndpoint}. " +
                            "Check network egress and firewall rules from the Credentials Proxy host, and " +
                            "that the server certificate chain is trusted. Details: " +
                            Innermost(transport).Message,
                            transport);
                    }

                    return response;
                }

                response?.Dispose();

                // Linear backoff: 500ms, 1s, 1.5s ...
                await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt)).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Evicts everything bound to one store configuration: pooled HttpClient, client certificate
        /// and cached credentials. The client and certificate hold native handles, so they are
        /// disposed after a grace period rather than immediately, to avoid tearing down connections
        /// that in-flight requests are still using.
        /// </summary>
        internal static void InvalidateConfiguration(LockboxContext context)
        {
            var configKey = context.CacheKey();

            if (Clients.TryRemove(configKey, out var retired))
            {
                DeferredDisposal.Schedule(retired);
            }

            ClientCertificateResolver.Invalidate(context);
            ResponseCache.InvalidateConfig(configKey);
            new TokenProvider(context).Invalidate();
        }

        private static HttpClient CreateHttpClient(LockboxContext context)
        {
            var handler = new HttpClientHandler
            {
                ClientCertificateOptions = ClientCertificateOption.Manual,
                AllowAutoRedirect = false,
                UseCookies = false,
            };

            if (context.SendClientCertificateToEndpoint)
            {
                // Off by default. The gateway in front of Lockbox authenticates the bearer token; the
                // certificate's job is to sign the client assertion, not to secure the transport.
                handler.ClientCertificates.Add(ClientCertificateResolver.Resolve(context));
            }

            try
            {
                handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            }
            catch (PlatformNotSupportedException)
            {
                // Older host runtimes: fall back to the process-wide setting below.
            }

            try
            {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            }
            catch
            {
                // Not fatal - some runtimes manage this themselves.
            }

            if (HostOptions.Current.AllowInsecureTls)
            {
                // Lab escape hatch only. Never enable this in production - it removes the guarantee that
                // you are actually talking to Lockbox.
                handler.ServerCertificateCustomValidationCallback = (_, __, ___, ____) => true;
            }

            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(HostOptions.Current.RequestTimeoutSeconds),
            };
        }

        /// <summary>
        /// Extracts the WWW-Authenticate challenge, if any. An empty result on a 401 is itself a clue:
        /// it suggests an authorization decision rather than a request for different credentials.
        /// </summary>
        private static string DescribeChallenge(HttpResponseMessage response)
        {
            var schemes = response.Headers.WwwAuthenticate
                .Select(h => h.Scheme + (string.IsNullOrWhiteSpace(h.Parameter) ? "" : " " + h.Parameter))
                .ToArray();

            return schemes.Length == 0
                ? " No WWW-Authenticate header was returned."
                : " WWW-Authenticate: " + string.Join("; ", schemes) + ".";
        }

        private static Exception Innermost(Exception ex)
        {
            while (ex.InnerException != null)
            {
                ex = ex.InnerException;
            }

            return ex;
        }

        /// <summary>
        /// Truncates a response body before it reaches a log or an exception message. Lockbox error
        /// bodies are short, but this stops an unexpected payload from spilling into logs wholesale.
        /// </summary>
        private static string Trim(string body)
        {
            if (string.IsNullOrWhiteSpace(body))
            {
                return "(empty)";
            }

            body = body.Replace("\r", " ").Replace("\n", " ").Trim();
            return body.Length <= 300 ? body : body.Substring(0, 300) + "...";
        }
    }
}
