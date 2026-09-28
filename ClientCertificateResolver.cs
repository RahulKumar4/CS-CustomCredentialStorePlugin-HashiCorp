using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// Loads the X509 client certificate used for mTLS against the Lockbox endpoint.
    ///
    /// Certificates are cached per configuration fingerprint, because loading a pfx or hitting the
    /// Windows certificate store on every robot request is expensive.
    /// </summary>
    internal static class ClientCertificateResolver
    {
        private static readonly ConcurrentDictionary<string, X509Certificate2> Cache =
            new ConcurrentDictionary<string, X509Certificate2>();

        public static X509Certificate2 Resolve(LockboxContext context)
        {
            return Cache.GetOrAdd(context.CacheKey(), _ => Load(context));
        }

        /// <summary>
        /// Drops the cached certificate so the next call reloads it (use after renewal).
        ///
        /// X509Certificate2 wraps a native handle, so the evicted instance is disposed rather than
        /// left to the finalizer - but only after a grace period, since an in-flight TLS handshake may
        /// still be using it.
        /// </summary>
        public static void Invalidate(LockboxContext context)
        {
            if (Cache.TryRemove(context.CacheKey(), out var retired))
            {
                DeferredDisposal.Schedule(retired);
            }
        }

        private static X509Certificate2 Load(LockboxContext context)
        {
            X509Certificate2 certificate;

            switch (context.ResolvedCertificateSource)
            {
                case CertificateSource.Store:
                    certificate = LoadFromStore(context);
                    break;
                case CertificateSource.File:
                    certificate = LoadFromFile(context);
                    break;
                case CertificateSource.Base64:
                    certificate = LoadFromBase64(context);
                    break;
                default:
                    throw ExceptionHelper.InvalidConfiguration("Unknown certificate source.");
            }

            if (!certificate.HasPrivateKey)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The certificate '{certificate.Subject}' has no accessible private key, so it cannot " +
                    "be used for mutual TLS. If it came from the Windows store, grant the account running " +
                    "the Credentials Proxy read access to the private key " +
                    "(certlm.msc > the certificate > All Tasks > Manage Private Keys).");
            }

            var now = DateTime.Now;
            if (now > certificate.NotAfter)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The client certificate expired on {certificate.NotAfter:u} " +
                    $"(thumbprint {certificate.Thumbprint}).");
            }

            if (now < certificate.NotBefore)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The client certificate is not valid until {certificate.NotBefore:u} " +
                    $"(thumbprint {certificate.Thumbprint}).");
            }

            return certificate;
        }

        /// <summary>
        /// Key storage flags for loading a pfx.
        ///
        /// MachineKeySet is a Windows CryptoAPI concept and is rejected on macOS, so it is applied only
        /// on Windows. This lets the same source build and run a local harness on a developer Mac while
        /// still using the machine key store when deployed to the Windows proxy.
        /// </summary>
        private static X509KeyStorageFlags KeyStorageFlags =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? X509KeyStorageFlags.MachineKeySet
                : X509KeyStorageFlags.DefaultKeySet;

        private static X509Certificate2 LoadFromStore(LockboxContext context)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"'{ConfigKeys.CertificateSource}' = 'Store' reads the Windows certificate store and " +
                    $"is not available on {RuntimeInformation.OSDescription}. For local development use " +
                    $"'File' with a pfx, or 'Base64'. Keep 'Store' in the deployed proxy configuration.");
            }

            var storeName = ParseStoreName(context.CertificateStoreName);
            var storeLocation = ParseStoreLocation(context.CertificateStoreLocation);

            // Thumbprints copied from the Windows UI often carry invisible characters and spaces.
            var thumbprint = Normalize(context.CertificateThumbprint);

            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var candidate in store.Certificates)
                {
                    if (string.Equals(
                            Normalize(candidate.Thumbprint), thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return candidate;
                    }
                }
            }

            throw ExceptionHelper.InvalidConfiguration(
                $"No certificate with thumbprint '{thumbprint}' was found in " +
                $"{storeLocation}\\{storeName}.");
        }

        private static X509Certificate2 LoadFromFile(LockboxContext context)
        {
            var path = context.CertificateFilePath.Trim();

            if (!File.Exists(path))
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The certificate file '{path}' does not exist, or the account running the " +
                    "Credentials Proxy cannot read it.");
            }

            try
            {
                return new X509Certificate2(
                    File.ReadAllBytes(path),
                    context.CertificatePassword,
                    KeyStorageFlags);
            }
            catch (Exception ex)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"The certificate file '{path}' could not be loaded. Check that it is a pfx/p12 and " +
                    $"that '{ConfigKeys.CertificatePassword}' is correct. Details: {ex.Message}");
            }
        }

        private static X509Certificate2 LoadFromBase64(LockboxContext context)
        {
            byte[] raw;
            try
            {
                raw = Convert.FromBase64String(context.CertificateBase64.Trim());
            }
            catch (FormatException)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    $"'{ConfigKeys.CertificateBase64}' is not valid base64. Produce it with: " +
                    "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\path\\client.pfx'))");
            }

            try
            {
                return new X509Certificate2(
                    raw,
                    context.CertificatePassword,
                    KeyStorageFlags);
            }
            catch (Exception ex)
            {
                throw ExceptionHelper.InvalidConfiguration(
                    "The base64 certificate could not be loaded. Check that it is a pfx/p12 and that " +
                    $"'{ConfigKeys.CertificatePassword}' is correct. Details: {ex.Message}");
            }
        }

        private static string Normalize(string thumbprint) =>
            (thumbprint ?? string.Empty)
                .Replace(" ", string.Empty)
                .Replace("\u200e", string.Empty)
                .Replace("\u200f", string.Empty)
                .Trim();

        private static StoreName ParseStoreName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return StoreName.My;
            }

            if (Enum.TryParse(value.Trim(), true, out StoreName parsed))
            {
                return parsed;
            }

            throw ExceptionHelper.InvalidConfiguration(
                $"'{ConfigKeys.CertificateStoreName}' value '{value}' is not a valid store name " +
                "(for example: My, Root, CertificateAuthority).");
        }

        private static StoreLocation ParseStoreLocation(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return StoreLocation.LocalMachine;
            }

            if (Enum.TryParse(value.Trim(), true, out StoreLocation parsed))
            {
                return parsed;
            }

            throw ExceptionHelper.InvalidConfiguration(
                $"'{ConfigKeys.CertificateStoreLocation}' value '{value}' is not valid " +
                "(expected LocalMachine or CurrentUser).");
        }
    }
}
