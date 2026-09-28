using System;
using System.Security.Cryptography;
using System.Text;
using UiPath.Orchestrator.Extensibility.SecureStores;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// Every SecureStoreException raised by this plugin is built here.
    ///
    /// The members of <c>SecureStoreException.Type</c> come from the UiPath.Orchestrator.Extensibility
    /// package. If you reference a version whose enum differs, this file is the only place to adjust.
    /// </summary>
    internal static class ExceptionHelper
    {
        public static SecureStoreException SecretNotFound(string message) =>
            new SecureStoreException(SecureStoreException.Type.SecretNotFound, message);

        public static SecureStoreException InvalidConfiguration(string message) =>
            new SecureStoreException(SecureStoreException.Type.InvalidConfiguration, message);

        public static SecureStoreException Unauthorized(string message) =>
            new SecureStoreException(SecureStoreException.Type.UnauthorizedOperation, message);

        public static SecureStoreException NotSupported(string operation) =>
            new SecureStoreException(
                $"'{operation}' is not supported. The Lockbox AD credential store is read-only: " +
                "service-account passwords are owned and rotated by HashiCorp Vault, " +
                "so they cannot be created, changed or deleted from Orchestrator.");

        public static SecureStoreException Generic(string message, Exception inner = null) =>
            inner == null
                ? new SecureStoreException(message)
                : new SecureStoreException(message, inner);
    }

    internal static class Hashing
    {
        public static string Sha256(string input)
        {
            using (var sha = SHA256.Create())
            {
                var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input ?? string.Empty));
                var sb = new StringBuilder(bytes.Length * 2);
                foreach (var b in bytes)
                {
                    sb.Append(b.ToString("x2"));
                }

                return sb.ToString();
            }
        }
    }
}
