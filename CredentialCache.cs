using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// A bounded, self-evicting cache for fetched credentials.
    ///
    /// Written to replace a plain ConcurrentDictionary, which had three defects worth naming because
    /// they all bite the same way - secret material living longer than intended:
    ///
    ///   1. Expired entries were only bypassed on read, never removed. A password for an account that
    ///      stopped being requested stayed resident for the lifetime of the proxy process.
    ///   2. Entries are keyed partly by a fingerprint of the store configuration. Rotating the client
    ///      certificate changes that fingerprint, so every prior entry became permanently unreachable
    ///      AND permanently resident.
    ///   3. Nothing bounded growth, so a store fronting many accounts could accumulate without limit.
    ///
    /// Mitigations here: expired entries are deleted on encounter, a periodic sweep clears entries
    /// nothing has touched, <see cref="InvalidateConfig"/> purges a whole configuration when its
    /// certificate is replaced or rejected, and the entry count is capped.
    ///
    /// Caveat worth stating plainly: .NET strings are immutable and garbage collected, so a cached
    /// password cannot be deterministically wiped from memory - eviction only drops the reference and
    /// makes it collectable. That is a reason to leave CacheSeconds at its default of 0.
    /// </summary>
    internal sealed class CredentialCache<T> where T : class
    {
        /// <summary>Hard ceiling on entries. Beyond this, the soonest-to-expire are dropped first.</summary>
        private const int MaxEntries = 500;

        /// <summary>Minimum gap between full sweeps, so hot paths do not pay for one every call.</summary>
        private static readonly TimeSpan SweepInterval = TimeSpan.FromSeconds(30);

        private readonly ConcurrentDictionary<string, Entry> _entries =
            new ConcurrentDictionary<string, Entry>(StringComparer.Ordinal);

        private long _nextSweepTicks = DateTimeOffset.UtcNow.Add(SweepInterval).UtcTicks;

        public int Count => _entries.Count;

        public bool TryGet(string configKey, string itemKey, out T value)
        {
            value = null;
            var composite = Compose(configKey, itemKey);

            if (_entries.TryGetValue(composite, out var entry))
            {
                if (entry.ExpiresAt > DateTimeOffset.UtcNow)
                {
                    value = entry.Value;
                    return true;
                }

                // Expired: delete rather than merely skip, so it cannot linger unreferenced.
                _entries.TryRemove(composite, out _);
            }

            SweepIfDue();
            return false;
        }

        public void Set(string configKey, string itemKey, T value, int ttlSeconds)
        {
            if (value == null || ttlSeconds <= 0)
            {
                // Caching disabled: make sure a previously cached value cannot outlive the setting change.
                _entries.TryRemove(Compose(configKey, itemKey), out _);
                return;
            }

            _entries[Compose(configKey, itemKey)] = new Entry
            {
                ConfigKey = configKey,
                Value = value,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(ttlSeconds),
            };

            Sweep();
            Trim();
        }

        /// <summary>
        /// Drops every entry belonging to one store configuration. Called when that configuration's
        /// client certificate is rotated or rejected, so credentials fetched under the old identity do
        /// not survive as unreachable residue.
        /// </summary>
        public void InvalidateConfig(string configKey)
        {
            foreach (var pair in _entries.ToArray())
            {
                if (string.Equals(pair.Value.ConfigKey, configKey, StringComparison.Ordinal))
                {
                    _entries.TryRemove(pair.Key, out _);
                }
            }
        }

        public void Clear() => _entries.Clear();

        private void SweepIfDue()
        {
            var now = DateTimeOffset.UtcNow.UtcTicks;
            var due = Interlocked.Read(ref _nextSweepTicks);

            if (now < due)
            {
                return;
            }

            // Only one caller wins the right to sweep; the rest carry on unblocked.
            if (Interlocked.CompareExchange(
                    ref _nextSweepTicks,
                    DateTimeOffset.UtcNow.Add(SweepInterval).UtcTicks,
                    due) == due)
            {
                Sweep();
            }
        }

        private void Sweep()
        {
            var now = DateTimeOffset.UtcNow;

            foreach (var pair in _entries.ToArray())
            {
                if (pair.Value.ExpiresAt <= now)
                {
                    _entries.TryRemove(pair.Key, out _);
                }
            }
        }

        private void Trim()
        {
            if (_entries.Count <= MaxEntries)
            {
                return;
            }

            var doomed = _entries.ToArray()
                .OrderBy(p => p.Value.ExpiresAt)
                .Take(_entries.Count - MaxEntries)
                .Select(p => p.Key);

            foreach (var key in doomed)
            {
                _entries.TryRemove(key, out _);
            }
        }

        private static string Compose(string configKey, string itemKey) => configKey + "|" + itemKey;

        private sealed class Entry
        {
            public string ConfigKey { get; set; }

            public T Value { get; set; }

            public DateTimeOffset ExpiresAt { get; set; }
        }
    }

    /// <summary>
    /// Disposes an object after a grace period.
    ///
    /// Pooled HttpClients and X509Certificate2 instances hold native handles and must be disposed, but
    /// disposing one the moment it is evicted would break requests still in flight against it. The
    /// delay lets those drain first.
    /// </summary>
    internal static class DeferredDisposal
    {
        private static readonly TimeSpan Grace = TimeSpan.FromSeconds(30);

        public static void Schedule(IDisposable disposable)
        {
            if (disposable == null)
            {
                return;
            }

            System.Threading.Tasks.Task.Delay(Grace).ContinueWith(_ =>
            {
                try
                {
                    disposable.Dispose();
                }
                catch
                {
                    // Disposal is best effort; a failure here must never surface to a robot.
                }
            });
        }
    }
}
