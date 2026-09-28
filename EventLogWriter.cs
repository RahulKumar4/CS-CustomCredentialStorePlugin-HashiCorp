using System;
using System.Reflection;
using System.Text;

namespace UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox
{
    /// <summary>
    /// How much detail reaches the Windows event log.
    /// Each level includes the ones above it.
    /// </summary>
    internal enum EventLogLevel
    {
        /// <summary>Nothing is written.</summary>
        Off = 0,

        /// <summary>Failures only.</summary>
        Error = 1,

        /// <summary>Failures plus recoverable problems (denied requests, fallbacks).</summary>
        Warning = 2,

        /// <summary>Adds one record per served credential and the startup summary.</summary>
        Information = 3,

        /// <summary>Adds per-request tracing and exception stack traces. Chatty - use while diagnosing.</summary>
        Verbose = 4,
    }

    /// <summary>
    /// Event ids, so operators can filter the Application log by id rather than by message text.
    /// Keep them stable: alerting rules get written against these numbers.
    /// </summary>
    internal static class PluginEventIds
    {
        public const int Initialized = 1000;
        public const int HostSettingIgnored = 1001;
        public const int ConfigurationRejected = 1002;

        public const int ValidationSucceeded = 1100;
        public const int ValidationFailed = 1101;

        public const int CredentialRequested = 1200;
        public const int CredentialServed = 1201;
        public const int CredentialDenied = 1202;
        public const int CredentialFailed = 1203;

        public const int WriteRefused = 1300;
    }

    /// <summary>
    /// Writes plugin events to the Windows event log (Event Viewer), off unless
    /// <c>Plugins.SecureStores.HashiCorpVaultLockbox.EventLogEnabled</c> is true.
    ///
    /// WHY REFLECTION. The plugin targets netstandard2.0 and is deployed as a single DLL dropped into
    /// the proxy's plugins\ folder. <c>System.Diagnostics.EventLog</c> lives in System.dll on .NET
    /// Framework and in a separate Windows-only package on .NET (Core), so a compile-time reference
    /// would either break the netstandard target or add assemblies to a deployment whose whole
    /// premise is "copy one file". Late binding keeps the drop single-file and simply degrades to a
    /// no-op if the type is not present in the host process.
    ///
    /// This is a diagnostic side channel: it never throws, never blocks a credential request, and
    /// never writes secret material. Passwords are not passed to it, by construction - callers hand
    /// it distinguished names, usernames and status text only.
    /// </summary>
    internal static class EventLogWriter
    {
        /// <summary>
        /// Registering a new event source writes under HKLM and needs administrative rights, which an
        /// IIS app-pool identity normally does not have. "Application" always exists and is writable,
        /// so events still reach Event Viewer; the header line carries the plugin name so they remain
        /// searchable.
        /// </summary>
        private const string FallbackSource = "Application";

        /// <summary>The event log caps an entry at 32766 characters and throws above it.</summary>
        private const int MaxMessageLength = 31000;

        /// <summary>Stop trying after this many consecutive write failures (e.g. log full, ACL).</summary>
        private const int MaxConsecutiveFailures = 3;

        private static readonly object Gate = new object();

        private static volatile EventLogLevel _level = EventLogLevel.Off;
        private static string _configuredSource = "UiPath HashiCorpVaultLockbox";
        private static string _logName = "Application";

        private static bool _bindAttempted;
        private static MethodInfo _writeEntry;
        private static string _effectiveSource;
        private static object _entryTypeError;
        private static object _entryTypeWarning;
        private static object _entryTypeInformation;
        private static int _consecutiveFailures;

        /// <summary>
        /// Applies host settings. Called from <see cref="HostOptions.Load"/> before the strict
        /// settings are parsed, so that a configuration error can itself be logged.
        /// </summary>
        public static void Configure(HostOptions options)
        {
            lock (Gate)
            {
                _configuredSource = string.IsNullOrWhiteSpace(options.EventLogSource)
                    ? "UiPath HashiCorpVaultLockbox"
                    : options.EventLogSource.Trim();
                _logName = string.IsNullOrWhiteSpace(options.EventLogName)
                    ? "Application"
                    : options.EventLogName.Trim();

                // Re-bind on every Initialize: the source or log name may have changed.
                _bindAttempted = false;
                _writeEntry = null;
                _effectiveSource = null;
                _consecutiveFailures = 0;

                _level = options.EventLogEnabled ? options.EventLogLevel : EventLogLevel.Off;
            }
        }

        public static void Error(int eventId, string message, Exception exception = null) =>
            Write(EventLogLevel.Error, eventId, Append(message, exception));

        public static void Warning(int eventId, string message, Exception exception = null) =>
            Write(EventLogLevel.Warning, eventId, Append(message, exception));

        public static void Information(int eventId, string message) =>
            Write(EventLogLevel.Information, eventId, message);

        public static void Verbose(int eventId, string message) =>
            Write(EventLogLevel.Verbose, eventId, message);

        private static void Write(EventLogLevel level, int eventId, string message)
        {
            if (level > _level || _consecutiveFailures >= MaxConsecutiveFailures)
            {
                return;
            }

            try
            {
                if (!EnsureBound())
                {
                    return;
                }

                object entryType;
                switch (level)
                {
                    case EventLogLevel.Error:
                        entryType = _entryTypeError;
                        break;
                    case EventLogLevel.Warning:
                        entryType = _entryTypeWarning;
                        break;
                    default:
                        entryType = _entryTypeInformation;
                        break;
                }

                _writeEntry.Invoke(
                    null,
                    new[] { _effectiveSource, Compose(level, message), entryType, (object)eventId });

                _consecutiveFailures = 0;
            }
            catch
            {
                // A diagnostic sink must never be the reason a robot fails to get its credential.
                _consecutiveFailures++;
            }
        }

        private static string Compose(EventLogLevel level, string message)
        {
            var text = new StringBuilder()
                .Append("UiPath secure store plugin: ")
                .Append(HashiCorpVaultLockboxSecureStore.NameIdentifier)
                .Append(" [").Append(level).Append(']')
                .AppendLine()
                .AppendLine()
                .Append(message ?? string.Empty)
                .ToString();

            return text.Length <= MaxMessageLength
                ? text
                : text.Substring(0, MaxMessageLength) + Environment.NewLine + "... (truncated)";
        }

        private static string Append(string message, Exception exception)
        {
            if (exception == null)
            {
                return message;
            }

            var text = new StringBuilder(message ?? string.Empty)
                .AppendLine()
                .AppendLine()
                .Append(exception.GetType().Name).Append(": ").Append(exception.Message);

            var inner = exception.InnerException;
            while (inner != null)
            {
                text.AppendLine().Append("  --> ")
                    .Append(inner.GetType().Name).Append(": ").Append(inner.Message);
                inner = inner.InnerException;
            }

            // Stack traces are noise in a credential-store log until you are actually debugging.
            if (_level >= EventLogLevel.Verbose && exception.StackTrace != null)
            {
                text.AppendLine().AppendLine().Append(exception.StackTrace);
            }

            return text.ToString();
        }

        private static bool EnsureBound()
        {
            if (_writeEntry != null)
            {
                return true;
            }

            lock (Gate)
            {
                if (_writeEntry != null)
                {
                    return true;
                }

                if (_bindAttempted)
                {
                    return false;
                }

                _bindAttempted = true;

                var eventLogType = ResolveEventLogType();
                if (eventLogType == null)
                {
                    return false;
                }

                var entryTypeEnum = eventLogType.Assembly.GetType("System.Diagnostics.EventLogEntryType")
                    ?? Type.GetType("System.Diagnostics.EventLogEntryType");
                if (entryTypeEnum == null || !entryTypeEnum.IsEnum)
                {
                    return false;
                }

                var writeEntry = eventLogType.GetMethod(
                    "WriteEntry",
                    BindingFlags.Public | BindingFlags.Static,
                    binder: null,
                    types: new[] { typeof(string), typeof(string), entryTypeEnum, typeof(int) },
                    modifiers: null);
                if (writeEntry == null)
                {
                    return false;
                }

                _entryTypeError = Enum.Parse(entryTypeEnum, "Error");
                _entryTypeWarning = Enum.Parse(entryTypeEnum, "Warning");
                _entryTypeInformation = Enum.Parse(entryTypeEnum, "Information");
                _effectiveSource = ResolveSource(eventLogType, _configuredSource, _logName);
                _writeEntry = writeEntry;

                return true;
            }
        }

        /// <summary>
        /// Returns the configured source if it exists or can be registered, otherwise the fallback.
        /// Both branches are normal: registration succeeds when the proxy first runs elevated (or the
        /// operator pre-created the source), and fails silently into "Application" when it does not.
        /// </summary>
        private static string ResolveSource(Type eventLogType, string source, string logName)
        {
            try
            {
                var sourceExists = eventLogType.GetMethod(
                    "SourceExists", BindingFlags.Public | BindingFlags.Static, null,
                    new[] { typeof(string) }, null);

                if (sourceExists != null && (bool)sourceExists.Invoke(null, new object[] { source }))
                {
                    return source;
                }

                var createSource = eventLogType.GetMethod(
                    "CreateEventSource", BindingFlags.Public | BindingFlags.Static, null,
                    new[] { typeof(string), typeof(string) }, null);

                if (createSource != null)
                {
                    createSource.Invoke(null, new object[] { source, logName });
                    return source;
                }
            }
            catch
            {
                // Not administrative, or the source belongs to another log. Fall through.
            }

            return FallbackSource;
        }

        /// <summary>
        /// Finds System.Diagnostics.EventLog wherever the host happens to keep it: System.dll on
        /// .NET Framework, the System.Diagnostics.EventLog assembly on .NET (Core) for Windows.
        /// </summary>
        private static Type ResolveEventLogType()
        {
            const string typeName = "System.Diagnostics.EventLog";

            try
            {
                var fromFramework = Type.GetType(
                    typeName + ", System, Version=4.0.0.0, Culture=neutral, " +
                    "PublicKeyToken=b77a5c561934e089",
                    throwOnError: false);
                if (fromFramework != null)
                {
                    return fromFramework;
                }
            }
            catch
            {
                // Ignored - try the remaining probes.
            }

            foreach (var assemblyName in new[] { "System.Diagnostics.EventLog", "System" })
            {
                try
                {
                    var assembly = Assembly.Load(new AssemblyName(assemblyName));
                    var type = assembly?.GetType(typeName, throwOnError: false);
                    if (type != null)
                    {
                        return type;
                    }
                }
                catch
                {
                    // Not present under that name in this host - keep probing.
                }
            }

            try
            {
                foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
                {
                    var type = assembly.GetType(typeName, throwOnError: false);
                    if (type != null)
                    {
                        return type;
                    }
                }
            }
            catch
            {
                // Ignored - the sink stays disabled.
            }

            return null;
        }
    }
}
