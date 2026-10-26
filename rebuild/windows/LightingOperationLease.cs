using System;
using System.Threading;

namespace RkRebuild
{
    // One operation per Windows login session, including separate CLI processes.
    // A semaphore is released from any async continuation (unlike a named mutex).
    internal sealed class LightingOperationLease : IDisposable
    {
        private Semaphore _semaphore;
        private LightingOperationLease(Semaphore semaphore) { _semaphore = semaphore; }

        public static LightingOperationLease Acquire()
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("HID operations require Windows.");
            var semaphore = new Semaphore(1, 1, @"Local\RKRebuild.ExperimentalLighting.Operation.v1");
            try
            {
                if (!semaphore.WaitOne(0)) throw new InvalidOperationException("Another RK Rebuild lighting operation is already running. Wait for it to finish before querying or applying settings.");
                return new LightingOperationLease(semaphore);
            }
            catch { semaphore.Dispose(); throw; }
        }

        public void Dispose()
        {
            Semaphore semaphore = Interlocked.Exchange(ref _semaphore, null);
            if (semaphore == null) return;
            try { semaphore.Release(); } finally { semaphore.Dispose(); }
        }
    }
}
