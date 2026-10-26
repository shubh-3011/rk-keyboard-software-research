using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RkRebuild;

internal static class BoundedWorkerTests
{
    private static int assertions;
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);

    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new Exception(message);
    }

    private static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T ex) { assertions++; return ex; }
        throw new Exception("Expected " + typeof(T).Name);
    }

    private static List<string> ChildArguments(params string[] arguments)
    {
        var result = new List<string>();
        if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase))
            result.Add(Assembly.GetExecutingAssembly().Location);
        result.Add("--worker-test-child");
        result.AddRange(arguments);
        return result;
    }

    private static Task<WorkerProcessResult> Run(string mode, params string[] arguments)
    {
        var all = new List<string> { mode };
        all.AddRange(arguments);
        return BoundedWorkerProcess.RunAsync(Environment.ProcessPath, ChildArguments(all.ToArray()), Bound);
    }

    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--worker-test-child") return await Child(args);

        var output = await Run("output");
        Check(output.ExitCode == 0 && output.StandardOutput == "worker output" && output.StandardError == "worker error",
            "exact child payload only, without runner PID/path/diagnostics");
        string argument = "spaces 日本語 café 🦊 \\\"quoted\\\" trailing\\";
        output = await Run("echo", argument, "", "second argument");
        Check(output.StandardOutput == argument + "\n\nsecond argument" && output.StandardError == "", "ArgumentList round trip");
        output = await Run("nonzero");
        Check(output.ExitCode == 23 && output.StandardError == "protocol error", "nonzero exit is a result");
        output = await Run("pipes");
        Check(output.StandardOutput == new string('o', 8192) && output.StandardError == new string('e', 8192),
            "concurrent pipes larger than pipe buffers and exactly at limit");

        await Throws<ArgumentNullException>(() => BoundedWorkerProcess.RunAsync(null, Array.Empty<string>(), Bound));
        await Throws<ArgumentException>(() => BoundedWorkerProcess.RunAsync(" ", Array.Empty<string>(), Bound));
        await Throws<ArgumentNullException>(() => BoundedWorkerProcess.RunAsync(Environment.ProcessPath, null, Bound));
        await Throws<ArgumentException>(() => BoundedWorkerProcess.RunAsync(Environment.ProcessPath, new string[] { null }, Bound));
        foreach (TimeSpan timeout in new[] { TimeSpan.Zero, TimeSpan.FromTicks(-1), TimeSpan.FromSeconds(30) + TimeSpan.FromTicks(1), TimeSpan.MaxValue })
            await Throws<ArgumentOutOfRangeException>(() => BoundedWorkerProcess.RunAsync(Environment.ProcessPath, Array.Empty<string>(), timeout));

        string marker = Path.Combine(Path.GetTempPath(), "bounded-worker-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                var ex = await Throws<OperationCanceledException>(() => BoundedWorkerProcess.RunAsync(
                    Environment.ProcessPath, ChildArguments("hang", marker), Bound, cancelled.Token));
                Check(ex.CancellationToken == cancelled.Token && !File.Exists(marker), "pre-cancellation prevents launch");
            }

            await CheckTerminated("hang", marker, false);
            await CheckTerminated("hang", marker, true);
            await CheckTerminated("flood-out", marker, false);
            await CheckTerminated("flood-err", marker, false);
            await CheckTerminated("flood-both", marker, false);
        }
        finally { if (File.Exists(marker)) File.Delete(marker); }

        // The inclusive maximum timeout is valid; a quick worker need not consume it.
        output = await BoundedWorkerProcess.RunAsync(Environment.ProcessPath, ChildArguments("output"), TimeSpan.FromSeconds(30));
        Check(output.ExitCode == 0, "30-second upper bound accepted");
        Console.WriteLine("Bounded worker tests passed: " + assertions + " assertions.");
        return 0;
    }

    private static async Task CheckTerminated(string mode, string marker, bool cancel)
    {
        if (File.Exists(marker)) File.Delete(marker);
        using var cancellation = new CancellationTokenSource();
        var watch = Stopwatch.StartNew();
        Task<WorkerProcessResult> running = BoundedWorkerProcess.RunAsync(Environment.ProcessPath,
            ChildArguments(mode, marker), mode == "hang" && !cancel ? TimeSpan.FromSeconds(2) : Bound, cancellation.Token);
        if (cancel)
        {
            while (!File.Exists(marker) && watch.Elapsed < TimeSpan.FromSeconds(5)) await Task.Delay(10);
            Check(File.Exists(marker), "child started before cancellation");
            cancellation.Cancel();
            var ex = await Throws<OperationCanceledException>(() => running);
            Check(ex.CancellationToken == cancellation.Token, "caller cancellation token preserved");
        }
        else if (mode == "hang") await Throws<TimeoutException>(() => running);
        else await Throws<InvalidDataException>(() => running);

        Check(watch.Elapsed < TimeSpan.FromSeconds(6), "failure plus cleanup is bounded, not full worker timeout");
        if (mode == "hang" && !cancel)
            Check(watch.Elapsed >= TimeSpan.FromMilliseconds(1800), "positive timeout is not an immediate failure");
        Check(File.Exists(marker), "helper reached its intentional PID fixture");
        int pid = int.Parse(File.ReadAllText(marker));
        bool exited;
        try { using var child = Process.GetProcessById(pid); exited = child.HasExited; }
        catch (ArgumentException) { exited = true; }
        Check(exited, "owned child has exited before failure returns");
    }

    private static async Task<int> Child(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        switch (args[1])
        {
            case "output":
                Console.Write("worker output");
                Console.Error.Write("worker error");
                return 0;
            case "echo":
                Console.Write(string.Join("\n", args, 2, args.Length - 2));
                return 0;
            case "nonzero":
                Console.Error.Write("protocol error");
                return 23;
            case "pipes":
                await Task.WhenAll(Task.Run(() => Console.Out.Write(new string('o', 8192))),
                    Task.Run(() => Console.Error.Write(new string('e', 8192))));
                return 0;
            case "hang":
            case "flood-out":
            case "flood-err":
            case "flood-both":
                // This PID is intentional test-fixture data, never runner metadata.
                File.WriteAllText(args[2], Environment.ProcessId.ToString());
                if (args[1] == "flood-both")
                {
                    await Task.WhenAll(Task.Run(() => Flood(Console.Out)), Task.Run(() => Flood(Console.Error)));
                    return 0;
                }
                if (args[1] != "hang")
                {
                    TextWriter writer = args[1] == "flood-out" ? Console.Out : Console.Error;
                    await Flood(writer);
                }
                await Task.Delay(Timeout.Infinite);
                return 0;
            default: return 99;
        }
    }

    private static async Task Flood(TextWriter writer)
    {
        string block = new string('x', 1024);
        while (true) { await writer.WriteAsync(block); await writer.FlushAsync(); }
    }
}
