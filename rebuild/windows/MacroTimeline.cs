using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RkRebuild
{
    // Community draft schema only. No numeric RK event IDs or device serialization.
    internal sealed class MacroStep
    {
        [JsonRequired] public string Kind { get; set; } = "key";
        [JsonRequired] public string Action { get; set; } = "A down";
        [JsonRequired] public int DelayMs { get; set; }
        public override string ToString()
        {
            return Kind == "delay" ? "Delay · " + DelayMs + " ms" : Kind + " · " + Action + " · wait after: " + DelayMs + " ms";
        }
    }

    internal sealed class MacroTimeline
    {
        [JsonRequired] public int SchemaVersion { get; set; } = 1;
        [JsonRequired] public string Name { get; set; } = "Untitled timeline";
        [JsonRequired] public string LoopMode { get; set; } = "none";
        [JsonRequired] public int LoopCount { get; set; } = 1;
        [JsonRequired] public List<MacroStep> Steps { get; set; } = new List<MacroStep>();
        public override string ToString() { return Name + " · " + (Steps == null ? 0 : Steps.Count) + " rows"; }
    }

    internal sealed class MacroTimelinePackage
    {
        public string Format { get; set; } = "rk-rebuild-local-timeline";
        public int SchemaVersion { get; set; } = 1;
        public MacroTimeline Timeline { get; set; }
    }

    internal static class MacroTimelineCodec
    {
        public const int MaxRows = 200;
        public const int MaxTimelines = 100;
        public const int MaxBytes = 1024 * 1024;
        private static readonly JsonSerializerOptions Options = new JsonSerializerOptions {
            WriteIndented = true, MaxDepth = 16, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };

        public static void Validate(MacroTimeline value)
        {
            if (value == null || value.SchemaVersion != 1) throw new InvalidDataException("Expected local timeline schema 1.");
            if (String.IsNullOrWhiteSpace(value.Name) || value.Name.Length > 48) throw new InvalidDataException("Name must contain 1–48 characters.");
            if (!new[] { "none", "count", "while-held", "until-press" }.Contains(value.LoopMode)) throw new InvalidDataException("Unknown local cycle mode.");
            if (value.LoopCount < 1 || value.LoopCount > 99) throw new InvalidDataException("Local cycle count must be 1–99.");
            if (value.Steps == null || value.Steps.Count > MaxRows) throw new InvalidDataException("A timeline must have 0–200 rows.");
            foreach (MacroStep step in value.Steps)
            {
                if (step == null || !new[] { "key", "mouse", "delay" }.Contains(step.Kind)) throw new InvalidDataException("Each row must be key, mouse, or delay.");
                if (step.Action == null || step.Action.Length > 100 || (step.Kind != "delay" && String.IsNullOrWhiteSpace(step.Action))) throw new InvalidDataException("Key/mouse labels must contain 1–100 characters.");
                if (step.Kind == "delay" && step.Action != "") throw new InvalidDataException("Delay rows must have an empty action label.");
                if (step.DelayMs < 0 || step.DelayMs > 60000) throw new InvalidDataException("Delay must be an integer from 0 to 60000 milliseconds.");
            }
        }

        public static string Export(MacroTimeline timeline)
        {
            Validate(timeline);
            return JsonSerializer.Serialize(new MacroTimelinePackage { Timeline = timeline }, Options);
        }

        public static MacroTimeline Import(string json)
        {
            if (json == null || Encoding.UTF8.GetByteCount(json) > MaxBytes) throw new InvalidDataException("JSON must be at most 1 MiB.");
            // Require envelope properties rather than silently accepting constructor defaults.
            using (JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 }))
            {
                JsonElement root = document.RootElement;
                RejectDuplicateProperties(root);
                if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("Format", out JsonElement format) || format.GetString() != "rk-rebuild-local-timeline" ||
                    !root.TryGetProperty("SchemaVersion", out JsonElement version) || version.GetInt32() != 1 || !root.TryGetProperty("Timeline", out _))
                    throw new InvalidDataException("Not an RK Rebuild local timeline package (schema 1).");
            }
            MacroTimelinePackage package = JsonSerializer.Deserialize<MacroTimelinePackage>(json, Options);
            Validate(package.Timeline);
            return package.Timeline;
        }

        private static void RejectDuplicateProperties(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON property: " + property.Name);
                    RejectDuplicateProperties(property.Value);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
                foreach (JsonElement item in element.EnumerateArray()) RejectDuplicateProperties(item);
        }

        public static MacroTimeline ReadFile(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            {
                if (stream.Length > MaxBytes) throw new InvalidDataException("JSON must be at most 1 MiB.");
                byte[] bytes = new byte[MaxBytes + 1];
                int used = 0, count;
                while (used < bytes.Length && (count = stream.Read(bytes, used, bytes.Length - used)) > 0) used += count;
                if (used > MaxBytes) throw new InvalidDataException("JSON must be at most 1 MiB.");
                string text = new UTF8Encoding(false, true).GetString(bytes, 0, used);
                return Import(text.TrimStart('\uFEFF'));
            }
        }

        public static void Move(List<MacroStep> steps, int index, int delta)
        {
            int target = index + delta;
            if (Math.Abs(delta) != 1 || index < 0 || index >= steps.Count || target < 0 || target >= steps.Count) return;
            MacroStep step = steps[index];
            steps.RemoveAt(index);
            steps.Insert(target, step);
        }
    }
}
