using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using RkRebuild;

internal static class CompatibilityTests
{
    private static int assertions;
    private static int tests;
    private static void Check(bool condition, string message)
    {
        assertions++;
        if (!condition) throw new Exception(message);
    }
    private static void Test(string name, Action action)
    {
        action();
        tests++;
        Console.WriteLine("PASS " + name);
    }
    private static string Resource(string name)
    {
        using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
        using var reader = new StreamReader(stream ?? throw new Exception("Missing resource " + name));
        return reader.ReadToEnd();
    }
    private static void Main()
    {
        string hub = Resource("Hub.json");
        string drive = Resource("Drive.json");
        CompatibilityCatalog catalog = CompatibilityCatalog.Load(hub, drive);
        Test("all real keyboard source records retained", () => {
            Check(catalog.Entries.Count == 444, "265 + 177 + 2 entries");
            Check(catalog.Entries.Count(e => e.SourceSnapshot == "hub-4.6") == 265, "hub count");
            Check(catalog.Entries.Count(e => e.SourceSnapshot == "rk-drive-2026-10-18" && !e.IsSpecialized) == 177, "drive count");
            Check(catalog.Entries.Count(e => e.IsSpecialized) == 2, "specialized count");
            Check(catalog.Entries.Select(e => (e.SourceSnapshot, e.DescriptorId)).Distinct().Count() == 444, "unique source descriptor identity");
        });
        Test("real declarations preserved independently of parser output", () => {
            using JsonDocument h = JsonDocument.Parse(hub);
            using JsonDocument d = JsonDocument.Parse(drive);
            int i = 0;
            foreach (JsonElement model in h.RootElement.GetProperty("models").EnumerateArray())
            {
                CompatibilityEntry entry = catalog.Entries[i++];
                Check(entry.ProfileId == model.GetProperty("code").GetString(), "hub profile code");
                Check(entry.ModelName == model.GetProperty("name").GetString(), "hub model name");
                Check(entry.VendorId == h.RootElement.GetProperty("vendorId").GetString(), "parsed root vendor");
                Check(entry.ProductId == model.GetProperty("code").GetString(), "direct PID");
                Check(entry.UsagePage == "" && entry.Usage == "" && entry.Connection == "", "no invented hub metadata");
            }
            foreach (string array in new[] { "models", "specializedKeyboardProfiles" })
                foreach (JsonElement model in d.RootElement.GetProperty(array).EnumerateArray())
                {
                    CompatibilityEntry entry = catalog.Entries[i++];
                    Check(entry.ModelName == model.GetProperty("name").GetString(), "drive model name");
                    Check(entry.VendorId == model.GetProperty("vendor_id").GetInt32().ToString("X4"), "drive vendor");
                    Check(entry.ProductId == model.GetProperty("product_id").GetInt32().ToString("X4"), "drive product");
                    Check(entry.UsagePage == model.GetProperty("usage_page").GetInt32().ToString("X4"), "usage page");
                    Check(entry.Usage == model.GetProperty("usage").GetInt32().ToString("X4"), "usage");
                    Check(entry.Connection == model.GetProperty("connection").GetString(), "connection");
                    Check(entry.DeclaredProtocol == model.GetProperty("protocol_type").GetString(), "protocol label only");
                    if (entry.IsSpecialized) Check(entry.ProfileId == model.GetProperty("profile_id").GetString(), "specialized profile ID");
                }
        });
        Test("every valid real direct identity resolves itself", () => {
            foreach (CompatibilityEntry entry in catalog.Entries.Where(e => e.VendorId != "" && e.ProductId != ""))
            {
                Check(catalog.Match(entry.VendorId, entry.ProductId).Contains(entry), "self resolution");
                Check(catalog.Match("0x" + entry.VendorId.ToLowerInvariant(), "0X" + entry.ProductId.ToLowerInvariant()).Contains(entry), "prefixed lowercase resolution");
            }
        });
        Test("all real shared identities retain every candidate", () => {
            var shared = catalog.Entries.GroupBy(e => (e.VendorId, e.ProductId)).Where(g => g.Count() > 1).ToArray();
            Check(shared.Length > 0, "real aliases exist");
            foreach (var group in shared)
                Check(catalog.Match(group.Key.VendorId, group.Key.ProductId).SequenceEqual(group), "all aliases in source order");
            Check(shared.Any(g => g.Select(e => e.SourceSnapshot).Distinct().Count() > 1), "cross-source aliases retained");
        });
        Test("synthetic collisions, transport and source separation", () => {
            var c = CompatibilityCatalog.Load("""
                {"vendorId":"aBcD","models":[{"code":"a","name":"Hub","isDirectPid":true}]}
                """, """
                {"models":[
                  {"name":"USB","vendor_id_hex":"0xABCD","product_id_hex":"000a","connection":"USB","protocol_type":"one"},
                  {"name":"Receiver","vendor_id":43981,"product_id":10,"connection":"2.4 GHz receiver","protocol_type":"two"},
                  {"name":"USB duplicate","vendor_id_hex":"ABCD","product_id_hex":"A"}],
                 "specializedKeyboardProfiles":[{"profile_id":"us","name":"Special","vendor_id_hex":"abcd","product_id_hex":"a"}]}
                """);
            Check(c.Match("abcd", "a").Count == 5, "five candidates, no deduplication or family choice");
            Check(c.Entries[0].VendorId == "ABCD" && c.Entries[0].ProductId == "000A", "not hardcoded vendor");
            Check(c.Entries[4].IsSpecialized && c.Entries[4].ProfileId == "us", "specialized identity");
            Check(c.Entries[1].ProfileId != c.Entries[2].ProfileId, "descriptor IDs distinguish aliases");
            Check(c.Match("ABCD", "000B").Count == 0, "no family inference");
        });
        Test("non-direct profiles cannot become USB aliases", () => {
            var c = CompatibilityCatalog.Load("""
                {"vendorId":"258A","models":[
                  {"code":"1234","isDirectPid":false,"profileData":{"PID_Wireless":"1234"}},
                  {"code":"1234"},{"code":"1234","isDirectPid":"true"},
                  {"code":"1234","isDirectPid":true}]}
                """, "{}");
            Check(c.Entries.Take(3).All(e => e.ProfileId == "1234" && e.VendorId == "" && e.ProductId == ""), "aliases retained without USB identity");
            Check(c.Match("258A", "1234").Count == 1, "only explicit boolean direct PID matches");
            Check(CompatibilityCatalog.Load("{\"models\":[{\"code\":\"1234\",\"isDirectPid\":true}]}", "{}").Match("258A", "1234").Count == 0, "missing vendor never defaulted");
        });
        Test("mouse collections and explicit mouse descriptors excluded", () => {
            const string mouse = "{\"name\":\"Mouse\",\"device_type\":\"Mouse\",\"vendor_id_hex\":\"258A\",\"product_id_hex\":\"1234\"}";
            var c = CompatibilityCatalog.Load("{}", "{\"models\":[" + mouse + "],\"specializedKeyboardProfiles\":[" + mouse + "],\"mouseModels\":[" + mouse + "]}");
            Check(c.Entries.Count == 0 && c.Match("258A", "1234").Count == 0, "no mouse records");
        });
        Test("hex normalization and invalid match rejection", () => {
            var c = CompatibilityCatalog.Load("{\"vendorId\":\"a\",\"models\":[{\"code\":\"b\",\"isDirectPid\":true}]}", "{}");
            Check(c.Match("0Xa", "000b").Count == 1, "short hex padding");
            foreach (string invalid in new[] { null, "", " ", "0x", "0x0xA", "0000A", "10000", "-A", "+A", "G", "A B", "VID_000A", "hid#vid_000A", "0x000A&pid_000B", "Ａ", "1.0" })
            {
                Check(c.Match(invalid, "B").Count == 0, "invalid vendor " + invalid);
                Check(c.Match("A", invalid).Count == 0, "invalid product " + invalid);
            }
            Check(c.Match("000A", "00AB").Count == 0, "no substring matching");
        });
        Test("invalid declared identities never match or fall back", () => {
            var c = CompatibilityCatalog.Load("{\"vendorId\":\"invalid\",\"models\":[{\"code\":\"1234\",\"isDirectPid\":true}]}", """
                {"models":[
                  {"vendor_id_hex":"garbage","vendor_id":9610,"product_id_hex":"1234"},
                  {"vendor_id_hex":"258A","product_id_hex":"12345"},
                  {"vendor_id":-1,"product_id":1},
                  {"vendor_id":65536,"product_id":1},
                  {"vendor_id":1.5,"product_id":1},
                  {"vendor_id_hex":null,"vendor_id":9610,"product_id":1},
                  {"vendor_id":"258a","product_id":"0x1","usage_page_hex":"no","usage":65536}]}
                """);
            Check(c.Entries.Count == 8, "invalid identities still catalogued");
            Check(c.Entries.Take(7).All(e => e.VendorId == "" || e.ProductId == ""), "invalid identities empty");
            Check(c.Match("258A", "1234").Count == 0, "no numeric fallback");
            Check(c.Match("258A", "1").Count == 1, "string hex declaration");
            Check(c.Entries[7].UsagePage == "" && c.Entries[7].Usage == "", "invalid optional usage empty");
        });
        Test("all entries are immutable catalog-only evidence", () => {
            Check(!catalog.HardwareWritesAllowed, "catalog never enables writes");
            foreach (CompatibilityEntry entry in catalog.Entries)
            {
                Check(entry.Status == CompatibilityStatus.CataloguedOnly, "catalogued-only status");
                Check(!entry.HardwareWritesAllowed, "entry never enables writes");
            }
            Check(((IList<CompatibilityEntry>)catalog.Entries).IsReadOnly, "entries read-only");
            Check(((IList<CompatibilityEntry>)catalog.Match("258A", "002A")).IsReadOnly, "matches read-only");
            Check(typeof(CompatibilityEntry).GetProperties().All(p => p.SetMethod == null), "entry properties immutable");
        });
        Test("empty catalogs supported", () => {
            var c = CompatibilityCatalog.Load("{}", "{}");
            Check(c.Entries.Count == 0 && c.Match("0", "0").Count == 0, "empty snapshots");
        });
        Console.WriteLine($"Compatibility tests: {tests} passed; {assertions} assertions; {catalog.Entries.Count} real catalog entries.");
    }
}
