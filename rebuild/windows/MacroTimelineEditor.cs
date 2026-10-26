using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace RkRebuild
{
    internal sealed partial class MainWindow
    {
        private MacroTimeline _activeTimeline;

        private void MacroOperation(Action action)
        {
            try { action(); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Local macro draft", MessageBoxButton.OK, MessageBoxImage.Warning); }
        }

        private Button MacroButton(string label, Action action)
        {
            Button button = ActionButton(label, false);
            button.MinWidth = 90;
            button.Margin = new Thickness(0, 4, 8, 4);
            button.Click += delegate { MacroOperation(action); };
            return button;
        }

        private TextBox MacroText(string text, int maxLength, double width)
        {
            return new TextBox { Text = text, MaxLength = maxLength, Width = width, Height = 32, Margin = new Thickness(0, 4, 8, 4) };
        }

        private ComboBox MacroChoice(string[] options, string selected, double width)
        {
            return new ComboBox { ItemsSource = options, SelectedItem = selected, Width = width, Height = 32, Margin = new Thickness(0, 4, 8, 4) };
        }

        private static int MacroInteger(string text, int min, int max, string field)
        {
            if (!Int32.TryParse(text, out int value) || value < min || value > max)
                throw new InvalidDataException(field + " must be a whole number from " + min + " to " + max + ".");
            return value;
        }

        private void RenderMacroTimelines()
        {
            AddIntro("Local macro timeline editor", "Manually draft key, mouse, and delay rows. Symbolic labels only: no input capture, playback, RK byte encoding, device writes, or firmware. Save row/header edits explicitly before navigating or exporting.");
            _pageBody.Children.Add(Paragraph("Community limits (not RK capacity): 100 timelines/profile, 200 rows/timeline, 0–60000 ms per delay, cycle count 1–99. Cycle modes are draft metadata only.", 11));
            List<MacroTimeline> timelines;
            if (!_settings.MacroTimelines.TryGetValue(_selected.Code, out timelines) || timelines == null)
                _settings.MacroTimelines[_selected.Code] = timelines = new List<MacroTimeline>();
            if (!timelines.Contains(_activeTimeline)) _activeTimeline = timelines.FirstOrDefault();
            WrapPanel library = new WrapPanel { Margin = new Thickness(0, 8, 0, 8) };
            ComboBox selector = new ComboBox { ItemsSource = timelines, SelectedItem = _activeTimeline, Width = 280, Height = 32, Margin = new Thickness(0, 6, 8, 0) };
            selector.SelectionChanged += delegate { _activeTimeline = selector.SelectedItem as MacroTimeline; RenderMacros(); };
            library.Children.Add(selector);
            library.Children.Add(MacroButton("New timeline", delegate {
                if (timelines.Count >= MacroTimelineCodec.MaxTimelines) throw new InvalidDataException("Local limit: 100 timelines per profile.");
                _activeTimeline = new MacroTimeline();
                timelines.Add(_activeTimeline);
                SaveSettings();
                RenderMacros();
            }));
            library.Children.Add(MacroButton("Import local JSON", delegate {
                if (timelines.Count >= MacroTimelineCodec.MaxTimelines) throw new InvalidDataException("Local limit: 100 timelines per profile.");
                OpenFileDialog dialog = new OpenFileDialog { Filter = "Local timeline JSON (*.rkmacro.json;*.json)|*.rkmacro.json;*.json", CheckFileExists = true };
                if (dialog.ShowDialog(this) != true) return;
                MacroTimeline imported = MacroTimelineCodec.ReadFile(dialog.FileName);
                // Always append. Imported drafts cannot overwrite another timeline or legacy note.
                timelines.Add(imported);
                _activeTimeline = imported;
                SaveSettings();
                RenderMacros();
            }));
            _pageBody.Children.Add(library);
            MacroTimeline timeline = _activeTimeline;
            if (timeline == null) { _pageBody.Children.Add(CardWithText("No structured timelines for this profile. Create one or import this app's local JSON format. Legacy notes below are not parsed into events.")); return; }
            try { MacroTimelineCodec.Validate(timeline); }
            catch (Exception ex) { _pageBody.Children.Add(CardWithText("This saved timeline is invalid and has been preserved unchanged: " + ex.Message)); return; }

            Border editor = Card();
            StackPanel body = new StackPanel { Margin = new Thickness(14) };
            editor.Child = body;
            body.Children.Add(Paragraph("Name (1–48 characters) · local cycle mode · count (1–99)", 12));
            WrapPanel header = new WrapPanel();
            TextBox name = MacroText(timeline.Name, 48, 240);
            ComboBox loop = MacroChoice(new[] { "none", "count", "while-held", "until-press" }, timeline.LoopMode, 140);
            TextBox cycles = MacroText(timeline.LoopCount.ToString(), 2, 60);
            header.Children.Add(name); header.Children.Add(loop); header.Children.Add(cycles);
            header.Children.Add(MacroButton("Save header locally", delegate {
                int count = MacroInteger(cycles.Text, 1, 99, "Cycle count");
                if (String.IsNullOrWhiteSpace(name.Text)) throw new InvalidDataException("Enter a timeline name.");
                timeline.Name = name.Text.Trim(); timeline.LoopMode = (string)loop.SelectedItem; timeline.LoopCount = count;
                MacroTimelineCodec.Validate(timeline);
                SaveSettings(); RenderMacros();
            }));
            header.Children.Add(MacroButton("Export saved JSON", delegate {
                string json = MacroTimelineCodec.Export(timeline);
                SaveFileDialog dialog = new SaveFileDialog { Filter = "Local timeline JSON (*.rkmacro.json)|*.rkmacro.json", FileName = "local-timeline.rkmacro.json", DefaultExt = ".rkmacro.json", AddExtension = true };
                if (dialog.ShowDialog(this) == true) File.WriteAllText(dialog.FileName, json, new UTF8Encoding(false));
            }));
            header.Children.Add(MacroButton("Delete timeline", delegate {
                if (MessageBox.Show(this, "Delete this structured local timeline? Legacy notes are unaffected.", "Local macro draft", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                timelines.Remove(timeline); _activeTimeline = null; SaveSettings(); RenderMacros();
            }));
            body.Children.Add(header);

            ListBox rows = new ListBox { ItemsSource = timeline.Steps, Height = 210, Margin = new Thickness(0, 10, 0, 8), Background = Brush(20, 20, 20), Foreground = Brush(220, 220, 220) };
            body.Children.Add(rows);
            TextBlock summary = Paragraph(timeline.Steps.Count + " / 200 rows · total specified wait: " + timeline.Steps.Sum(step => (long)step.DelayMs) + " ms per pass (not execution duration)", 11);
            body.Children.Add(summary);
            body.Children.Add(Paragraph("Row kind · symbolic action (e.g. A down / A up / left click) · delay in milliseconds. For key/mouse rows, delay is wait-after metadata. Delay-only rows have no action.", 11));
            WrapPanel fields = new WrapPanel();
            ComboBox kind = MacroChoice(new[] { "key", "mouse", "delay" }, "key", 100);
            TextBox action = MacroText("A down", 100, 260);
            TextBox delay = MacroText("0", 5, 90);
            delay.ToolTip = "Milliseconds (ms), whole number 0–60000";
            action.ToolTip = "Symbolic text only; no key codes or captured input";
            fields.Children.Add(kind); fields.Children.Add(action); fields.Children.Add(delay);
            fields.Children.Add(Paragraph("ms", 12));
            kind.SelectionChanged += delegate { action.IsEnabled = (string)kind.SelectedItem != "delay"; };
            rows.SelectionChanged += delegate {
                MacroStep selected = rows.SelectedItem as MacroStep;
                if (selected == null) return;
                kind.SelectedItem = selected.Kind; action.Text = selected.Action; delay.Text = selected.DelayMs.ToString();
            };
            body.Children.Add(fields);
            Func<MacroStep> readStep = delegate {
                MacroStep step = new MacroStep { Kind = (string)kind.SelectedItem, Action = (string)kind.SelectedItem == "delay" ? "" : action.Text.Trim(), DelayMs = MacroInteger(delay.Text, 0, 60000, "Delay (ms)") };
                MacroTimelineCodec.Validate(new MacroTimeline { Steps = new List<MacroStep> { step } });
                return step;
            };
            Action persistRows = delegate { MacroTimelineCodec.Validate(timeline); SaveSettings(); rows.Items.Refresh(); summary.Text = timeline.Steps.Count + " / 200 rows · total specified wait: " + timeline.Steps.Sum(step => (long)step.DelayMs) + " ms per pass (not execution duration)"; };
            WrapPanel controls = new WrapPanel();
            Action<bool> insert = before => {
                if (timeline.Steps.Count >= MacroTimelineCodec.MaxRows) throw new InvalidDataException("Local limit: 200 rows.");
                MacroStep step = readStep();
                int index = rows.SelectedIndex < 0 ? timeline.Steps.Count : rows.SelectedIndex + (before ? 0 : 1);
                timeline.Steps.Insert(index, step); persistRows(); rows.SelectedIndex = index;
            };
            controls.Children.Add(MacroButton("Insert before", () => insert(true)));
            controls.Children.Add(MacroButton("Insert after / append", () => insert(false)));
            controls.Children.Add(MacroButton("Save selected row", delegate {
                int index = rows.SelectedIndex;
                if (index < 0) throw new InvalidDataException("Select a row to edit first.");
                timeline.Steps[index] = readStep(); persistRows(); rows.SelectedIndex = index;
            }));
            foreach (int direction in new[] { -1, 1 })
            {
                int delta = direction;
                controls.Children.Add(MacroButton(delta < 0 ? "Move up" : "Move down", delegate {
                    int index = rows.SelectedIndex;
                    if (index < 0 || index + delta < 0 || index + delta >= timeline.Steps.Count) return;
                    MacroTimelineCodec.Move(timeline.Steps, index, delta); persistRows(); rows.SelectedIndex = index + delta;
                }));
            }
            controls.Children.Add(MacroButton("Remove row", delegate {
                int index = rows.SelectedIndex;
                if (index < 0) return;
                timeline.Steps.RemoveAt(index); persistRows(); rows.SelectedIndex = Math.Min(index, timeline.Steps.Count - 1);
            }));
            body.Children.Add(controls);
            body.Children.Add(Paragraph("Insert uses the fields above; without a selection either insert button appends. Import appends into this profile. JSON is not .mck, mac.dct, RK Drive, or a hardware payload.", 11));
            _pageBody.Children.Add(editor);
        }
    }
}
