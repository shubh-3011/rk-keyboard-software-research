using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace RkRebuild
{
    internal sealed partial class MainWindow
    {
        private void RenderLightingDraft()
        {
            string rawUi, rawHw, rawDefault;
            _selected.Options.TryGetValue("LightUI", out rawUi);
            _selected.Options.TryGetValue("LightHW", out rawHw);
            _selected.Options.TryGetValue("DefBri", out rawDefault);
            if (String.IsNullOrWhiteSpace(rawUi) || _selected.LightingSlots.Count == 0)
            {
                _pageBody.Children.Add(CardWithText("This profile has no explicit LightUI table to edit safely. Reference slots below are not proof of hardware controls; no scale has been invented."));
                return;
            }
            int[] ui, hw;
            try { ui = LightingDraftRules.ParseByteList(rawUi); hw = LightingDraftRules.ParseByteList(rawHw); }
            catch (Exception ex) { _pageBody.Children.Add(CardWithText("Profile lookup table could not be used: " + ex.Message)); return; }
            LightingDraft existing;
            _settings.LightingDrafts.TryGetValue(_selected.Code, out existing);
            int initial = 0;
            if (Int32.TryParse(rawDefault, out int value) && value >= 0 && value < ui.Length) initial = value;
            LightingDraft draft = new LightingDraft { ProfileSlot = _selected.LightingSlots[0], BrightnessIndex = initial };
            string previousNote = "";
            if (existing != null)
            {
                try { LightingDraftRules.Validate(existing, _selected.LightingSlots, ui); draft.ProfileSlot = existing.ProfileSlot; draft.BrightnessIndex = existing.BrightnessIndex; }
                catch (Exception ex) { previousNote = "An older invalid draft is preserved until you explicitly save a replacement: " + ex.Message; }
            }
            Border card = Card();
            StackPanel body = new StackPanel { Margin = new Thickness(18) };
            card.Child = body;
            body.Children.Add(Kicker("LOCAL LIGHTING DRAFT · HUB 4.6 CATALOG"));
            body.Children.Add(Paragraph("Choose a declared profile slot and a LightUI index. Values are the profile's raw display/output lookups, not brightness percentages. This does not read or apply keyboard state.", 12));
            if (previousNote != "") body.Children.Add(Paragraph(previousNote, 11));
            WrapPanel fields = new WrapPanel { Margin = new Thickness(0, 8, 0, 8) };
            ComboBox slots = new ComboBox { ItemsSource = _selected.LightingSlots, SelectedItem = draft.ProfileSlot, Width = 110, Height = 32, Margin = new Thickness(0, 0, 14, 0), ToolTip = "Declared profile slot; not a decoded firmware mode" };
            ComboBox brightness = new ComboBox { ItemsSource = Enumerable.Range(0, ui.Length).Select(i => "Index " + i + " · display " + ui[i]).ToArray(), SelectedIndex = draft.BrightnessIndex, Width = 240, Height = 32 };
            fields.Children.Add(Paragraph("Profile slot", 12)); fields.Children.Add(slots);
            fields.Children.Add(Paragraph("Brightness lookup", 12)); fields.Children.Add(brightness);
            body.Children.Add(fields);
            TextBlock translation = Paragraph("", 12);
            Action refresh = delegate {
                draft.ProfileSlot = slots.SelectedItem is int slot ? slot : -1;
                draft.BrightnessIndex = brightness.SelectedIndex;
                int? output = LightingDraftRules.OutputValue(draft, hw);
                translation.Text = "LightUI[" + draft.BrightnessIndex + "] = " + (draft.BrightnessIndex >= 0 ? ui[draft.BrightnessIndex].ToString() : "unselected") +
                    " · explicit LightHW = " + (output.HasValue ? output.Value.ToString() : "not provided for this index; no fallback guessed") +
                    " · no device report is generated";
            };
            slots.SelectionChanged += delegate { refresh(); };
            brightness.SelectionChanged += delegate { refresh(); };
            refresh(); body.Children.Add(translation);
            Button save = ActionButton("Save lighting draft locally", true);
            save.Margin = new Thickness(0, 10, 0, 0);
            TextBlock status = Paragraph("Not applied to keyboard", 11);
            save.Click += delegate {
                try
                {
                    LightingDraftRules.Validate(draft, _selected.LightingSlots, ui);
                    _settings.LightingDrafts[_selected.Code] = new LightingDraft { ProfileSlot = draft.ProfileSlot, BrightnessIndex = draft.BrightnessIndex };
                    SettingsStore.Save(_settings);
                    status.Text = "Saved locally for " + _selected.Code + ". Keyboard unchanged.";
                }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "Local lighting draft", MessageBoxButton.OK, MessageBoxImage.Warning); }
            };
            body.Children.Add(save); body.Children.Add(status);
            _pageBody.Children.Add(card);
        }
    }
}
