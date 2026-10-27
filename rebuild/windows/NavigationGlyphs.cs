using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;

namespace RkRebuild
{
    internal sealed partial class MainWindow
    {
        // Independently drawn geometry, not extracted vendor icons. The narrow
        // icon rail follows observed 4.06 navigation; extra research pages remain
        // accessible and do not grant any additional hardware permissions.
        private static FrameworkElement CreateNavigationGlyph(string page)
        {
            string geometry = page switch
            {
                "Device" => "M2,11 L12,2 22,11 M5,9 L5,22 10,22 10,15 14,15 14,22 19,22 19,9",
                "Key mapping" => "M2,5 L22,5 22,19 2,19 Z M5,8 L7,8 M10,8 L12,8 M15,8 L17,8 M19,8 L20,8 M5,11 L7,11 M10,11 L12,11 M15,11 L17,11 M19,11 L20,11 M5,15 L7,15 M9,15 L18,15",
                "Lighting" => "M8,16 C1,10 6,3 12,3 C18,3 23,10 16,16 L16,19 8,19 Z M9,22 L15,22 M12,0 L12,1 M1,8 L3,8 M21,8 L23,8 M3,2 L5,4 M19,4 L21,2",
                "Macros" => "M3,3 L17,3 21,7 21,21 3,21 Z M17,3 L17,7 21,7 M7,10 L10,13 7,16 M12,16 L17,16",
                "RK Drive editor" => "M3,3 L21,3 21,21 3,21 Z M7,7 L17,7 M7,12 L17,12 M7,17 L17,17 M10,5 L10,9 M15,10 L15,14 M11,15 L11,19",
                "Models" => "M2,3 L10,3 10,10 2,10 Z M14,3 L22,3 22,10 14,10 Z M2,14 L10,14 10,21 2,21 Z M14,14 L22,14 22,21 14,21 Z",
                "RK Drive directory" => "M2,6 L10,6 12,9 22,9 22,21 2,21 Z M2,6 L2,3 10,3 12,6 20,6 20,9",
                "Compatibility" => "M12,2 L21,6 20,15 Q18,20 12,23 Q6,20 4,15 L3,6 Z M7,12 L11,16 17,9",
                "Preferences" => "M10,2 L14,2 15,6 19,5 22,9 19,12 22,15 19,19 15,18 14,22 10,22 9,18 5,19 2,15 5,12 2,9 5,5 9,6 Z M16,12 A4,4 0 1 1 8,12 A4,4 0 1 1 16,12",
                _ => throw new ArgumentException("Unknown navigation page", nameof(page))
            };
            var path = new System.Windows.Shapes.Path
            {
                Data = Geometry.Parse(geometry), StrokeThickness = 1.5,
                StrokeLineJoin = PenLineJoin.Round, StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round, Width = 24, Height = 24
            };
            path.SetBinding(System.Windows.Shapes.Shape.StrokeProperty, new Binding("Foreground")
            {
                RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(Button), 1)
            });
            return new Viewbox { Child = path, Width = 32, Height = 32, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
        }
    }
}
