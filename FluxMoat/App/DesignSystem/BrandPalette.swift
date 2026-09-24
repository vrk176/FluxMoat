import SwiftUI

/// Brand colors for the main app. Values come from `OnboardingPalette` but are
/// copied, not shared, so retuning app surfaces doesn't shift the onboarding art.
enum BrandPalette {
    /// Logo mark blue, light (top) and deep (bottom).
    static let blueLight = Color(red: 0.45, green: 0.68, blue: 0.98)
    static let blueDeep = Color(red: 0.18, green: 0.42, blue: 0.88)

    /// Dark mode background gradient, top to bottom.
    static let surfaceTop = Color(red: 0.04, green: 0.09, blue: 0.16)
    static let surfaceBottom = Color(red: 0.10, green: 0.13, blue: 0.28)

    /// Threat-intel blocks. Violet rather than a red shade so it stays distinct
    /// from plain "blocked" red in stacked bars, including under deuteranopia.
    /// Adaptive because the text sits on an 18% wash of itself, so contrast comes
    /// from the surface underneath (4.2:1 dark, 4.1:1 light).
    static let threat = Color(uiColor: UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.78, green: 0.54, blue: 1.00, alpha: 1)
            : UIColor(red: 0.55, green: 0.22, blue: 0.92, alpha: 1)
    })

    /// Translucent so cards read as a lighter shade of the gradient behind them.
    static let cardFill = Color.white.opacity(0.07)
    static let separator = Color.white.opacity(0.10)
    static let textPrimary = Color.white.opacity(0.94)
    static let textSecondary = Color.white.opacity(0.62)

    static let darkSurface = LinearGradient(
        colors: [surfaceTop, surfaceBottom],
        startPoint: .top,
        endPoint: .bottom
    )
}

extension View {
    /// Replaces the grouped background with the brand gradient in dark mode.
    /// Light mode keeps the stock look.
    func brandDarkBackground() -> some View {
        modifier(BrandDarkBackground())
    }

    /// Styles list rows as cards on the brand gradient. Takes `dark` from the
    /// caller so view identity doesn't change when the color scheme flips.
    ///
    /// Light mode passes an explicit color instead of nil: nil removes the row
    /// background view, and if the scheme flips to dark while the list is under
    /// a pushed page, the rows never get one back.
    func brandCardRows(_ dark: Bool) -> some View {
        let fill = dark ? BrandPalette.cardFill : Color(uiColor: .secondarySystemGroupedBackground)
        let separator: Color? = dark ? BrandPalette.separator : nil
        return listRowBackground(fill).listRowSeparatorTint(separator)
    }

    /// Label color for prominent buttons on the accent tint. White on the dark
    /// mode accent is only ~2.3:1, so dark mode uses the navy surface color.
    func brandProminentLabel(_ dark: Bool) -> some View {
        foregroundStyle(dark ? AnyShapeStyle(BrandPalette.surfaceTop) : AnyShapeStyle(Color.white))
    }
}

private struct BrandDarkBackground: ViewModifier {
    @Environment(\.colorScheme) private var colorScheme

    func body(content: Content) -> some View {
        let dark = colorScheme == .dark
        return content
            .scrollContentBackground(dark ? .hidden : .automatic)
            .background {
                if dark {
                    BrandPalette.darkSurface.ignoresSafeArea()
                }
            }
    }
}
