import SwiftUI

/// Layout helpers for regular-width windows.
///
/// Gated on horizontal size class, not device idiom: an iPad in narrow Split
/// View or Stage Manager should get the phone layout.
enum ReadableWidth {
    /// Max content column width, chosen so long footer text stays readable.
    static let column: CGFloat = 720

    /// Horizontal inset that centers a `column`-wide slice in `containerWidth`.
    /// `WorldMapView` uses it too so its map card lines up with the rows.
    static func inset(in containerWidth: CGFloat) -> CGFloat {
        max(0, (containerWidth - column) / 2)
    }
}

extension View {
    /// Caps the content column at `ReadableWidth.column` and centers it at
    /// regular width. No-op at compact width.
    ///
    /// Insets the safe area instead of using `.frame(maxWidth:)`, so a `List` or
    /// `Form` still paints its grouped background edge to edge.
    func readableWidth() -> some View {
        modifier(ReadableWidthModifier())
    }

    /// Sheet detents based on the presenting screen's width. Pass the size class
    /// from the presenting view: inside a form sheet the content always reports
    /// compact.
    ///
    /// Regular width uses `.presentationSizing(.page)`, because a form sheet
    /// sizes itself and ignores `.large` on its own.
    @ViewBuilder
    func adaptiveSheetDetents(
        _ compact: Set<PresentationDetent>, regularWidth: Bool
    ) -> some View {
        if regularWidth {
            presentationDetents([.large])
                .presentationSizing(.page)
        } else {
            presentationDetents(compact)
        }
    }
}

private struct ReadableWidthModifier: ViewModifier {
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    /// Width of the wrapped content, measured after the padding. Stable only
    /// because the wrapped views are width-greedy, so padding the safe area
    /// doesn't change their reported width. Content with an intrinsic width
    /// wider than `column` would feed back into the inset and grow without bound.
    @State private var containerWidth: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .safeAreaPadding(.horizontal, inset)
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { containerWidth = $0 }
    }

    private var inset: CGFloat {
        guard horizontalSizeClass == .regular else { return 0 }
        return ReadableWidth.inset(in: containerWidth)
    }
}
