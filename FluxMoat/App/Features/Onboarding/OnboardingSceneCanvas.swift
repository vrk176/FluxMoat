import SwiftUI

/// The single scene behind all five onboarding pages. Every element
/// interpolates from `progress`, so page changes animate as one continuous
/// scene. Decorative; the container hides it from VoiceOver.
struct OnboardingSceneCanvas: View {
    /// 0…4 across the five stages; fractional while a transition animates.
    var progress: Double
    /// One-shot fade-in for the first arc on the awake stage (0 to 1 on appear).
    var intro: Double
    var phase: OnboardingVPNPhase
    var reduceMotion: Bool

    /// Wide windows change `sceneUnit` and the ready stage's `orbCenter`.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    /// Orb center in normalized canvas coordinates. Raised on the privacy stage
    /// so the ring clears the copy. On a wide window only the ready stage moves
    /// down: it shows just the logo, while the other stages keep phone values
    /// because the arc endpoints live in the top half of this space.
    private var orbCenter: CGPoint {
        let ready: Double = horizontalSizeClass == .regular ? 0.45 : 0.33
        return CGPoint(x: 0.5, y: keyed([0.42, 0.42, 0.42, 0.27, ready]))
    }

    /// Fraction of the ring asset's width taken by the ring itself; the rest is
    /// glow that fades to zero alpha (580.9 px of ring in a 900 px square).
    private static let ringArtFraction: CGFloat = 0.6454

    /// Frame width for the ring art, sized so the ring's outer edge spans
    /// `unit × 0.66`, with the transparent glow margin hanging off the sides.
    private static func ringFrame(_ unit: CGFloat) -> CGFloat {
        unit * 0.66 / ringArtFraction
    }

    /// The scale everything in the scene is drawn from. The cap stops the ring
    /// from clipping above the top of the window on large iPads in portrait,
    /// where the height term dominates; it also keeps the 900 px art from being
    /// upscaled too far.
    private func sceneUnit(in size: CGSize) -> CGFloat {
        let unit = min(size.width, size.height * 0.55)
        guard horizontalSizeClass == .regular else { return unit }
        return min(unit, Self.regularUnitCeiling)
    }

    private static let regularUnitCeiling: CGFloat = 620

    /// A connection arc and the verdict color it takes on the understand stage.
    /// Red only ever means blocked, same as Live Traffic.
    private struct Arc {
        let to: CGPoint
        let bow: CGFloat
        let verdict: Color
        let alphaKeys: [Double]
    }

    /// Endpoints stay in the map band (y ≤ 0.48) so no arc crosses the copy below.
    private var arcs: [Arc] {
        [
            Arc(to: CGPoint(x: 0.87, y: 0.28), bow: -0.26, verdict: OnboardingPalette.arcNormal,
                alphaKeys: [1, 1, 1, 0, 0]), // the awake arc, stays through understand
            Arc(to: CGPoint(x: 0.15, y: 0.27), bow: -0.26, verdict: OnboardingPalette.arcNormal,
                alphaKeys: [0, 1, 1, 0, 0]),
            Arc(to: CGPoint(x: 0.60, y: 0.47), bow: 0.30, verdict: OnboardingPalette.arcNotable,
                alphaKeys: [0, 1, 1, 0, 0]),
            Arc(to: CGPoint(x: 0.24, y: 0.46), bow: -0.30, verdict: OnboardingPalette.arcBlocked,
                alphaKeys: [0, 1, 1, 0, 0]),
        ]
    }

    var body: some View {
        GeometryReader { geo in
            let unit = sceneUnit(in: geo.size)
            let orbPoint = CGPoint(x: geo.size.width * orbCenter.x, y: geo.size.height * orbCenter.y)
            // Same orb size on the privacy and ready stages so the node doesn't jump.
            let orbScale = keyed([1.0, 1.0, 1.0, 0.62, 0.62])
            /// Progress of the verdict coloring (stage 1 to 2).
            let verdictBlend = max(0, min(1, progress - 1))

            ZStack {
                LinearGradient(
                    colors: [
                        keyedColor(OnboardingPalette.backgroundTop),
                        keyedColor(OnboardingPalette.backgroundBottom),
                    ],
                    startPoint: .top, endPoint: .bottom
                )

                WorldMapShape()
                    .fill(Color(red: 0.55, green: 0.56, blue: 0.76))
                    .opacity(keyed([0, 0.20, 0.20, 0.09, 0]))
                    .blur(radius: 1.2)
                    .padding(.horizontal, 8)
                    .frame(height: geo.size.height * 0.52)
                    .position(x: geo.size.width / 2, y: geo.size.height * 0.40)

                ForEach(Array(arcs.enumerated()), id: \.offset) { index, arc in
                    let baseAlpha = keyed(arc.alphaKeys)
                    // The first arc also waits for the intro fade-in.
                    let alpha = index == 0 ? baseAlpha * intro : baseAlpha
                    TrafficArcView(
                        from: orbCenter,
                        to: arc.to,
                        bow: arc.bow,
                        color: OnboardingPalette.arcNormal.mix(with: arc.verdict, by: verdictBlend),
                        alpha: alpha
                    )
                }

                // The ring asset has a real alpha channel, so it sits directly on the
                // gradient. See `Self.ringFrame` for the width.
                Image("OnboardingMoatRing")
                    .resizable()
                    .scaledToFit()
                    .frame(width: Self.ringFrame(unit))
                    .position(orbPoint)
                    .opacity(keyed([0, 0, 0, 1, 0]))

                OrbView(
                    diameter: unit * 0.34 * orbScale,
                    brightness: phase == .on ? 1.25 : 1.0,
                    breathe: !reduceMotion && progress < 3.5
                )
                .position(orbPoint)
                .opacity(keyed([1, 1, 1, 1, 0]))

                Image("OnboardingLogo")
                    .resizable()
                    .scaledToFit()
                    .frame(width: unit * 0.60)
                    // The glow is baked into the art, so brightness is the only adjustment.
                    .brightness(phase == .on ? 0.10 : 0)
                    .saturation(phase == .on ? 1.15 : 1.0)
                    .opacity(keyed([0, 0, 0, 0, 1]))
                    .position(orbPoint)
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.9), value: phase)
            }
        }
        .allowsHitTesting(false)
    }

    /// Piecewise-linear interpolation across the five stage key values.
    private func keyed(_ keys: [Double]) -> Double {
        let clamped = max(0, min(Double(keys.count - 1), progress))
        let i = Int(clamped)
        guard i < keys.count - 1 else { return keys[keys.count - 1] }
        let t = clamped - Double(i)
        return keys[i] * (1 - t) + keys[i + 1] * t
    }

    private func keyedColor(_ colors: [Color]) -> Color {
        let clamped = max(0, min(Double(colors.count - 1), progress))
        let i = Int(clamped)
        guard i < colors.count - 1 else { return colors[colors.count - 1] }
        return colors[i].mix(with: colors[i + 1], by: clamped - Double(i))
    }
}
