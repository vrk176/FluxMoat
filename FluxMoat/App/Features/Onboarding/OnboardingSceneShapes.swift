import SwiftUI

// Drawable pieces of the onboarding scene, only ever composed by
// OnboardingSceneCanvas.

// MARK: - Orb

/// The glowing core. `brightness` lifts it when protection turns on;
/// `breathe` is the idle pulse and must be false under Reduce Motion.
struct OrbView: View {
    var diameter: CGFloat
    var brightness: Double = 1.0
    var breathe: Bool = false

    var body: some View {
        TimelineView(.animation(minimumInterval: 1 / 20, paused: !breathe)) { context in
            let phase = breathe ? sin(context.date.timeIntervalSinceReferenceDate * 0.9) : 0
            let scale = 1.0 + 0.03 * phase
            ZStack {
                Circle()
                    .fill(.white.opacity(0.16 * brightness))
                    .frame(width: diameter, height: diameter)
                    .blur(radius: diameter * 0.10)
                Circle()
                    .fill(.white.opacity(0.30 * brightness))
                    .frame(width: diameter * 0.78, height: diameter * 0.78)
                Circle()
                    .fill(.white.opacity(0.45 * brightness))
                    .frame(width: diameter * 0.56, height: diameter * 0.56)
                Circle()
                    .fill(OnboardingPalette.core.opacity(brightness))
                    .frame(width: diameter * 0.22, height: diameter * 0.22)
                    .shadow(color: OnboardingPalette.core.opacity(0.8 * brightness), radius: diameter * 0.10)
            }
            .scaleEffect(scale)
        }
    }
}

// MARK: - Traffic arcs

/// A cubic curve from the orb to a destination on the map, drawn with `trim`
/// so it can grow in, plus an endpoint dot.
struct TrafficArcShape: Shape {
    /// Normalized canvas coordinates (0…1).
    var from: CGPoint
    var to: CGPoint
    /// Sideways bow as a fraction of the chord length. Positive bows left of the
    /// from-to direction. A perpendicular bow keeps south-bound arcs out of the copy.
    var bow: CGFloat
    var trim: CGFloat

    var animatableData: CGFloat {
        get { trim }
        set { trim = newValue }
    }

    func path(in rect: CGRect) -> Path {
        let a = CGPoint(x: rect.width * from.x, y: rect.height * from.y)
        let b = CGPoint(x: rect.width * to.x, y: rect.height * to.y)
        let mid = CGPoint(x: (a.x + b.x) / 2, y: (a.y + b.y) / 2)
        let dx = b.x - a.x, dy = b.y - a.y
        let control = CGPoint(x: mid.x - dy * bow, y: mid.y + dx * bow)
        var path = Path()
        path.move(to: a)
        path.addQuadCurve(to: b, control: control)
        return path.trimmedPath(from: 0, to: trim)
    }
}

/// An arc plus its endpoint dot, colored and faded as one unit.
struct TrafficArcView: View {
    var from: CGPoint
    var to: CGPoint
    var bow: CGFloat
    var color: Color
    var alpha: Double

    var body: some View {
        GeometryReader { geo in
            ZStack {
                TrafficArcShape(from: from, to: to, bow: bow, trim: alpha)
                    .stroke(
                        color.opacity(0.75 * alpha),
                        style: StrokeStyle(lineWidth: 2, lineCap: .round)
                    )
                    .shadow(color: color.opacity(0.5 * alpha), radius: 4)
                Circle()
                    .fill(color.opacity(alpha))
                    .frame(width: 7, height: 7)
                    .shadow(color: color.opacity(0.8 * alpha), radius: 5)
                    .position(x: geo.size.width * to.x, y: geo.size.height * to.y)
                    .opacity(alpha >= 0.98 ? 1 : 0)
            }
        }
        .allowsHitTesting(false)
    }
}

// MARK: - Moat ring

/// Vector version of the ring mark. The gap is part of the brand mark and
/// must never close, and no failure state breaks or reddens the ring.
/// Not currently on screen (the canvas uses the logo asset); kept as a
/// fallback if the asset is removed.
struct MoatRingView: View {
    var diameter: CGFloat
    /// Draw-in progress of the ring stroke, 0 to 1 (the gap stays open at 1).
    var drawn: CGFloat
    /// Traveller position in radians.
    var dotAngle: Angle = .zero
    var dotVisible: Bool = false
    /// Progress of the stream sweeping out through the gap, 0 to 1.
    var streamThrough: CGFloat = 0

    /// The gap faces right and is 64° wide, matching the logo.
    static let gapCenter = Angle(degrees: -12)
    private var gapHalf: Angle { Angle(degrees: 32) }

    var body: some View {
        let radius = diameter / 2
        // Thick stroke (about 10% of the diameter) with bloom; a thin line looks like wire.
        let strokeWidth = diameter * 0.10
        ZStack {
            // Bloom pass: the same arc, blurred, underneath.
            ringArc.stroke(
                OnboardingPalette.ringLight.opacity(0.55),
                style: StrokeStyle(lineWidth: strokeWidth, lineCap: .round)
            )
            .blur(radius: strokeWidth * 0.9)

            ringArc.stroke(
                LinearGradient(
                    colors: [OnboardingPalette.ringLight, OnboardingPalette.ringDeep],
                    startPoint: .top, endPoint: .bottom
                ),
                style: StrokeStyle(lineWidth: strokeWidth, lineCap: .round)
            )

            // Highlight along the upper half, fading out by mid-height.
            ringArc.stroke(
                LinearGradient(
                    colors: [.white.opacity(0.45), .clear],
                    startPoint: .top, endPoint: .center
                ),
                style: StrokeStyle(lineWidth: strokeWidth * 0.35, lineCap: .round)
            )

            if streamThrough > 0.01 {
                stream
            }

            if dotVisible {
                Circle()
                    .fill(.white)
                    .frame(width: 12, height: 12)
                    .shadow(color: OnboardingPalette.core.opacity(0.9), radius: 8)
                    .offset(
                        x: radius * cos(dotAngle.radians),
                        y: radius * sin(dotAngle.radians)
                    )
            }
        }
        .frame(width: diameter, height: diameter)
        .allowsHitTesting(false)
    }

    private var ringArc: RingArcShape {
        RingArcShape(
            start: Self.gapCenter + gapHalf,
            sweep: Angle(degrees: 360 - 64),
            drawn: drawn
        )
    }

    /// Several strands of different widths and brightness with small offsets,
    /// to match the logo's stream.
    private var stream: some View {
        let strands: [(width: CGFloat, opacity: Double, dy: CGFloat, color: Color)] = [
            (diameter * 0.16, 0.14, 0, OnboardingPalette.ringLight),   // halo
            (diameter * 0.075, 0.35, -2, OnboardingPalette.ringLight), // body
            (diameter * 0.038, 0.90, 0, .white),                       // core
            (diameter * 0.016, 1.00, 2, .white),                       // filament
        ]
        return ZStack {
            ForEach(Array(strands.enumerated()), id: \.offset) { _, strand in
                FlowStreamShape(trim: streamThrough)
                    .stroke(
                        LinearGradient(
                            colors: [strand.color.opacity(0), strand.color, OnboardingPalette.core],
                            startPoint: .leading, endPoint: .trailing
                        ),
                        style: StrokeStyle(lineWidth: strand.width, lineCap: .round)
                    )
                    .opacity(strand.opacity)
                    .offset(y: strand.dy)
            }
        }
    }
}

/// The logo's S-curve stream, from inside the ring out through the gap. Drawn
/// in the ring's local square, trimmed for the sweep-in.
struct FlowStreamShape: Shape {
    var trim: CGFloat

    var animatableData: CGFloat {
        get { trim }
        set { trim = newValue }
    }

    func path(in rect: CGRect) -> Path {
        let w = rect.width, h = rect.height
        var path = Path()
        // From lower left inside the ring, dip below center, then out through the
        // right-side gap climbing slightly.
        path.move(to: CGPoint(x: w * 0.18, y: h * 0.68))
        path.addCurve(
            to: CGPoint(x: w * 0.62, y: h * 0.55),
            control1: CGPoint(x: w * 0.32, y: h * 0.80),
            control2: CGPoint(x: w * 0.50, y: h * 0.68)
        )
        path.addCurve(
            to: CGPoint(x: w * 1.10, y: h * 0.40),
            control1: CGPoint(x: w * 0.78, y: h * 0.44),
            control2: CGPoint(x: w * 0.95, y: h * 0.40)
        )
        return path.trimmedPath(from: 0, to: trim)
    }
}

/// Arc from `start` sweeping clockwise by `sweep * drawn`. Animatable on
/// `drawn` so the ring draws in during the privacy transition.
struct RingArcShape: Shape {
    var start: Angle
    var sweep: Angle
    var drawn: CGFloat

    var animatableData: CGFloat {
        get { drawn }
        set { drawn = newValue }
    }

    func path(in rect: CGRect) -> Path {
        var path = Path()
        guard drawn > 0.01 else { return path }
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2
        path.addArc(
            center: center,
            radius: radius,
            startAngle: start,
            endAngle: start + Angle(degrees: sweep.degrees * drawn),
            clockwise: false
        )
        return path
    }
}

// MARK: - Palette

/// Onboarding always uses a dark look regardless of system theme. Colors are
/// explicit and nothing inherits the app tint.
enum OnboardingPalette {
    static let core = Color(red: 0.45, green: 0.85, blue: 1.0)       // cyan heart
    // Ring stroke: the logo's blue, lighter at the top.
    static let ringLight = Color(red: 0.45, green: 0.68, blue: 0.98)
    static let ringDeep = Color(red: 0.18, green: 0.42, blue: 0.88)
    static let arcNormal = Color(red: 0.35, green: 0.70, blue: 1.0)  // allowed flow
    static let arcNotable = Color(red: 1.0, green: 0.62, blue: 0.25) // noteworthy
    static let arcBlocked = Color(red: 1.0, green: 0.33, blue: 0.33) // blocked (matches verdict red)
    static let textPrimary = Color.white.opacity(0.94)
    static let textSecondary = Color.white.opacity(0.62)

    /// Background gradient stops per stage (top, bottom).
    static let backgroundTop: [Color] = [
        Color(red: 0.04, green: 0.09, blue: 0.16),
        Color(red: 0.07, green: 0.10, blue: 0.23),
        Color(red: 0.13, green: 0.11, blue: 0.30),
        Color(red: 0.14, green: 0.12, blue: 0.32),
        Color(red: 0.05, green: 0.10, blue: 0.20),
    ]
    static let backgroundBottom: [Color] = [
        Color(red: 0.05, green: 0.11, blue: 0.20),
        Color(red: 0.10, green: 0.13, blue: 0.28),
        Color(red: 0.16, green: 0.14, blue: 0.35),
        Color(red: 0.17, green: 0.15, blue: 0.38),
        Color(red: 0.16, green: 0.13, blue: 0.35),
    ]
}
