import SwiftUI

/// Low-poly world silhouette drawn behind a blur on the onboarding canvas.
/// Decorative only. Points are normalized, roughly equirectangular:
/// x 0...1 is 180°W to 180°E, y 0...1 is 78°N to 60°S. If this needs more
/// detail, switch to an SVG asset rather than growing the table.
struct WorldMapShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        for polygon in Self.continents {
            guard let first = polygon.first else { continue }
            path.move(to: point(first, in: rect))
            for p in polygon.dropFirst() {
                path.addLine(to: point(p, in: rect))
            }
            path.closeSubpath()
        }
        return path
    }

    private func point(_ p: (Double, Double), in rect: CGRect) -> CGPoint {
        CGPoint(x: rect.minX + rect.width * p.0, y: rect.minY + rect.height * p.1)
    }

    /// One polygon per landmass, roughly clockwise.
    private static let continents: [[(Double, Double)]] = [
        // North America (Alaska, Canada, east coast, Mexico, back up)
        [
            (0.02, 0.16), (0.06, 0.10), (0.10, 0.12), (0.13, 0.08),
            (0.20, 0.07), (0.26, 0.10), (0.29, 0.15), (0.27, 0.20),
            (0.30, 0.24), (0.27, 0.30), (0.24, 0.33), (0.22, 0.38),
            (0.19, 0.44), (0.17, 0.50), (0.15, 0.46), (0.14, 0.40),
            (0.11, 0.36), (0.08, 0.30), (0.05, 0.26), (0.04, 0.21),
        ],
        // Greenland
        [
            (0.31, 0.05), (0.36, 0.04), (0.38, 0.08), (0.35, 0.13),
            (0.32, 0.12), (0.30, 0.08),
        ],
        // South America
        [
            (0.20, 0.52), (0.25, 0.50), (0.30, 0.53), (0.32, 0.58),
            (0.30, 0.65), (0.28, 0.72), (0.25, 0.80), (0.23, 0.87),
            (0.21, 0.83), (0.21, 0.74), (0.19, 0.66), (0.18, 0.58),
        ],
        // Europe
        [
            (0.44, 0.20), (0.46, 0.14), (0.50, 0.11), (0.55, 0.12),
            (0.57, 0.16), (0.55, 0.21), (0.52, 0.24), (0.49, 0.27),
            (0.46, 0.26),
        ],
        // Africa
        [
            (0.45, 0.30), (0.50, 0.28), (0.55, 0.30), (0.58, 0.35),
            (0.60, 0.42), (0.58, 0.50), (0.55, 0.58), (0.53, 0.66),
            (0.51, 0.71), (0.49, 0.66), (0.47, 0.58), (0.44, 0.48),
            (0.42, 0.40), (0.43, 0.34),
        ],
        // Asia (Urals, Siberia, far east, SE Asia, India, back west)
        [
            (0.57, 0.14), (0.62, 0.08), (0.70, 0.06), (0.78, 0.07),
            (0.86, 0.10), (0.93, 0.14), (0.95, 0.20), (0.90, 0.24),
            (0.87, 0.30), (0.83, 0.34), (0.80, 0.40), (0.76, 0.46),
            (0.72, 0.50), (0.69, 0.44), (0.66, 0.48), (0.63, 0.52),
            (0.61, 0.46), (0.63, 0.38), (0.59, 0.32), (0.57, 0.26),
            (0.56, 0.20),
        ],
        // Australia
        [
            (0.80, 0.66), (0.85, 0.63), (0.90, 0.65), (0.92, 0.70),
            (0.90, 0.76), (0.85, 0.78), (0.81, 0.75), (0.79, 0.70),
        ],
    ]
}
