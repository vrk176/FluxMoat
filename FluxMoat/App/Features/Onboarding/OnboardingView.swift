import SwiftUI

/// Five-stage onboarding over one continuous scene. Always dark. The VPN
/// permission prompt comes only on the last page, and all VPN state is derived
/// from AppModel so this view can't disagree with the Dashboard.
struct OnboardingView: View {
    let onFinish: () -> Void

    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Wide window, i.e. an iPad not in a narrow Split View column. Only
    /// `page(for:)` reacts to it: constraining the `TabView` itself would limit the
    /// page swipe to the column and stop the art from filling the window.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var selection: Int = 0
    /// Animated mirror of `selection` that drives the canvas.
    @State private var progress: Double = 0
    /// One-shot wake-in of the first arc.
    @State private var intro: Double = 0
    /// Turn-on attempts this session; the second failure adds the Settings hint.
    /// Deliberately not persisted.
    @State private var attempts = 0
    @State private var detailsExpanded = false

    private var phase: OnboardingVPNPhase { .derive(from: model) }

    var body: some View {
        ZStack {
            OnboardingSceneCanvas(
                progress: progress,
                intro: intro,
                phase: phase,
                reduceMotion: reduceMotion
            )
            .ignoresSafeArea()
            .accessibilityHidden(true)

            TabView(selection: $selection) {
                ForEach(OnboardingStage.allCases) { stage in
                    page(for: stage)
                        .tag(stage.rawValue)
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
        }
        .preferredColorScheme(.dark)
        .onChange(of: selection) { _, new in
            if reduceMotion {
                progress = Double(new)
            } else {
                withAnimation(.easeInOut(duration: 0.7)) { progress = Double(new) }
            }
        }
        .onAppear {
            if reduceMotion {
                intro = 1
            } else {
                withAnimation(.easeOut(duration: 1.4).delay(0.4)) { intro = 1 }
            }
        }
    }

    // MARK: - Pages

    @ViewBuilder
    private func page(for stage: OnboardingStage) -> some View {
        if horizontalSizeClass == .regular {
            // On a wide window, cap the copy column width (otherwise the Continue button
            // is hundreds of points long) and lift the block off the bottom edge toward
            // the art. The lift is a fraction of the window because the art is placed by
            // fractions too. Portrait only: a short wide window has no height to spare.
            GeometryReader { geo in
                pageColumn(for: stage, lift: lift(in: geo.size))
                    .frame(maxWidth: Self.regularColumnWidth)
                    .frame(width: geo.size.width, height: geo.size.height)
            }
        } else {
            pageColumn(for: stage, lift: 0)
        }
    }

    /// How far up off the bottom edge the copy block is floated.
    private func lift(in size: CGSize) -> CGFloat {
        guard size.height > size.width else { return 0 }
        return size.height * Self.regularLiftFraction
    }

    private func pageColumn(for stage: OnboardingStage, lift: CGFloat) -> some View {
        VStack(spacing: 0) {
            Spacer(minLength: 0)
            // Use a plain stack when it fits so the copy sits at the bottom with the CTA;
            // fall back to scrolling at accessibility text sizes.
            ViewThatFits(in: .vertical) {
                pageCopy(for: stage)
                ScrollView {
                    pageCopy(for: stage)
                }
                .frame(maxHeight: 420)
                .defaultScrollAnchor(.top)
            }

            pageDots
                .padding(.top, 20)

            ctaArea(for: stage)
                .padding(.horizontal, 28)
                .padding(.top, 16)
                .padding(.bottom, 12)

            // A Spacer rather than padding so it collapses first when the window is too
            // short, instead of pushing the button off screen. Zero on a phone.
            Spacer(minLength: 0)
                .frame(maxHeight: lift)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Page \(stage.rawValue + 1) of \(OnboardingStage.allCases.count)")
    }

    /// Copy column width cap on a wide window, roughly a phone's width.
    private static let regularColumnWidth: CGFloat = 560
    /// Enough to lift the block under the art without the privacy stage's ring
    /// ending up behind the title.
    private static let regularLiftFraction: CGFloat = 0.15

    private func pageCopy(for stage: OnboardingStage) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(stage.title)
                .font(.title.weight(.semibold))
                .foregroundStyle(OnboardingPalette.textPrimary)
                .accessibilityAddTraits(.isHeader)
            Text(stage == .ready && phase == .on ? OnboardingStage.readyBodyOn : stage.body)
                .font(.body)
                .foregroundStyle(OnboardingPalette.textSecondary)
                // ViewThatFits measures at ideal size, which truncates multiline Text to
                // one line. Force full wrapping height.
                .fixedSize(horizontal: false, vertical: true)
            if stage == .privacy {
                boundariesList
            }
            if stage == .ready {
                readyStatus
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 28)
    }

    private var boundariesList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Know the boundaries")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(OnboardingPalette.textPrimary)
                .padding(.top, 6)
            ForEach(OnboardingStage.boundaries, id: \.self) { line in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text("·").foregroundStyle(OnboardingPalette.textSecondary)
                    Text(line)
                        .font(.footnote)
                        .foregroundStyle(OnboardingPalette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    /// Ready-page status under the body copy: a friendly summary, with the raw
    /// error behind a disclosure.
    @ViewBuilder
    private var readyStatus: some View {
        switch phase {
        case .idle:
            EmptyView()
        case .requesting:
            Label(OnboardingStage.waitingForIOS, systemImage: "hourglass")
                .font(.callout)
                .foregroundStyle(OnboardingPalette.textSecondary)
                .padding(.top, 4)
        case .on:
            Label(OnboardingStage.protectionOn, systemImage: "checkmark.shield.fill")
                .font(.callout.weight(.medium))
                .foregroundStyle(OnboardingPalette.core)
                .padding(.top, 4)
        case .notStarted(let detail):
            VStack(alignment: .leading, spacing: 8) {
                Text(OnboardingStage.notStartedSummary)
                    .font(.callout)
                    .foregroundStyle(OnboardingPalette.textPrimary)
                if attempts >= 2 {
                    Text(OnboardingStage.settingsHint)
                        .font(.footnote)
                        .foregroundStyle(OnboardingPalette.textSecondary)
                }
                DisclosureGroup(OnboardingStage.technicalDetails, isExpanded: $detailsExpanded) {
                    Text(detail)
                        .font(.footnote.monospaced())
                        .foregroundStyle(OnboardingPalette.textSecondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                }
                .font(.footnote)
                .tint(OnboardingPalette.textSecondary)
            }
            .padding(.top, 4)
        }
    }

    private var pageDots: some View {
        HStack(spacing: 8) {
            ForEach(OnboardingStage.allCases) { stage in
                Circle()
                    .fill(stage.rawValue == selection ? OnboardingPalette.textPrimary : .white.opacity(0.25))
                    .frame(width: 7, height: 7)
            }
        }
        .accessibilityHidden(true)
    }

    // MARK: - CTAs

    @ViewBuilder
    private func ctaArea(for stage: OnboardingStage) -> some View {
        if stage != .ready {
            Button {
                advance()
            } label: {
                Text("Continue")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .tint(OnboardingPalette.core.opacity(0.85))
            .foregroundStyle(.black)
        } else {
            VStack(spacing: 10) {
                switch phase {
                case .on:
                    Button { onFinish() } label: {
                        Text(OnboardingStage.ctaEnter).frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .tint(OnboardingPalette.core.opacity(0.85))
                    .foregroundStyle(.black)
                case .idle, .requesting, .notStarted:
                    Button {
                        attempts += 1
                        detailsExpanded = false
                        model.setProtection(true)
                    } label: {
                        Text(retryLabel).frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .tint(OnboardingPalette.core.opacity(0.85))
                    .foregroundStyle(.black)
                    .disabled(phase == .requesting)

                    // Always allowed. It doesn't cancel a start already handed to the system;
                    // the Dashboard reconciles.
                    Button(OnboardingStage.ctaNotNow) { onFinish() }
                        .font(.callout)
                        .foregroundStyle(OnboardingPalette.textSecondary)
                }
            }
        }
    }

    private var retryLabel: String {
        if case .notStarted = phase { return OnboardingStage.ctaRetry }
        return OnboardingStage.ctaTurnOn
    }

    private func advance() {
        guard selection < OnboardingStage.allCases.count - 1 else { return }
        selection += 1
    }
}
