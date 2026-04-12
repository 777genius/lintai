use lintai_api::{Category, Severity};
use lintai_engine::{DiagnosticSeverity, RuntimeErrorKind};

use crate::shipped_rules::PublicLane;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TextRenderOptions {
    pub(crate) color_mode: ColorMode,
    pub(crate) is_terminal: bool,
}

impl TextRenderOptions {
    pub(crate) fn new(color_mode: ColorMode, is_terminal: bool) -> Self {
        Self {
            color_mode,
            is_terminal,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TextColorEnvironment {
    pub(crate) no_color: bool,
    pub(crate) clicolor: Option<String>,
    pub(crate) clicolor_force: Option<String>,
}

impl TextColorEnvironment {
    pub(crate) fn current() -> Self {
        Self {
            no_color: std::env::var_os("NO_COLOR").is_some(),
            clicolor: std::env::var("CLICOLOR").ok(),
            clicolor_force: std::env::var("CLICOLOR_FORCE").ok(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedTextStyle {
    color_enabled: bool,
}

impl ResolvedTextStyle {
    #[cfg(test)]
    pub(crate) fn plain_for_tests() -> Self {
        Self {
            color_enabled: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn color_for_tests() -> Self {
        Self {
            color_enabled: true,
        }
    }

    pub(crate) fn from_environment(options: TextRenderOptions, env: &TextColorEnvironment) -> Self {
        let color_enabled = match options.color_mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => {
                if env.clicolor_force.as_deref() == Some("1") {
                    true
                } else if env.no_color || env.clicolor.as_deref() == Some("0") {
                    false
                } else {
                    options.is_terminal
                }
            }
        };
        Self { color_enabled }
    }

    pub(crate) fn section_heading(self, title: &str, count: usize) -> String {
        let base = format!("{title} ({count})");
        self.paint(&base, &[AnsiStyle::Bold], None)
    }

    pub(crate) fn lane_heading(self, lane: PublicLane, count: usize) -> String {
        let base = format!("{} ({count})", lane.slug());
        self.paint(&base, &[AnsiStyle::Bold], Some(lane_color(lane)))
    }

    pub(crate) fn lane_explainer(self, lane: PublicLane) -> String {
        self.secondary(lane_explainer_text(lane))
    }

    pub(crate) fn lane_summary_label(self, lane: PublicLane, count: usize) -> String {
        let base = format!("{} {count}", lane.slug());
        self.paint(&base, &[AnsiStyle::Bold], Some(lane_color(lane)))
    }

    fn badge(self, label: &str, color: Option<AnsiColor>, styles: &[AnsiStyle]) -> String {
        let base = format!("[{label}]");
        self.paint(&base, styles, color)
    }

    pub(crate) fn severity_badge(self, severity: Severity) -> String {
        let (color, styles) = match severity {
            Severity::Deny => (Some(AnsiColor::Red), &[AnsiStyle::Bold][..]),
            Severity::Warn => (Some(AnsiColor::Yellow), &[][..]),
            Severity::Allow => (Some(AnsiColor::BrightBlack), &[AnsiStyle::Dim][..]),
        };
        self.badge(severity.slug(), color, styles)
    }

    pub(crate) fn category_badge(self, category: Category) -> String {
        self.badge(
            category_label(category),
            Some(category_color(category)),
            &[],
        )
    }

    pub(crate) fn diagnostic_badge(self, severity: DiagnosticSeverity) -> String {
        let color = match severity {
            DiagnosticSeverity::Info => Some(AnsiColor::Blue),
            DiagnosticSeverity::Warn => Some(AnsiColor::Yellow),
        };
        self.badge(diagnostic_label(severity), color, &[])
    }

    pub(crate) fn runtime_error_badge(self, kind: RuntimeErrorKind) -> String {
        self.badge(
            error_kind_label(kind),
            Some(AnsiColor::Red),
            &[AnsiStyle::Bold],
        )
    }

    pub(crate) fn secondary(self, text: &str) -> String {
        self.paint(text, &[AnsiStyle::Dim], None)
    }

    fn paint(self, text: &str, styles: &[AnsiStyle], color: Option<AnsiColor>) -> String {
        if !self.color_enabled {
            return text.to_owned();
        }

        let mut codes = Vec::new();
        if let Some(color) = color {
            codes.push(color.code());
        }
        for style in styles {
            codes.push(style.code());
        }
        if codes.is_empty() {
            return text.to_owned();
        }

        format!("\x1b[{}m{}\x1b[0m", codes.join(";"), text)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnsiColor {
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    BrightBlack,
}

impl AnsiColor {
    fn code(self) -> &'static str {
        match self {
            Self::Red => "31",
            Self::Green => "32",
            Self::Yellow => "33",
            Self::Blue => "34",
            Self::Magenta => "35",
            Self::Cyan => "36",
            Self::BrightBlack => "90",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnsiStyle {
    Bold,
    Dim,
}

impl AnsiStyle {
    fn code(self) -> &'static str {
        match self {
            Self::Bold => "1",
            Self::Dim => "2",
        }
    }
}

fn lane_color(lane: PublicLane) -> AnsiColor {
    match lane {
        PublicLane::Recommended => AnsiColor::Green,
        PublicLane::ThreatReview => AnsiColor::Red,
        PublicLane::SupplyChain => AnsiColor::Magenta,
        PublicLane::Compat => AnsiColor::Blue,
        PublicLane::Governance => AnsiColor::Yellow,
        PublicLane::Guidance => AnsiColor::Cyan,
        PublicLane::Advisory => AnsiColor::Blue,
        PublicLane::Preview => AnsiColor::BrightBlack,
    }
}

fn lane_explainer_text(lane: PublicLane) -> &'static str {
    match lane {
        PublicLane::Recommended => "quiet practical default findings",
        PublicLane::ThreatReview => "explicit malicious, secret-bearing, or spyware-like review",
        PublicLane::SupplyChain => "reproducibility, provenance, and dependency hardening review",
        PublicLane::Compat => "config, schema, and policy contract review",
        PublicLane::Governance => "shared authority and workflow policy review",
        PublicLane::Guidance => "advice-oriented guidance and maintainability review",
        PublicLane::Advisory => "installed-package advisory review",
        PublicLane::Preview => "broader contextual review outside the quiet default",
    }
}

fn category_color(category: Category) -> AnsiColor {
    match category {
        Category::Critical => AnsiColor::Red,
        Category::Security => AnsiColor::Red,
        Category::Hardening => AnsiColor::Yellow,
        Category::Quality => AnsiColor::Blue,
        Category::Audit => AnsiColor::Cyan,
        Category::Nursery => AnsiColor::BrightBlack,
    }
}

fn category_label(category: Category) -> &'static str {
    match category {
        Category::Critical => "critical",
        Category::Security => "security",
        Category::Hardening => "hardening",
        Category::Quality => "quality",
        Category::Audit => "audit",
        Category::Nursery => "nursery",
    }
}

fn diagnostic_label(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warn => "warn",
    }
}

fn error_kind_label(kind: RuntimeErrorKind) -> &'static str {
    match kind {
        RuntimeErrorKind::Read => "read",
        RuntimeErrorKind::InvalidUtf8 => "invalid-utf8",
        RuntimeErrorKind::Parse => "parse",
        RuntimeErrorKind::ProviderExecution => "provider-execution",
        RuntimeErrorKind::ProviderTimeout => "provider-timeout",
    }
}

#[cfg(test)]
mod tests {
    use super::{ColorMode, ResolvedTextStyle, TextColorEnvironment, TextRenderOptions};
    use crate::shipped_rules::PublicLane;

    #[test]
    fn auto_color_uses_terminal_when_env_is_clean() {
        let style = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Auto, true),
            &TextColorEnvironment::default(),
        );
        assert!(style.color_enabled);
    }

    #[test]
    fn auto_color_disables_on_non_terminal() {
        let style = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Auto, false),
            &TextColorEnvironment::default(),
        );
        assert!(!style.color_enabled);
    }

    #[test]
    fn auto_color_respects_env_switches() {
        let disabled = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Auto, true),
            &TextColorEnvironment {
                no_color: true,
                ..TextColorEnvironment::default()
            },
        );
        assert!(!disabled.color_enabled);

        let clicolor_disabled = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Auto, true),
            &TextColorEnvironment {
                clicolor: Some("0".to_owned()),
                ..TextColorEnvironment::default()
            },
        );
        assert!(!clicolor_disabled.color_enabled);

        let forced = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Auto, false),
            &TextColorEnvironment {
                clicolor_force: Some("1".to_owned()),
                ..TextColorEnvironment::default()
            },
        );
        assert!(forced.color_enabled);
    }

    #[test]
    fn clicolor_force_overrides_other_disable_switches() {
        let forced = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Auto, false),
            &TextColorEnvironment {
                no_color: true,
                clicolor: Some("0".to_owned()),
                clicolor_force: Some("1".to_owned()),
            },
        );
        assert!(forced.color_enabled);
    }

    #[test]
    fn always_and_never_override_auto_resolution() {
        let always = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Always, false),
            &TextColorEnvironment::default(),
        );
        assert!(always.color_enabled);

        let never = ResolvedTextStyle::from_environment(
            TextRenderOptions::new(ColorMode::Never, true),
            &TextColorEnvironment {
                clicolor_force: Some("1".to_owned()),
                ..TextColorEnvironment::default()
            },
        );
        assert!(!never.color_enabled);
    }

    #[test]
    fn lane_explainer_is_plain_text_friendly() {
        let style = ResolvedTextStyle::plain_for_tests();
        assert_eq!(
            style.lane_explainer(PublicLane::Governance),
            "shared authority and workflow policy review"
        );
    }
}
