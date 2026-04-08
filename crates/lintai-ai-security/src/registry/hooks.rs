use lintai_api::{Category, Confidence, RuleTier, Severity, declare_rule};

use super::*;
use crate::hook_rules::{
    check_hook_authorized_keys_write, check_hook_base64_exec,
    check_hook_browser_secret_store_access, check_hook_browser_secret_store_exfil,
    check_hook_camera_capture, check_hook_camera_capture_exfil, check_hook_clipboard_exfil,
    check_hook_clipboard_read, check_hook_cron_persistence, check_hook_download_exec,
    check_hook_environment_dump, check_hook_environment_dump_exfil,
    check_hook_insecure_permission_change, check_hook_keylogging, check_hook_keylogging_exfil,
    check_hook_launchd_registration, check_hook_linux_capability_manipulation,
    check_hook_microphone_capture, check_hook_microphone_capture_exfil,
    check_hook_password_file_access, check_hook_plain_http_exfil, check_hook_root_delete,
    check_hook_screen_capture, check_hook_screen_capture_exfil, check_hook_secret_exfil,
    check_hook_sensitive_file_exfil, check_hook_setuid_setgid, check_hook_shell_profile_write,
    check_hook_static_auth_exposure, check_hook_systemd_service_registration,
    check_hook_tls_bypass, check_hook_webhook_secret_exfil,
};

declare_rule! {
    pub struct HookDownloadExecRule {
        code: "SEC201",
        summary: "Hook script downloads remote code and executes it",
        doc_title: "Hook script: remote code execution",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookSecretExfilRule {
        code: "SEC202",
        summary: "Hook script appears to exfiltrate secrets through a network call",
        doc_title: "Hook script: secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookPlainHttpExfilRule {
        code: "SEC203",
        summary: "Hook script sends secret material to an insecure http:// endpoint",
        doc_title: "Hook script: insecure HTTP secret send",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookTlsBypassRule {
        code: "SEC204",
        summary: "Hook script disables TLS or certificate verification for a network call",
        doc_title: "Hook script: TLS verification disabled",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookStaticAuthExposureRule {
        code: "SEC205",
        summary: "Hook script embeds static authentication material in a network call",
        doc_title: "Hook script: hardcoded auth in network call",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookBase64ExecRule {
        code: "SEC206",
        summary: "Hook script decodes a base64 payload and executes it",
        doc_title: "Hook script: base64 payload execution",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookRootDeleteRule {
        code: "SEC633",
        summary: "Hook script attempts destructive root deletion",
        doc_title: "Hook script: destructive root deletion",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookPasswordFileAccessRule {
        code: "SEC634",
        summary: "Hook script accesses a sensitive system password file",
        doc_title: "Hook script: password file access",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookShellProfileWriteRule {
        code: "SEC635",
        summary: "Hook script writes to a shell profile startup file",
        doc_title: "Hook script: shell profile write",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookAuthorizedKeysWriteRule {
        code: "SEC636",
        summary: "Hook script writes to SSH authorized_keys",
        doc_title: "Hook script: authorized_keys write",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookCronPersistenceRule {
        code: "SEC649",
        summary: "Hook script manipulates cron persistence",
        doc_title: "Hook script: cron persistence",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookSystemdServiceRegistrationRule {
        code: "SEC650",
        summary: "Hook script registers a systemd service or unit for persistence",
        doc_title: "Hook script: systemd persistence",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookLaunchdRegistrationRule {
        code: "SEC651",
        summary: "Hook script registers a launchd plist for persistence",
        doc_title: "Hook script: launchd persistence",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookInsecurePermissionChangeRule {
        code: "SEC661",
        summary: "Hook script performs an insecure permission change",
        doc_title: "Hook script: insecure chmod",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookSetuidSetgidRule {
        code: "SEC662",
        summary: "Hook script manipulates setuid or setgid permissions",
        doc_title: "Hook script: setuid or setgid manipulation",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookLinuxCapabilityManipulationRule {
        code: "SEC663",
        summary: "Hook script manipulates Linux capabilities",
        doc_title: "Hook script: Linux capability manipulation",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookWebhookSecretExfilRule {
        code: "SEC673",
        summary: "Hook script posts secret material to a webhook endpoint",
        doc_title: "Hook script: webhook secret exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookSensitiveFileExfilRule {
        code: "SEC683",
        summary: "Hook script transfers a sensitive credential file to a remote destination",
        doc_title: "Hook script: sensitive file exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookClipboardReadRule {
        code: "SEC687",
        summary: "Hook script reads local clipboard contents",
        doc_title: "Hook script: clipboard read",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookBrowserSecretStoreAccessRule {
        code: "SEC688",
        summary: "Hook script accesses browser credential or cookie stores",
        doc_title: "Hook script: browser credential store access",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookClipboardExfilRule {
        code: "SEC695",
        summary: "Hook script exfiltrates clipboard contents over the network",
        doc_title: "Hook script: clipboard exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookBrowserSecretStoreExfilRule {
        code: "SEC696",
        summary: "Hook script exfiltrates browser credential or cookie store data",
        doc_title: "Hook script: browser credential store exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookScreenCaptureRule {
        code: "SEC703",
        summary: "Hook script captures a screenshot or desktop image",
        doc_title: "Hook script: screen capture",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookScreenCaptureExfilRule {
        code: "SEC704",
        summary: "Hook script captures and exfiltrates a screenshot or desktop image",
        doc_title: "Hook script: screen capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookCameraCaptureRule {
        code: "SEC711",
        summary: "Hook script captures a camera image or webcam stream",
        doc_title: "Hook script: camera capture",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookMicrophoneCaptureRule {
        code: "SEC712",
        summary: "Hook script records microphone or audio input",
        doc_title: "Hook script: microphone capture",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookCameraCaptureExfilRule {
        code: "SEC713",
        summary: "Hook script captures and exfiltrates camera or webcam data",
        doc_title: "Hook script: camera capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookMicrophoneCaptureExfilRule {
        code: "SEC714",
        summary: "Hook script records and exfiltrates microphone or audio input",
        doc_title: "Hook script: microphone capture exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookKeyloggingRule {
        code: "SEC727",
        summary: "Hook script captures keystrokes or keyboard input",
        doc_title: "Hook script: keylogger capture",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookKeyloggingExfilRule {
        code: "SEC728",
        summary: "Hook script captures and exfiltrates keystrokes or keyboard input",
        doc_title: "Hook script: keylogger exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookEnvironmentDumpRule {
        code: "SEC735",
        summary: "Hook script dumps environment variables or shell state",
        doc_title: "Hook script: environment dump",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

declare_rule! {
    pub struct HookEnvironmentDumpExfilRule {
        code: "SEC736",
        summary: "Hook script dumps and exfiltrates environment variables or shell state",
        doc_title: "Hook script: environment dump exfiltration",
        category: Category::Security,
        default_severity: Severity::Deny,
        default_confidence: Confidence::High,
        tier: RuleTier::Stable,
    }
}

pub(crate) const RULE_SPECS: [NativeRuleSpec; 32] = [
    NativeRuleSpec {
        metadata: HookDownloadExecRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit remote download-and-execute behavior in hook shell lines, not prose text.",
            malicious_case_ids: &["hook-download-exec"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals download-and-execute observation over non-comment hook lines.",
        },
        check: check_hook_download_exec,
        safe_fix: None,
        suggestion_message: Some(
            "vendor or pin the script locally instead of downloading and executing it inline",
        ),
        suggestion_fix: Some(hook_download_exec_fix),
    },
    NativeRuleSpec {
        metadata: HookSecretExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches secret-bearing network exfil behavior in executable hook lines.",
            malicious_case_ids: &["hook-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals secret exfil observation from network markers plus secret markers on non-comment lines.",
        },
        check: check_hook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing network exfil flow and keep secret access local",
        ),
        suggestion_fix: Some(hook_secret_exfil_fix),
    },
    NativeRuleSpec {
        metadata: HookPlainHttpExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches insecure HTTP transport on a secret-bearing hook exfil path.",
            malicious_case_ids: &["hook-plain-http-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals precise http:// span observation gated by concurrent secret exfil markers.",
        },
        check: check_hook_plain_http_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove insecure HTTP secret exfil and keep secret handling local or over HTTPS",
        ),
        suggestion_fix: Some(hook_plain_http_exfil_fix),
    },
    NativeRuleSpec {
        metadata: HookTlsBypassRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit TLS verification bypass tokens in executable hook network context.",
            malicious_case_ids: &["hook-tls-bypass"],
            benign_case_ids: &["cursor-plugin-tls-verified-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals TLS-bypass token observation over parsed hook line tokens and network context.",
        },
        check: check_hook_tls_bypass,
        safe_fix: None,
        suggestion_message: Some(
            "remove TLS-bypass flags or env overrides and use normal certificate verification",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookStaticAuthExposureRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches literal static auth material in hook URLs or authorization headers.",
            malicious_case_ids: &["hook-static-auth-userinfo"],
            benign_case_ids: &["hook-auth-dynamic-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals userinfo/header literal extraction excluding dynamic references.",
        },
        check: check_hook_static_auth_exposure,
        safe_fix: None,
        suggestion_message: Some(
            "move embedded credentials out of URLs and headers into environment or provider-local auth configuration",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookBase64ExecRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit base64 decode-and-execute behavior in executable hook lines.",
            malicious_case_ids: &["hook-base64-exec"],
            benign_case_ids: &["hook-base64-decode-safe"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals base64-decode plus exec observation over non-comment hook lines.",
        },
        check: check_hook_base64_exec,
        safe_fix: None,
        suggestion_message: Some(
            "remove the obfuscated base64 decode-and-exec flow from the hook script",
        ),
        suggestion_fix: Some(hook_base64_exec_fix),
    },
    NativeRuleSpec {
        metadata: HookRootDeleteRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit `rm`-style destructive root deletion payloads in executable hook lines.",
            malicious_case_ids: &["hook-persistence-escalation"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals shell-token analysis over non-comment hook lines for `rm` with recursive+force flags targeting `/` or using `--no-preserve-root`.",
        },
        check: check_hook_root_delete,
        safe_fix: None,
        suggestion_message: Some(
            "remove the destructive root deletion command from the hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookPasswordFileAccessRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches direct access to sensitive password and sudo policy files in executable hook lines.",
            malicious_case_ids: &["hook-persistence-escalation"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals path detection over non-comment hook lines for `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/gshadow`, or `/etc/master.passwd`.",
        },
        check: check_hook_password_file_access,
        safe_fix: None,
        suggestion_message: Some("remove the sensitive password-file access from the hook script"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookShellProfileWriteRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit shell startup profile modification in executable hook lines.",
            malicious_case_ids: &["hook-persistence-escalation"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals redirection-or-tee detection over `.bashrc`, `.bash_profile`, `.zshrc`, or `.profile` targets in non-comment hook lines.",
        },
        check: check_hook_shell_profile_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the shell profile write and keep startup-file persistence out of the hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookAuthorizedKeysWriteRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit writes to SSH `authorized_keys` in executable hook lines.",
            malicious_case_ids: &["hook-persistence-escalation"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals redirection-or-tee detection for `authorized_keys` targets in non-comment hook lines.",
        },
        check: check_hook_authorized_keys_write,
        safe_fix: None,
        suggestion_message: Some(
            "remove the `authorized_keys` modification and keep SSH persistence out of the hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookCronPersistenceRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit cron manipulation or cron file writes in executable hook lines.",
            malicious_case_ids: &["hook-service-persistence"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-or-write-target detection over non-comment hook lines for `crontab` mutation or writes to `/etc/cron*` and `/var/spool/cron`.",
        },
        check: check_hook_cron_persistence,
        safe_fix: None,
        suggestion_message: Some(
            "remove cron persistence setup from the hook script and keep scheduled-task changes under explicit review",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookSystemdServiceRegistrationRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit systemd service registration or unit-file writes in executable hook lines.",
            malicious_case_ids: &["hook-service-persistence"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-or-write-target detection over non-comment hook lines for `systemctl enable|link` or writes to systemd unit paths.",
        },
        check: check_hook_systemd_service_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove systemd persistence from the hook script and keep service registration out of shared hooks",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookLaunchdRegistrationRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit launchd registration or LaunchAgents/LaunchDaemons plist writes in executable hook lines.",
            malicious_case_ids: &["hook-service-persistence"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-or-write-target detection over non-comment hook lines for `launchctl load|bootstrap` or writes to LaunchAgents/LaunchDaemons plist paths.",
        },
        check: check_hook_launchd_registration,
        safe_fix: None,
        suggestion_message: Some(
            "remove launchd persistence from the hook script and keep plist registration out of shared hooks",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookInsecurePermissionChangeRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit insecure chmod payloads in executable hook lines.",
            malicious_case_ids: &["hook-privilege-escalation-payloads"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals shell-token analysis over non-comment hook lines for `chmod 777`, `chmod 0777`, or symbolic world-writable modes such as `a+rwx`.",
        },
        check: check_hook_insecure_permission_change,
        safe_fix: None,
        suggestion_message: Some(
            "remove the insecure chmod change from the hook script and use the minimum required permissions",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookSetuidSetgidRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit setuid or setgid chmod payloads in executable hook lines.",
            malicious_case_ids: &["hook-privilege-escalation-payloads"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals shell-token analysis over non-comment hook lines for chmod octal modes with setuid/setgid bits or symbolic modes such as `u+s` and `g+s`.",
        },
        check: check_hook_setuid_setgid,
        safe_fix: None,
        suggestion_message: Some("remove setuid or setgid manipulation from the hook script"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookLinuxCapabilityManipulationRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit Linux capability manipulation payloads in executable hook lines.",
            malicious_case_ids: &["hook-privilege-escalation-payloads"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals shell-token analysis over non-comment hook lines for `setcap` or dangerous Linux capability tokens such as `cap_setuid` and `cap_sys_admin`.",
        },
        check: check_hook_linux_capability_manipulation,
        safe_fix: None,
        suggestion_message: Some("remove Linux capability manipulation from the hook script"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookWebhookSecretExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit secret-bearing posts to well-known webhook endpoints in executable hook lines.",
            malicious_case_ids: &["hook-webhook-secret-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for secret markers plus webhook endpoint markers such as `hooks.slack.com/services/` or `discord.com/api/webhooks/`.",
        },
        check: check_hook_webhook_secret_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the secret-bearing webhook post from the hook script and keep secret access local",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookSensitiveFileExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit transfer of sensitive credential files to remote network or cloud-storage destinations in executable hook lines.",
            malicious_case_ids: &[
                "hook-sensitive-file-exfil",
                "hook-sensitive-file-rclone-exfil",
            ],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for sensitive file paths such as `.env`, `.aws/credentials`, `.ssh/id_rsa`, or `.kube/config` combined with transfer commands like `scp`, `sftp`, `rsync`, `curl`, `aws s3 cp`, `gsutil cp`, or `rclone copy`.",
        },
        check: check_hook_sensitive_file_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove the remote transfer of sensitive credential files from the hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookClipboardReadRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit clipboard-reading commands in executable hook lines.",
            malicious_case_ids: &["hook-local-data-theft"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard`.",
        },
        check: check_hook_clipboard_read,
        safe_fix: None,
        suggestion_message: Some("remove clipboard reads from the shared hook script"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookBrowserSecretStoreAccessRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches direct access to browser credential or cookie storage files in executable hook lines.",
            malicious_case_ids: &["hook-local-data-theft"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`.",
        },
        check: check_hook_browser_secret_store_access,
        safe_fix: None,
        suggestion_message: Some(
            "remove browser credential or cookie store access from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookClipboardExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches clipboard-reading commands that also transmit data to remote network endpoints in executable hook lines.",
            malicious_case_ids: &["hook-local-data-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for clipboard read utilities such as `pbpaste`, `wl-paste`, `xclip -o`, `xsel --output`, or PowerShell `Get-Clipboard` combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_hook_clipboard_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of clipboard contents from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookBrowserSecretStoreExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches direct access to browser credential or cookie storage files combined with remote transfer behavior in executable hook lines.",
            malicious_case_ids: &["hook-local-data-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for browser profile paths such as Chrome or Firefox state directories paired with secret-store files like `Cookies`, `Login Data`, `logins.json`, `key4.db`, `Web Data`, or `Local State`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_hook_browser_secret_store_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove network exfiltration of browser credential or cookie store data from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookScreenCaptureRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit screen capture utilities in executable hook lines.",
            malicious_case_ids: &["hook-screen-capture", "hook-screen-capture-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`.",
        },
        check: check_hook_screen_capture,
        safe_fix: None,
        suggestion_message: Some("remove screenshot capture behavior from the shared hook script"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookScreenCaptureExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit screen capture utilities combined with remote transfer behavior in executable hook lines.",
            malicious_case_ids: &["hook-screen-capture-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit screen capture utilities such as `screencapture`, `scrot`, `gnome-screenshot`, `grim`, `maim`, `grimshot`, ImageMagick `import -window root`, or PowerShell `CopyFromScreen`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_hook_screen_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove screenshot capture and remote transfer behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookCameraCaptureRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit camera or webcam capture utilities in executable hook lines.",
            malicious_case_ids: &["hook-device-capture", "hook-device-capture-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera or video device selectors.",
        },
        check: check_hook_camera_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove camera or webcam capture behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookMicrophoneCaptureRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit microphone or audio-recording utilities in executable hook lines.",
            malicious_case_ids: &["hook-device-capture", "hook-device-capture-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit audio capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with microphone or audio device selectors.",
        },
        check: check_hook_microphone_capture,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone or audio capture behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookCameraCaptureExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit camera or webcam capture utilities combined with remote transfer behavior in executable hook lines.",
            malicious_case_ids: &["hook-device-capture-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit camera capture utilities such as `imagesnap`, `fswebcam`, or `ffmpeg` with camera or video device selectors, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_hook_camera_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove camera capture and remote transfer behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookMicrophoneCaptureExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Matches explicit microphone or audio-recording utilities combined with remote transfer behavior in executable hook lines.",
            malicious_case_ids: &["hook-device-capture-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit audio capture utilities such as `arecord`, `parecord`, `parec`, `rec`, `sox -d`, or `ffmpeg` with microphone or audio device selectors, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_hook_microphone_capture_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove microphone capture and remote transfer behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookKeyloggingRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks hook shell lines for explicit keystroke capture utilities or keylogger markers.",
            malicious_case_ids: &["hook-keylogger", "hook-keylogger-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`.",
        },
        check: check_hook_keylogging,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture or keylogger behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookKeyloggingExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks hook shell lines for explicit keystroke capture utilities or keylogger markers combined with remote transfer behavior.",
            malicious_case_ids: &["hook-keylogger-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit keylogger primitives such as `logkeys`, `xinput test`, `evtest`, `showkey`, PowerShell `GetAsyncKeyState`, or inline Python listener markers like `pynput.keyboard.Listener`, combined with remote sinks such as `curl`, `wget`, `scp`, `rsync`, `nc`, or HTTP(S) endpoints.",
        },
        check: check_hook_keylogging_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove keystroke capture and remote transfer behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookEnvironmentDumpRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks hook shell lines for explicit environment or shell-state enumeration commands.",
            malicious_case_ids: &[
                "hook-env-dump",
                "hook-env-dump-exfil",
                "hook-env-dump-cloud-exfil",
            ],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`.",
        },
        check: check_hook_environment_dump,
        safe_fix: None,
        suggestion_message: Some("remove environment dumping behavior from the shared hook script"),
        suggestion_fix: None,
    },
    NativeRuleSpec {
        metadata: HookEnvironmentDumpExfilRule::METADATA,
        surface: Surface::Hook,
        default_presets: BASE_PRESETS,
        detection_class: DetectionClass::Structural,
        lifecycle: RuleLifecycle::Stable {
            rationale: "Checks hook shell lines for explicit environment or shell-state enumeration commands combined with remote transfer behavior.",
            malicious_case_ids: &["hook-env-dump-exfil", "hook-env-dump-cloud-exfil"],
            benign_case_ids: &["cursor-plugin-clean-basic"],
            requires_structured_evidence: true,
            remediation_reviewed: true,
            deterministic_signal_basis: "HookSignals command-line analysis over non-comment hook lines for explicit environment enumeration primitives such as `printenv`, `env` used as a dump, `export -p`, `declare -xp`, or `compgen -v`, combined with remote sinks such as `curl`, `wget`, `scp`, `sftp`, `rsync`, `nc`, `aws s3 cp`, `gsutil cp`, `rclone copy`, or HTTP(S) endpoints.",
        },
        check: check_hook_environment_dump_exfil,
        safe_fix: None,
        suggestion_message: Some(
            "remove environment dumping and remote transfer behavior from the shared hook script",
        ),
        suggestion_fix: None,
    },
];

pub(crate) fn rule_specs() -> &'static [NativeRuleSpec] {
    &RULE_SPECS
}
