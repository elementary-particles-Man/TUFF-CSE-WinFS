#[cfg(test)]
mod tests {
    use tuff_cse_winfs::completion::{self, CompletionStatus};

    #[test]
    fn test_success_code_format() {
        let fp = "7A3F-91C2";
        let host = "PC-02341";
        let target_count = 2;
        let excluded_count = 1;
        let status = CompletionStatus::BackgroundSealing;

        let code = completion::build_success_code(fp, host, target_count, excluded_count, status);
        assert!(code.starts_with("CSE-INSTALL-OK"));
        assert!(code.contains("FP=7A3F-91C2"));
        assert!(code.contains("HOST=PC-02341"));
        assert!(code.contains("TARGET=2"));
        assert!(code.contains("EXCLUDED=1"));
        assert!(code.contains("STATUS=BACKGROUND-SEALING"));
    }

    #[test]
    fn test_failed_code_format() {
        let fp = "7A3F-91C2";
        let host = "PC-02341";
        let reason = "ADMIN_REQUIRED";

        let code = completion::build_failed_code(fp, host, reason);
        assert!(code.starts_with("CSE-INSTALL-FAILED"));
        assert!(code.contains("FP=7A3F-91C2"));
        assert!(code.contains("HOST=PC-02341"));
        assert!(code.contains("REASON=ADMIN_REQUIRED"));
    }

    #[test]
    fn test_no_secrets_in_code() {
        let fp = "7A3F-91C2";
        let host = "PC-02341";
        let code = completion::build_success_code(fp, host, 1, 0, CompletionStatus::Ready);

        // Verification of absence of common secret names
        assert!(!code.contains("basekey"));
        assert!(!code.contains("MK"));
        assert!(!code.contains("TK"));
        assert!(!code.contains("PK"));
    }
}
