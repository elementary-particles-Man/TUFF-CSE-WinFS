#[cfg(test)]
mod tests {
    use tuff_cse_winfs::policy::{self, BackgroundPriority, InstallPolicy, TargetVolume};

    #[test]
    fn test_example_policy_parses() {
        let json = r#"{
            "policy_id": "FIN-CSE-2026-001",
            "mode": "background",
            "targets": [
                {
                    "volume": "D:",
                    "role": "data",
                    "cse": true
                }
            ],
            "supported_filesystems": [
                "NTFS",
                "exFAT",
                "FAT32",
                "FAT"
            ],
            "exclude_system_volumes": true,
            "background_priority": "lowest",
            "meta_flush_minutes": 30,
            "meta_flush_jitter_minutes": 7,
            "completion_code": true
        }"#;

        let policy: InstallPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.policy_id, "FIN-CSE-2026-001");
        assert_eq!(policy.background_priority, BackgroundPriority::Lowest);
        assert_eq!(policy.targets.len(), 1);
        policy::validate_policy(&policy).unwrap();
    }

    #[test]
    fn test_empty_policy_id_rejected() {
        let policy = InstallPolicy {
            policy_id: "".to_string(),
            mode: "background".to_string(),
            targets: vec![TargetVolume {
                volume: "D:".to_string(),
                role: "data".to_string(),
                cse: true,
            }],
            supported_filesystems: vec!["NTFS".to_string()],
            exclude_system_volumes: true,
            background_priority: BackgroundPriority::Lowest,
            meta_flush_minutes: 30,
            meta_flush_jitter_minutes: 7,
            completion_code: true,
        };

        assert!(policy::validate_policy(&policy).is_err());
    }

    #[test]
    fn test_empty_targets_rejected() {
        let policy = InstallPolicy {
            policy_id: "ID".to_string(),
            mode: "background".to_string(),
            targets: vec![],
            supported_filesystems: vec!["NTFS".to_string()],
            exclude_system_volumes: true,
            background_priority: BackgroundPriority::Lowest,
            meta_flush_minutes: 30,
            meta_flush_jitter_minutes: 7,
            completion_code: true,
        };

        assert!(policy::validate_policy(&policy).is_err());
    }

    #[test]
    fn test_unsupported_filesystem_refs_rejected() {
        let policy = InstallPolicy {
            policy_id: "ID".to_string(),
            mode: "background".to_string(),
            targets: vec![TargetVolume {
                volume: "D:".to_string(),
                role: "data".to_string(),
                cse: true,
            }],
            supported_filesystems: vec!["ReFS".to_string()],
            exclude_system_volumes: true,
            background_priority: BackgroundPriority::Lowest,
            meta_flush_minutes: 30,
            meta_flush_jitter_minutes: 7,
            completion_code: true,
        };

        assert!(policy::validate_policy(&policy).is_err());
    }
}
