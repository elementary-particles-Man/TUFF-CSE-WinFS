# TUFF-CSE-WinFS v1 詳細設計書

## 1. コンポーネント構成

TUFF-CSE-WinFS v1 は以下のコンポーネントで構成する。

```text
TuffCseWinFsSetup.exe
  導入用実行ファイル。
  driver package配置、policy読込、ProgramData初期化、完了コード表示を担当する。

tuffcsewinfs.sys
  Windows volume side CSE driver。
  対象volumeのread/write経路に介入し、CSE処理を実行する。

tuff-cse-winfsctl.exe
  システム部門用管理CUI。
  seal/unseal/status等を実行する。

C:\ProgramData\TUFF-CSE-WinFS\devices\
  CSE管理情報格納領域。
```

---

## 2. ディレクトリ構成

```text
C:\ProgramData\TUFF-CSE-WinFS\devices\
  BTM\
    {volume_hash}.btm
  JRN\
    {volume_hash}.jrn
  META\
    {volume_hash}.meta
  KEYS\
    {volume_hash}.sealedkey
    {volume_hash}.pairing
    {volume_hash}.policy
```

### 2.1 volume_hash

`volume_hash` は以下の材料から生成する。

```text
volume_hash = HASH(
  normalized_volume_guid,
  partition_identity,
  filesystem_type,        // NTFS, exFAT, FAT32, FAT
  install_policy_id,
  organization_salt
)
```

---

## 3. インストール処理

### 3.1 実行フロー

```text
TuffCseWinFsSetup.exe install
  ↓
管理者権限確認
  ↓
policy読込 (システム部配布コマンド引数等)
  ↓
C:\ProgramData\TUFF-CSE-WinFS\devices\ 作成
  ↓
対象volume判定 (filesystem in { NTFS, exFAT, FAT32, FAT })
  ↓
鍵生成および管理情報初期化
  ↓
完了コード表示
```

### 3.2 対象volume判定

対象volume判定条件：

```text
- filesystem in { NTFS, exFAT, FAT32, FAT }
- drive type = local
- not network drive
- not boot/system/pagefile/crashdump/hibernation volume
- not EFI/MSR/Recovery/OEM
```

---

## 4. 鍵生成詳細

### 4.1 材料

```text
base_material:
  システム部門指定の導入材料 (社員は手入力せず引数から渡される)

hw_material:
  複合HW-ID材料 (TPM, CPU, Board, Storage, Windows Identity等)

volume_material:
  volume_hash, policy_id等
```

---

## 5. BTM設計

### 5.1 役割

BTMは、対象volume上のどのCSE block/rangeがCSE済みかを示すbit mapである。

### 5.2 単位

処理単位は、対象volumeの論理セクタ長またはCSE block sizeとする。

---

## 6. CSE処理

read/write/background sealは、ファイルシステム（NTFS/exFAT/FAT32/FAT）の内部構造に依存しない **volume range処理** として実行する。

- **FS非依存部分:** ボリューム上のオフセットと長さに基づくセクタ単位のCSE封緘。
- **FS依存部分:** ボリュームマウント時のファイルシステム種別判定、および対象外ボリュームの除外ロジック。

---

## 7. 性能設計 (Performance Design)

TUFF-CSE-WinFS v1 の主なボトルネックはファイルシステム対応数ではなく、CSE_encrypt/CSE_decryptのスループットである。CSE coreはportable scalar pathを基準とし、SSE2、AVX2、AES-NI/VAES利用可能部分などの拡張命令セットdispatchを将来拡張する。最終的な高速化ではC/C++ coreおよびC-compatible ABI境界を想定する。

### 7.1 最適化ターゲット

- CSE_encrypt / CSE_decrypt
- BTM scan / comparison
- Masking (XOR, rotate, byte swap, block permutation)

### 7.2 Dispatch Paths

- **Portable Scalar:** 全環境で動作する基準実装。
- **SIMD (SSE2, AVX2):** CPU拡張命令を利用した並列処理。
- **AES-NI / VAES:** ハードウェアアクセラレーションを利用可能な環境での高速化。

### 7.3 ABI Policy

CSE coreは将来的にC++等による高度な最適化coreへ移行しやすいよう、**C-compatible ABI境界**を意識して記述する。

---

## 9. フェーズ設計 (Phases)

### 9.1 P1A: Driver Package Boundary
P1Aは、Windowsドライバ本体の実装へ入る前段として、インストーラとの境界である Driver Package の定義とスタブを実装するフェーズである。

- **Pass-through Skeleton:** `tuffcsewinfs.sys` の基盤となるWDMフィルタドライバの骨格を実装する。P1A時点ではIRPを下位デバイスへそのまま流す（pass-through）のみであり、CSE処理や暗号化は行わない。
- **INF Template:** ドライバのインストール指示書である `tuffcsewinfs.inf` の雛形を定義する。
- **Installer Validation:** `TuffCseWinFsSetup.exe` 側で、指定された Driver Package パスを検証する。P1A時点では、INFファイルのみが存在する「Source Skeleton」状態を許容し、実際のシステムへのドライバ導入（pnputil等）は行わない。
- **対象外:** ドライバの署名取得、WDKによるビルド自動化、暗号処理実装はP1B以降とする。

### 9.2 P1B: Windows Driver Build Boundary
P1Bは、P1AのSkeletonを実際にビルドするための環境定義フェーズである。

- **WDK Build Boundary:** Visual Studioソリューション (`TUFF-CSE-WinFS.sln`) およびプロジェクト (`tuffcsewinfs.vcxproj`) を追加し、手動ビルドスクリプト (`build-driver.ps1`) を提供する。
- **Installer Validation 拡張:** `DriverPackageState` に `BuildReadySource`（ビルド準備完了ソース）と `BuiltUnsigned`（未署名ビルド済み）を追加し、より詳細なパッケージ状態を識別する。
- **対象外:** 本フェーズでの成果物は署名前の `.sys` ファイル生成までであり、カタログファイル (`.cat`) の生成、Microsoft署名、`pnputil` による導入、CSE暗号処理の実装はP1C以降とする。

### 9.3 P1C: Managed Operations Contract
P1Cは、ボリュームの管理状態と運用操作を定義するフェーズである。

- **CLI Skeleton:** 管理用CUI `tuff-cse-winfsctl.exe` の骨格を実装する。
- **データ構造:** `OperationKind`, `OperationRequest`, `OperationResult`, `VolumeBindingState`, `ManagedPolicy`, `OperationJournalRecord` を定義する。
- **状態遷移 (State Transition):**
    | From | Operation | To | Status |
    | :--- | :--- | :--- | :--- |
    | Unregistered | Bind | BoundLocked | Accepted |
    | BoundLocked | Unlock | Unlocked | PendingCryptoPhase |
    | Locked | Unlock | Unlocked | PendingCryptoPhase |
    | Unlocked | Lock | Locked | PendingDriverPhase |
    | Locked / BoundLocked | Eject | CleanRemoved | PendingDriverPhase |
    | * | Status / Audit | same | Accepted |
    | * | Export / Rebind / Recover | same | Reserved |
- **Audit Journal:** 運用操作の履歴を JSON Lines 形式で `JRN\operations-{volume_hash}.jsonl` へ記録する。
- **対象外:** TPM実鍵、復号、`export`/`rebind`/`recover` の実処理、AD/KMS/HSM連携、`pnputil`実行、ドライバ署名、実I/O変換は実装しない。

### 9.4 P2A: Binding Model / Key-Material Boundary
P2Aは、TPMやデバイス固有情報を用いたバインディングの「モデル」と「鍵材料境界」を定義するフェーズである。

- **データ構造:** `BindingMaterialKind`, `BindingProfile`, `BindingPolicy`, `BindingDescriptor`, `KeyMaterialClass`, `KeyMaterialRef`, `KeyDerivationPlan` を定義する。
- **制約事項:** `BindingPolicy` と `ManagedPolicy` を明確に分離する。
- **秘匿化:** 生のTPM識別子、ホストID、デバイスUUID等の生データ (`raw HW-ID` 等) はメモリ上（`BindingInputSnapshot`）にのみ存在させ、永続化・ログ出力・表示はソルト化されたフィンガープリントに限定する。
- **機能拡張:** `tuff-cse-winfsctl bind` コマンドに `--plan-only` フラグを追加し、指定された `BindingPolicy` に基づく `BindingDescriptor` と `KeyDerivationPlan` を（モックデータを用いて）生成・表示する。
- **対象外:** TPM実API呼び出し、Windows CNG/DPAPIの実呼び出し、実鍵生成、復号、実ドライバI/O制御などは実装しない。

### 9.5 P2B: Single-Host Managed State
P2Bは、単一ホスト上でのボリューム管理状態を永続化し、CLIと連動させるフェーズである。

- **Persistence:** `BindingStore` を実装し、`BindingDescriptor`, `KeyDerivationPlan`, `VolumeRuntimeState`, `RuntimeSession` を `ProgramData` 配下へ永続化する。
- **Runtime Session:** `Unlocked` 状態のプレースホルダとして `RuntimeSession` を定義し、メモリ上の鍵材料（P2B時点ではスタブ）との紐付けを準備する。
- **状態管理:** `tuff-cse-winfsctl` の `status`, `bind`, `unlock`, `lock`, `eject` を実際の永続化状態と連動させる。

### 9.6 P2C: Runtime Zeroize / Journal Recovery
P2Cは、稼働中のシークレット保護と、異常終了時からの復旧を定義するフェーズである。

- **Secure Runtime:** `zeroize` クレートを用い、Drop時にメモリをゼロ消去する `SecureRuntimeBuffer` を実装する。P2C時点ではテスト用のプレースホルダを扱う。
- **Transactional Journaling:** オペレーションジャーナルに `Begin`, `Commit`, `Abort`, `Recovery` フェーズを追加し、状態遷移の原子性を保証する。
- **Recovery Logic:** 起動時やStatus確認時に「BeginしたままCommitされていない操作」や「期限切れのセッション」を検出し、安全側（Locked または RecoveryRequired）へ強制遷移させる。
- **機能拡張:** `status --recover-stale` オプションを追加し、手動でのリカバリ実行を可能にする。

### 9.7 P3A: Managed Export Manifest Boundary
P3Aは、ボリュームの外部搬出（Export）に向けたマニフェストと計画を定義するフェーズである。

- **用語の分離:** `unlock`（現地利用）、`export`（搬出用再封緘）、`eject`（安全取り外し）、`rebind`（所有境界移動）の意味を明確に分離する。
- **データ構造:** `ExportPolicy`, `ExportRecipient`, `ExportPlan`, `ExportManifest`, `ExportStatus` を定義する。
- **Export Flow:**
    1.  `tuff-cse-winfsctl export` コマンドにより、`ExportPlan` を生成する。
    2.  指定された `recipient_id` と `recipient_key_fingerprint` を含む `ExportManifest` を `META/exports` 配下へ保存する。
    3.  `JRN` へ `EXPORT` の `Begin` / `Commit` を記録する。
- **秘匿化:** 搬出先（recipient）の秘密鍵や、実データの平文、再封緘用の中間鍵などは一切扱わず、マニフェストには検証用の識別子のみを記録する。
- **対象外:** 実データのコピー、再封緘処理、搬出先公開鍵を用いた暗号化、`rebind`/`recover` の実処理などはP3B/P3C以降とする。

### 9.8 P3B: Recovery Key / Rebind Model Boundary
P3Bは、紛失・故障時からのリカバリと、所有ホストの明示的な移転（Rebind）のモデルを定義するフェーズである。

- **用語の定義:** `recover` は失われた利用境界（TPM等）を安全に復帰させる計画、`rebind` は所有ホストを別のホストへ切り替えるためのマニフェスト生成と定義する。
- **データ構造:** `RecoveryPolicy`, `RecoveryKeyDescriptor`, `RecoveryPlan`, `RebindPolicy`, `RebindPlan`, `RebindManifest` を定義する。
- **Recovery Flow:**
    1.  `tuff-cse-winfsctl recover` コマンドにより、提供されたリカバリキー・フィンガープリントに基づく `RecoveryKeyDescriptor` と `RecoveryPlan` を生成する。
    2.  `KEYS/recovery` および `KEYS/recovery-plans` 配下へ記録する。
- **Rebind Flow:**
    1.  `tuff-cse-winfsctl rebind` コマンドにより、新しいホストのフィンガープリントを指定した `RebindPlan` と `RebindManifest` を生成する。
    2.  `KEYS/rebind-plans` および `META/rebind` 配下へ記録する。
- **秘匿化:** 生のリカバリキー、ホスト固有識別子、実鍵データは一切永続化せず、フィンガープリントと計画IDのみを記録する。
- **対象外:** 実復号・鍵復元、Binding Descriptorの置換、実所有権移転処理、AD/KMS/HSM/Quorum連携はP3C/P5/P6以降とする。

### 9.9 P3C: Manual Export/Rebind/Recover State Implementation
P3Cは、生成された各計画（Export/Rebind/Recover）に対して手動確認（Manual Confirmation）を行い、管理上の完了または中止を記録するフェーズである。

- **用語の定義:** `manual_complete` は計画を手動確認により完了扱いへ進める操作、`manual_cancel` は中止扱いへ進める操作。
- **データ構造:** `PlanLifecycleStatus` (Planned, ManualConfirmationRequired, ManualConfirmed, Completed, Cancelled, Rejected), `ManualFlowRecord` を定義。
- **Confirmation Token:** 誤操作防止用のトークン。生データは保存せず、ソルトなし（または固定ソルト相当）のSHA-256ハッシュのみを永続化する。
- **Manual Audit Journal:** `JRN/manual/` 配下に各計画の完了・中止記録を個別のJSONファイルとして保存する。
- **状態遷移:**
    - `Planned` → `ManualConfirmationRequired` (生成時オプション)
    - `ManualConfirmationRequired` → `ManualConfirmed` → `Completed` (完了操作時)
    - `Planned` / `ManualConfirmationRequired` → `Cancelled` (中止操作時)
- **秘匿化:** ジャーナルおよびフロー記録に生の確認トークン、鍵データ、ホスト識別子を一切含めない。
- **対象外:** 実データコピー、再封緘、実復号、Binding Descriptorの書き換え、Local Admin Approvalの実装（P4）、署名付きジャーナル（P4）、AD連携（P5）は次フェーズ以降とする。

### 9.10 P4A: Local Policy / Local Admin Approval Boundary
P4Aは、ローカル管理者承認のモデルを定義し、承認要求と承認判断を管理情報として記録するための境界を確立するフェーズである。

- **用語の定義:** `LocalOperationClass` (Bind, Unlock, Lock, Eject, Export, Recover, Rebind, ManualComplete, ManualCancel) を定義。
- **データ構造:** `LocalPolicy`, `LocalAdminPrincipal`, `LocalApprovalRequest`, `LocalApprovalDecision` を定義。
- **Approval Flow:**
    1.  `tuff-cse-winfsctl approval request` により、特定の操作に対する承認要求を `JRN/approvals/` へ記録。
    2.  `tuff-cse-winfsctl approval approve` / `deny` により、管理者フィンガープリントを付与した承認判断を記録。
- **ポリシー判定:** `LocalPolicy` に基づき、エクスポートやリカバリ等の重要な操作に対してローカル管理者承認を要求するかを判定する境界を実装。
- **秘匿化:** 生のWindows管理者SID、アカウント情報、パスワード、認証情報は一切永続化・記録せず、フィンガープリントのみを使用。
- **対象外:** 実際のWindows管理者特権の検証 (SID照合)、UAC (User Account Control) との連動、署名付き監査ログの実装はP4B/P4C以降とする。

## 10. P6A Enterprise Recovery Authority Boundary

P6AはEnterprise KMS/HSM/Quorum Recovery の最初の境界である。ここでは live KMS/HSM 接続、PKCS#11 実接続、cloud KMS SDK、鍵復元、CSE 暗号処理、TPM 実API、driver I/O を追加しない。

### 10.1 Data Model

- `EnterpriseAuthorityPolicy`
- `EnterpriseQuorumPolicy`
- `EnterpriseRecoveryRequest`
- `EnterpriseRecoveryDecision`
- `EnterpriseRecoveryEnforcer`

Authority material は fingerprint / policy id / hash のみを持つ。Quorum は fingerprint 済み承認者、閾値、decision hash で判定する。Recovery decision は operation kind、volume hash、domain recovery ids、policy ids、approver fingerprints、status、validity window を保持する。

### 10.2 Enforcement Order

| Step | Gate |
| :--- | :--- |
| 1 | Domain policy evaluate |
| 2 | Offline snapshot verify |
| 3 | DomainApprovalEnforcer |
| 4 | DomainRecoveryEnforcer |
| 5 | EnterpriseRecoveryEnforcer |
| 6 | P4B LocalApprovalEnforcer |
| 7 | P3C manual confirmation token |
| 8 | Existing operation path |

Enterprise gate は P5C の後段に置くが、P5C/P5B/P4B/P3C を代替しない。Enterprise metadata は P4C signed canonical payload に含め、改ざんは audit-signing verify で検出する。

### 10.3 Provider Boundary

- `ImportedOfflineAuthority` / `ImportedOfflineDecision` はオフラインで取り込んだメタデータを表す。
- `ReservedKmsProvider`, `ReservedHsmProvider`, `ReservedCloudKms`, `ReservedPkcs11Hsm` は型として予約するが、P6A では実接続しない。
- raw authority、raw principal、KMS secret、HSM secret、key material は保存・表示・journal しない。

### 10.4 CLI Boundary

- `enterprise-authority import|status|evaluate`
- `enterprise-quorum import|status|evaluate`
- `enterprise-recovery request|import-decision|dev-approve|dev-deny|status|evaluate`

`TUFF_CSE_WINFS_ALLOW_DEV_ENTERPRISE_RECOVERY=1` がない dev approval / deny は拒否する。

## 11. P6B Enterprise Provider Adapter Boundary

P6BはEnterprise Provider Adapter の最初の境界である。ここでは live KMS/HSM 接続、Cloud KMS SDK、PKCS#11 実接続、TPM 実API、driver I/O、鍵復元処理を追加しない。Provider は offline policy / attestation / health metadata として扱う。

### 11.1 Data Model

- `EnterpriseProviderPolicy`
- `EnterpriseProviderAttestationSummary`
- `EnterpriseProviderEnforcer`
- `EnterpriseProviderKind`
- `EnterpriseProviderCapability`
- `EnterpriseProviderHealth`

Provider material は provider id / attestation id / attestation hash / policy hash のみを持つ。Provider kind は `ImportedOfflineProvider` と reserved kinds を分けて扱い、reserved kinds は実接続なしの型予約に留める。

### 11.2 Enforcement Order

| Step | Gate |
| :--- | :--- |
| 1 | Domain policy evaluate |
| 2 | Offline snapshot verify |
| 3 | DomainApprovalEnforcer |
| 4 | DomainRecoveryEnforcer |
| 5 | EnterpriseRecoveryEnforcer |
| 6 | EnterpriseProviderEnforcer |
| 7 | P4B LocalApprovalEnforcer |
| 8 | P3C manual confirmation token |
| 9 | Existing operation path |

P6B は P6A の後段で provider adapter boundary を追加するが、P6A/P5C/P5B/P4B/P3C を代替しない。Enterprise provider metadata は P4C signed canonical payload に含め、改ざんは audit-signing verify で検出する。

### 11.3 CLI Boundary

- `enterprise-provider import`
- `enterprise-provider import-attestation`
- `enterprise-provider status`
- `enterprise-provider evaluate`

Provider credential / API key / client secret / token / private key / KMS secret / HSM secret / raw TPM は保存・表示・journal しない。

---

## 12. P6C Enterprise Provider Lifecycle Boundary

P6Cは、P6Bで定義されたEnterprise Provider Adapter Boundaryの上に、provider lifecycle / revocation / rotation / attestation renewal boundaryを実装する。本フェーズにおいても、live KMS/HSM接続や鍵復元は行わず、offline/imported lifecycle eventとsigned journalによって、revoked/superseded/rotated/expired providerがenforcement gateを通過できないことを保証する。

### 12.1 Data Model

- `EnterpriseProviderLifecycleEventId`
- `EnterpriseProviderGeneration`
- `EnterpriseProviderLifecycleState` (`Active`, `PendingRotation`, `Superseded`, `Revoked`, `Expired`, `ReservedLiveRefreshRequired`)
- `EnterpriseProviderLifecycleEventKind` (`ImportedActivation`, `ImportedRevocation`, `ImportedRotationPlan`, `ImportedRotationComplete`, `ImportedAttestationRenewal`, `ReservedLiveRefresh`)
- `EnterpriseProviderRevocationReason` (`CompromisedReserved`, `PolicySuperseded`, `AuthorityRevoked`, `AttestationExpired`, `AdministrativeRevocation`, `ReservedLiveProviderFailure`)
- `EnterpriseProviderLifecycleEvent`
- `EnterpriseProviderRotationPlan`
- `EnterpriseProviderRotationDecision`

### 12.2 Enforcement Order

P6Cにおける enforcer 順序は以下の通り定義される。

| Step | Gate |
| :--- | :--- |
| 1 | Domain policy evaluate |
| 2 | Offline snapshot verify |
| 3 | DomainApprovalEnforcer |
| 4 | DomainRecoveryEnforcer |
| 5 | EnterpriseProviderLifecycleEnforcer (追加) |
| 6 | EnterpriseProviderEnforcer |
| 7 | EnterpriseRecoveryEnforcer |
| 8 | P4B LocalApprovalEnforcer |
| 9 | P3C manual confirmation token |
| 10 | Existing operation path |

### 12.3 Verification & Safety Rules

1. **Active State Verification**: provider が Active 以外の状態（Revoked, Superseded, Expired等）である場合、enforcer は `Rejected` を返す。
2. **Generation Match**: `OperationRequest` および `EnterpriseRecoveryDecision` の provider generation が、現在の最新 lifecycle event の active generation と一致しない場合、拒否する。
3. **Rotation Gate**: Rotation Complete 前は新 generation は使用できず、旧 generation のみ通す。Rotation Complete 後は旧 generation の使用は拒否され、新 generation のみ通過を許可する。
4. **No Secrets in Logs**: provider credential, KMS/HSM secret, API key, client secret, private key, token などの秘匿情報は、METAファイル・Journalレコード・stdout/stderr出力に一切含まれないことを保証する。

### 12.4 CLI Subcommands

- `enterprise-provider lifecycle import-event`
- `enterprise-provider lifecycle status`
- `enterprise-provider lifecycle revoke`
- `enterprise-provider lifecycle rotation-plan`
- `enterprise-provider lifecycle rotate-complete`
- `enterprise-provider lifecycle renew-attestation`

※ 開発用 lifecycle 操作には環境変数 `TUFF_CSE_WINFS_ALLOW_DEV_PROVIDER_LIFECYCLE=1` の指定を必須とする。

---

## 13. 開発・検証環境 (CI/CD)

### 13.1 P0.5 クロスプラットフォームCI
専用インストーラ骨格の安定性を維持するため、GitHub Actions による継続的インテグレーション（CI）を実施する。

- **対象プラットフォーム:** Ubuntu, Windows
- **検証項目:**
    - 静的解析 (`cargo fmt`)
    - ユニットテスト (`cargo test`)
    - インストーラ論理検証 (`install --dry-run`)
    - ポリシー整合性検証 (`verify --policy`)

*※注意: カーネルドライバのビルド・署名、および特権が必要なハードウェア操作は本CIフェーズの対象外である。*
