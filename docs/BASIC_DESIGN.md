# TUFF-CSE-WinFS v1 基本設計書

## 1. 目的

TUFF-CSE-WinFS v1 は、金融機関・行政機関・重要インフラ等の業務端末において、ローカル接続された通常データボリューム（NTFS / exFAT / FAT32 / FAT）上のデータを、利用者操作を極力増やさずにCSE封緘するための Windows 向け保護ドライバ／導入パッケージである。

本設計の目的は、USBメモリ、外付けSSD、業務用ローカルデータ領域等に平文データが残留・搬出されるリスクを低減することである。

TUFF-CSE-WinFS v1 は、導入組織のシステム部門、または公的検証ルートを通じて、署名・検証・配布・運用される業務導入型ソフトウェアとして扱う。

---

## 2. 導入想定

想定する導入経路は以下とする。

```text
財務省 / デジタル庁 / 所管機関
  ↓
Microsoft署名・検証
  ↓
金融機関・行政機関・関連組織のシステム部門
  ↓
業務端末へ配布
  ↓
社員・職員は指定コマンドを貼り付けて実行
```

導入しない組織は使用しない。  
TUFF-CSE-WinFS v1 は強制配布ソフトではなく、導入組織が必要と判断した場合に利用する。

---

## 3. 責任分界

### 3.1 開発側の責任範囲

```text
- TUFF-CSE-WinFS v1 基本設計
- TUFF-CSE-WinFS v1 詳細設計
- ドライバ本体 (tuffcsewinfs.sys)
- インストーラ / 導入補助ツール (TuffCseWinFsSetup.exe)
- 管理CUI (tuff-cse-winfsctl.exe)
- 導入マニュアル
- ドライバ署名取得手順
- テスト手順
- 既知制約
```

### 3.2 導入組織側の責任範囲

```text
- Microsoft署名取得
- 検証環境での動作確認
- 社内配布判断
- 社員・職員向けメール作成
- 実行コマンドライン作成
- 対象ボリューム指定
- 基本キー / policy管理
- 完了コード照合
- 運用責任
```

---

## 4. 基本方針

TUFF-CSE-WinFS v1 は以下を基本方針とする。

```text
- Windows起動領域を触らない
- EFI / MSR / Recovery / OEM / boot / system 領域を対象外にする
- 物理ディスク全体を対象にしない
- 対応ファイルシステム上の通常データボリュームのみ対象にする
- ネットワークドライブは対象外にする
- パーティションリサイズはしない
- MS予約領域を借りない
- デバイス末尾LBAへ直書きしない
- 管理情報は C:\ProgramData\TUFF-CSE-WinFS\devices\ 配下へ置く
- 社員・職員に選択作業（対象ボリューム選択、AnchorProvider選択等）をさせない
- 社員・職員にbasekeyを手入力させない
```

---

## 5. 対象範囲

### 5.1 対象 (Formal Scope)

TUFF-CSE-WinFS v1 は、Windows上のローカル接続通常データボリュームを対象に、NTFS / exFAT / FAT32 / FAT を横断してCSE封緘を提供する。CSE処理はファイルシステム内部構造ではなく、対象volumeのread/write rangeに対して行う。ReFS、RAW、ネットワークドライブ、Windows起動・回復・予約領域は対象外とする。

```text
- ローカル接続された通常データボリューム
- 対応ファイルシステム: NTFS, exFAT, FAT32, FAT
- システム部門が明示的に指定したドライブレター
- boot/system/pagefile/crashdump/hibernation ではないボリューム
```

### 5.2 対象外 (Out of Scope)

```text
- C: 等のWindows起動ボリューム
- boot/system/pagefile/crashdump/hibernation対象ボリューム
- EFI System Partition
- Microsoft Reserved Partition (MSR)
- Recovery Partition
- OEM Partition
- ReFS
- RAW
- ネットワークドライブ
- BitLocker等により仕様上競合するボリューム
```

---

## 6. 管理情報配置 (ProgramData Configuration)

TUFF-CSE-WinFS v1 の管理情報は C:\ProgramData\TUFF-CSE-WinFS\devices\ 配下に固定する。BTM、JRN、META、KEYSをこの配下に配置し、対象volume側にraw LBA anchorや必須.cse anchorを作成しない。

```text
C:\ProgramData\TUFF-CSE-WinFS\devices\
  BTM\
  JRN\
  META\
  KEYS\
```

---

## 7. 鍵管理方針

TUFF-CSE-WinFS v1 では、以下の鍵構造を採用する。

```text
MK:
  端末側の複合HW-ID、導入パラメータ、salt等から生成される主鍵。

TK:
  対象volume認証用のtoken key。

PK:
  対象volume pairing用のpairing key。

MK-Device:
  対象volumeごとに生成されるdevice binding key。
```

---

## 8. HW-ID方針

HW-IDは単一情報に依存しない。複合HW-ID材料（TPM、CPU、Board、Storage、Windows Identity等）を組み合わせてMK導出seedとして使用する。

---

## 9. 導入方式 (Employee Flow)

社員・職員はbasekeyを手入力しない。システム部門から配布された実行ファイル一式と、メール本文に記載された実行コマンドラインを使用し、管理者ターミナルへ貼り付けて実行する。完了後、表示された完了コード1行を返信する。

社員・職員の操作は以下のみ。

```text
1. 配布された実行ファイル一式を展開する
2. 管理者ターミナルを開く
3. システム部メールに記載された実行コマンドラインをそのまま貼り付けて実行する
4. 表示された完了コード1行をコピーして返信する
```

社員が basekey、対象volume、AnchorProvider 等を自分で判断・入力する必要はない。

---

## 10. 完了コード

インストール完了時、TuffCseWinFsSetup.exe はターミナルに1行の完了コードを表示する。社員はこの1行をそのまま返信する。

---

## 11. CSE処理方式

CSE処理単位は、対象volumeの論理セクタ長またはCSE block sizeとする。

---

## 12. 性能方針 (Performance Axis)

TUFF-CSE-WinFS v1 の主なボトルネックはファイルシステム対応数ではなく、CSE_encrypt/CSE_decryptのスループットである。CSE coreはportable scalar pathを基準とし、SSE2、AVX2、AES-NI/VAES利用可能部分などの拡張命令セットdispatchを将来拡張する。最終的な高速化ではC/C++ coreおよびC-compatible ABI境界を想定する。

---

## 13. 初期版でやらないこと (Removed Design Items)

```text
- AnchorProvider選択
- raw LBA anchor (物理ディスク末尾LBA利用等)
- 対象volumeのパーティションリサイズ
- MSR/EFI/Recovery/OEM領域利用
- 対象volume内への.cse anchor必須化
- ネットワークドライブ対応
- 社員によるbasekey手入力
- 社員による対象volume選択
- CSE本文へのMAC/tag追加
```
