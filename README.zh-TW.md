# AgenticDef

[![CI](https://github.com/trionnemesis/AgenticDef/actions/workflows/ci.yml/badge.svg)](https://github.com/trionnemesis/AgenticDef/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> 受政策與預算限制、唯讀且可追溯證據的 AI 安全調查 runtime。模型提出調查動作；確定性程式碼決定哪些工具、資源、呼叫與結論可以被接受。

🌐 [GitHub Pages 簡介](https://trionnemesis.github.io/AgenticDef/) · [English](README.md) · [架構](docs/architecture.md) · [驗收證據](docs/verification.md) · [下一階段規劃](docs/roadmap.md) · [Releases](https://github.com/trionnemesis/AgenticDef/releases)

## 為什麼需要

沒有事件時，不必持續呼叫模型。事件通過驗證後，啟動一次有上限的調查，在證據足夠或預算耗盡時結束。真正需要驗證的是：惡意證據能否取得權限、模型能否擴張能力，以及調查失敗是否被誤判為無害。

**v0.2 是本機可執行的核心驗證。** 不包含 GKE 部署、常駐事件監聽、基礎設施修復或生產環境操作。離線 replay 使用確定性假模型，不能當成真實 AI 偵測準確率。

## 能做什麼

| 能力 | 實際行為 |
|---|---|
| 契約驗證 | JSON Schema 驗證事件、政策、動作、證據、結果與 replay 驗收預期（`expected.yaml`） |
| 權限控制 | 工具白名單與精確資源範圍；不信任模型授權 |
| 預算限制 | 執行時間、模型呼叫、工具呼叫、證據數量皆有上限 |
| 唯讀工具 | 僅四項：變更事件、版本化 RBAC、主體綁定、核准紀錄 |
| 證據 grounding | 發現必須引用已存在的證據；定論需要完整五次相關讀取 |
| 冪等處理 | `event_id + policy_version` 原子取得工作權；重送不重複執行；claim 競爭落敗時與既有紀錄走相同的身分與結果驗證 |
| 可重播驗收 | S01–S08、audit、持久化結果、結構式斷言 |
| 單一模型 adapter | Anthropic API；離線 HTTP 與核心整合測試，未實測真實 API |

## 快速開始

需要 Python 3.11+。首次安裝依賴後，replay 本身不需要網路、API key、GCP 憑證或叢集。

```bash
git clone https://github.com/trionnemesis/AgenticDef.git
cd AgenticDef
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m pytest -q
replay scenarios --all --output results/first-run
```

`.[dev]` 已足以執行完整離線測試，包含 mock HTTP 的模型 adapter 測試。Windows 啟用虛擬環境使用 `.venv\Scripts\Activate.ps1`。未指定 `--output` 時建立新的暫存目錄；重用既有輸出目錄會回傳原本的終態結果，不會重新調查。

每個調查的 `record.json` 包含事件與政策雜湊、來源標記、稽核順序、證據、原始內容、結果與終態。Wheel 內含 schema；情境資料位於 repo 與 source archive，從別的目錄使用 wheel 時需指定情境路徑。

## 八個驗收情境

| 情境 | 預期結果 |
|---|---|
| S01 未核准的權限提升 | `confirmed_suspicious` |
| S02 已核准的高權限變更 | `likely_benign` |
| S03 必要證據不存在 | `insufficient_evidence` |
| S04 惡意證據搭配模擬越權要求 | `investigation_failed`；工具執行前拒絕 |
| S05 重複事件 | 回傳原結果，不增加模型或工具工作 |
| S06 預算耗盡 | `inconclusive`；不得繼續呼叫 |
| S07 未註冊工具 | `investigation_failed` |
| S08 捏造證據 ID | `investigation_failed`；不接受該發現 |

「調查安全地失敗」可以是「回歸情境通過」。Replay 結束碼 `0` 代表驗收斷言符合預期，**不代表環境安全**；`1` 代表斷言失敗，`2` 代表設定或持久化錯誤，包括 `expected.yaml` 不符 schema（在建立模型、工具或紀錄之前檢查）。

## 模型 API 模式

```bash
pip install -e '.[anthropic]'
# 在本機環境設定 ANTHROPIC_API_KEY
agenticdef scenarios/S01 --provider anthropic --model YOUR_AVAILABLE_MODEL_ID
```

只有這個明確選用的模式才會呼叫付費 API。證據仍然是合成資料，並非 GKE。請依模型延遲調整受信任政策的時限；變更政策時更新 `policy_version`。模型 ID 由操作者指定，不猜測帳號可用型號。

此模式結束碼：`0` 低風險、`1` 確認可疑、`2` 未能判定或失敗。不能把離線回歸結果包裝成真實 API 測試結果。

## 信任邊界

模型拿不到可修改的政策或預算。所有工具要求必須經過 schema、白名單與 scope 檢查；不存在 shell、kubectl、任意 HTTP/SQL 或第五個工具。寫入範圍只有本機的證據、稽核與結果。

所有 provider 呼叫，包括最後的結果生成，都會先保留預算。任何硬上限耗盡後，不能再呼叫其他種類的工具或模型。非同步 adapter 必須配合取消；惡意、阻塞的 Python 外掛不屬於此可信 adapter 的威脅模型。

Grounding 證明「引用存在」，不保證語意正確；語意另由情境測試驗證。中斷後遺留的 running claim 不會自動恢復，以避免重複放大工作。

## 開發與狀態

```bash
pip install -r requirements-dev.lock
pip install --no-deps -e .
make check
make replay
make build
```

目前原始碼版本是 experimental v0.2.1；**已發布的版本只有 [v0.2.0](https://github.com/trionnemesis/AgenticDef/releases/tag/v0.2.0)**，是否發布 v0.2.1 由維護者另行決定。v0.2.0 之後原始碼已修正：

* evidence adapter 缺少必要可呼叫方法 → 保存失敗終態（[修補說明](docs/release-v0.2.1.md)、[#2](https://github.com/trionnemesis/AgenticDef/issues/2) E3）；
* claim 競爭落敗時略過重送身分與結果驗證（[#4](https://github.com/trionnemesis/AgenticDef/issues/4)）；
* 格式錯誤的 `expected.yaml` 可能讓驗收空洞通過（[#5](https://github.com/trionnemesis/AgenticDef/issues/5)）；
* 若 v0.2.0 不存在，0.2.1 套件可能被掛到 `v0.2.0`（[#6](https://github.com/trionnemesis/AgenticDef/issues/6)）；
* 只安裝 `.[dev]` 無法收集離線測試（[#7](https://github.com/trionnemesis/AgenticDef/issues/7)）。

M0–M5 已完成本機 replay 與回歸；M6 已實作並通過離線 HTTP 與共享核心測試，包括以 mock HTTP transport 完整執行 S01/S02、由情境評估器評分，以及反向判定的負向控制（[#8](https://github.com/trionnemesis/AgenticDef/issues/8)）。這些是腳本化回應；真實 API 呼叫尚未實測，模型準確率未量測。沒有 live GKE adapter、雲端 dispatcher、remediation、多 agent 或生產 UI。

CI 在 Python 3.11/3.12 執行完整測試與 replay、建置套件，並在 checkout 之外以 wheel 重跑 S01–S08；另有獨立 job 在乾淨環境只安裝 `.[dev]` 執行離線測試。通過後 `main` 才開放 Pages 與首次版本發布：只有在 GitHub 確認 `v0.2.0` 不存在**且**套件版本正好是 `0.2.0` 時才會建立，其他狀態（含查詢結果不確定）一律 fail closed。既有 Release 不會覆寫。完整狀態請看 [驗收紀錄](docs/verification.md)，架構選擇請看 [ADR](docs/adr-0001.md)。

## 下一階段

詳見 [docs/roadmap.md](docs/roadmap.md)。摘要：

1. **收斂 v0.2.x**：#8（只加測試）已實作；關閉 [#9](https://github.com/trionnemesis/AgenticDef/issues/9) 追蹤、另行決定是否發布 v0.2.1。不新增能力，不改 runtime 語意。
2. **v0.3 前的決策關卡**：SPEC 允許下一版加入一個 live 唯讀 GCP/GKE 證據 adapter，但須先由人回答 [#2](https://github.com/trionnemesis/AgenticDef/issues/2) section D 的問題（能力是否凍結、事件類型、live 證據大小、語意正確性歸屬、crashed claim 回收、發布權限）。目前沒有已核准的 v0.3 設計。

Remediation、多 agent 編排、通用執行工具與生產部署仍不在範圍內。

## 貢獻與授權

依 [AGENTS.md](AGENTS.md) 工作，行為變更需附回歸測試。請勿在公開 issue 貼上憑證或私人事件資料。

[MIT License](LICENSE)
