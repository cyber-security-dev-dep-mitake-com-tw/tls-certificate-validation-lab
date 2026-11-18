# TLS 憑證真偽與冒用偵測實驗室

這是一個封閉網路裡的雙服務實驗室。SVC1 產生測試憑證與握手，SVC2 只看握手、憑證與授權政策，自己做出判決。

密碼學結論只有三種風險：`INVALID_CERTIFICATE`、`WEAK_CRYPTOGRAPHY`、`VALID_BUT_UNAUTHORIZED`。握手失敗可以是預期的 `HANDSHAKE_REJECTED`，此時不強迫給風險分類。

## 語言

- **Rust**：憑證、TLS 1.1／1.2／1.3、采集器、檢測器、授權政策、地面真相、REA／LLM 介面。
- **Zig**：`possession_failed`。只收公開憑證，讀完 ClientHello 後送出致命 alert，沒有簽名金鑰。
- **Julia**：合成弱參數，以及只看公開模數的檢測。`analyze.jl` 不回傳因數。`oracle.jl` 只接受 `origin=synthetic` 且不超過 512 bit，回應不帶回質數或私鑰。
- 既有的 `src/*.py` 不再被 Compose 啟動，也不會被新路徑 import。

## 快速啟動

```bash
cp .env.example .env
# Linux/macOS：把 HOST_UID、HOST_GID 設成 id -u、id -g
docker compose up --build --abort-on-container-exit --exit-code-from svc2
cat reports/report.json
docker compose down
```

首次建置會編譯 Rust、Zig，並下載 Julia runtime。執行時容器網路是 `internal: true`，不對宿主機發布連接埠。

宿主機上的唯讀采集（預設安全等級，不進 oracle）：

```bash
cargo run --manifest-path rust/Cargo.toml -p harvester -- --host app.example.com --out baseline
```

若簽發者看起來像 CDN，metadata 會標記 `possible_cdn_edge`。這只是提示。抓到的通常是邊緣憑證，不是源站憑證。

## 風險與情境

| 情境 | SVC2 預期 |
|---|---|
| 授權 Lab CA | `VALID` |
| 自簽、未授權 CA、SAN、時間、EKU | `INVALID_CERTIFICATE` |
| 受信任 CA 但 SPKI 不在授權清單 | `KEY_NOT_APPROVED` / `VALID_BUT_UNAUTHORIZED` |
| 複製憑證但沒有私鑰 | `HANDSHAKE_REJECTED`；離線鏈驗證仍可成功 |
| 同一張有效憑證出現在未授權埠 | `UNAUTHORIZED_ENDPOINT` / `VALID_BUT_UNAUTHORIZED` |
| 512-bit RSA、過大公開指數、ROCA 指紋、共享質因數、SHA-1、重複 ECDSA `r` | `WEAK_CRYPTOGRAPHY` |

TLS 1.1 的協定政策一律是 `DEPRECATED`。512-bit RSA 在 TLS 1.3 上預期 `HANDSHAKE_REJECTED`，因為協定拒絕這把認證金鑰。SHA-1 若仍完成握手，則判為 `WEAK_SIGNATURE`。Fermat 夾具的公開結論是金鑰過短；質數是否過近只由 oracle 在合成樣本上自檢，不進 SVC2。

弱金鑰實驗只處理實驗室自己產生、不超過 512 bit 的參數。Batch GCD 跳過 1024 bit 以上的模數，而且不輸出公因數。報告不包含私鑰或質因數。

## REA／LLM

`DeterministicRea` 依公開特徵推薦檢測器，並把既有判決映射成威脅事件。`LlmProvider` 預設關閉。模型回應若多出私鑰或判決欄位會被拒絕；即使內容與判決衝突，`certificate_status` 與 `risk_class` 也不會被改寫。

## 尚未實作

OCSP／CRL、即時 CT 查詢、CAA。采集器只記錄憑證裡內嵌的 SCT，不向外部 CT log 發請求。

MD5 簽章沒有另外打開函式庫開關。OpenSSL 若拒絕，就不做 MD5 夾具。

## 限制

- 不要把正式環境私鑰放進 SVC1。
- `SECLEVEL=0` 只用在實驗室內部連線，讓弱憑證仍能完成握手，再由檢測器自己判定。
- 標準 PKI 驗證成功，不代表這台伺服器是你授權的。未授權使用要靠 SPKI 清單、簽發紀錄與端點綁定。
- 這個專案不是公開 CA 偽造器、流量攔截器或通用因數分解工具。

參考：[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) · [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) · [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) · [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525)
