# TLS Certificate Forgery & Validation Lab（繁體中文）

這是一個**內部雙服務、封閉網路、可重現的 TLS 憑證驗證實驗室**，用於訓練 SVC2 判斷 TLS 1.1 / 1.2 / 1.3 的憑證信任與協定安全性。

> 請先區分：TLS 1.1 / 1.2 / 1.3 是**握手協定版本**，不是三種不同的 X.509 憑證。憑證是否授權、是否通過驗證，以及協定是否被允許是三個不同的判斷。

## 系統架構

- **SVC1 — Fixture Server**：啟動 24 個內部 TCP/TLS 端點（8 類憑證 × 3 個 TLS 版本），建立授權 Lab Root CA、未授權 Rogue Root CA、七類測試憑證。所有私鑰僅留在 SVC1 容器。
- **SVC2 — Independent Validator**：透過 OpenSSL 進行嚴格握手，取得憑證、驗證信任鏈、SAN、有效期限、EKU，以及明確配置的 SPKI 授權清單。其核心 `detector.py` 不會收到測試案例答案。
- **Evaluation Harness**：`run_matrix.py` 將 SVC2 結果和 Ground Truth 比對，輸出 JSON、CSV、TP/TN/FP/FN 及原因分類準確率。評估器持有標籤，但不傳入判斷函式。

網路 `lab_internal` 設定 `internal: true`，所有 SVC1 port 都**不對宿主機及公網發布**，也不會安裝 Root CA 到宿主 OS。Linux/macOS/Windows Docker Desktop 均可使用 Compose（Linux 綁定輸出目錄須注意 UID/GID）。

## 快速啟動

```bash
# 1. 解壓縮 ZIP 後，在專案根目錄操作
cp .env.example .env

# 2. 可把 LAB_DOMAIN 改成自己持有的測試子網域
#    例如 LAB_DOMAIN=tls-lab.example.com
#    無需新增公網 DNS 記錄。

# 3. 在 Linux/macOS 把 .env 中的 HOST_UID/HOST_GID 設成 id -u、id -g 的數值。
#    Windows Docker Desktop 可先保留預設值。

# 4. 啟動 SVC1，等健康檢查通過，讓 SVC2 自動執行 24 個測試
docker compose up --build --abort-on-container-exit --exit-code-from svc2

# 5. 取得驗證結果
cat reports/report.json
cat reports/report.csv

# 6. 關閉實驗室
docker compose down
```

> Docker build 首次需要連線下載 Python Base Image、系統 OpenSSL 和 `cryptography` 套件；執行測試時不需要連線到公網。這個環境沒有在本回覆中執行過 Docker Compose 整合建置，但已在本機 Python/OpenSSL 環境實際完成全部 24 個 TLS 握手測試。

## 測試情境矩陣

| 情境 | TLS 1.1 port | TLS 1.2 port | TLS 1.3 port | SVC2 預期 |
|---|---:|---:|---:|---|
| 授權 Lab CA 憑證 | 15111 | 15112 | 15113 | `VALID` |
| Self-signed | 15211 | 15212 | 15213 | `SELF_SIGNED` |
| 未授權 Rogue CA | 15311 | 15312 | 15313 | `UNKNOWN_ISSUER` |
| SAN 錯誤 | 15411 | 15412 | 15413 | `HOSTNAME_MISMATCH` |
| 已過期 | 15511 | 15512 | 15513 | `EXPIRED` |
| 尚未生效 | 15611 | 15612 | 15613 | `NOT_YET_VALID` |
| EKU 僅供 clientAuth | 15711 | 15712 | 15713 | `INVALID_PURPOSE` |
| 同一受信任 CA，但未核准的公鑰 | 15811 | 15812 | 15813 | `KEY_NOT_APPROVED` |

TLS 1.1 的 **全部八種** 情境另有 `protocol_policy=DEPRECATED`。即使憑證是授權的，TLS 1.1 仍不符合安全基準。

### 特別重要的第八個案例

`unapproved_leaf` 是**真實有效的憑證鏈**：CA 正確、SAN 正確、EKU 正確、時間正確、簽章也正確。**單靠 X.509 驗證無法拒絕它**；SVC2 必須比對事先授權的 SPKI 指紋，才會標記 `KEY_NOT_APPROVED`。

這種檢查屬於「額外授權政策」，不能直接把任意未見過的 SPKI 視為惡意。正常的 Certificate/Key Rotation 必須配合核准與變更管理，否則容易產生大量 False Positive。

### 本機已執行的實測結果

- 24/24 正確分類。
- 協定版本辨識：24/24。
- TLS 安全政策分類：24/24。
- Binary Confusion Matrix：`TP=21, TN=3, FP=0, FN=0`。
- 此數字只代表**已知合成樣本**的測試通過率；不等於野外攻擊的召回率或未知憑證真偽的真實準確率。

## 把你自己網域的公開 CA 憑證加入「真正的憑證」測試

SVC1 的 `good` 是「授權 Lab CA 核發」而非公網 CA 憑證。要納入真正生產系統上的公開 CA 憑證，可以**從宿主機直接對你的 HTTPS 服務做唯讀驗證**：

```bash
python -m pip install -r requirements.txt
python src/public_probe.py --host app.yourdomain.com --tls 1.3
python src/public_probe.py --host app.yourdomain.com --tls 1.2
```

這個外部測試使用執行環境的預設 Root CA Trust Store。請不要把正式環境的 TLS Private Key 移進 SVC1。若公開服務不支援 TLS 1.1，應記錄為該版本握手不被允許，**不是憑證偽造的證據**。

## 進階：Trust Store Injection 的模擬

在 SVC1 容器中**只對一條 OpenSSL 命令**指定 Rogue CA，模擬客戶端信任被更換的情況：

```bash
docker compose exec svc1 openssl s_client \
  -connect 127.0.0.1:15312 \
  -servername tls-lab.example.test \
  -verify_hostname tls-lab.example.test \
  -purpose sslserver \
  -CAfile /state/rogue_root.pem \
  -verify_return_error -tls1_2 -brief </dev/null
```

若修改了 `LAB_DOMAIN`，務必同步修改指令內的 SNI 與 `-verify_hostname`。這會展示：**同一張 Rogue CA 簽發的憑證，在授權 Trust Anchor 下失敗；在明確信任 Rogue Root 時卻可驗證通過。** 本實驗不需要也不應在宿主機安裝該 Root CA。

## 下一階段建議

1. **P0 — 未見樣本測試**：多組私鑰、多組 CA、合法的 Certificate Rotation、不同鏈深度、不同 Root Store。
2. **P1 — CT Log + CAA 對照**：針對自己持有的網域，建立不預期核發憑證的監控。
3. **P1 — Trust Store Integrity**：比較 Windows/macOS/Linux Root Store 與組織核准政策；任何變更都應有審核來源。
4. **P1 — OCSP/CRL**：依實際使用的 TLS 客戶端與撤銷策略，補足憑證撤銷檢查。
5. **P2 — 可觀測性**：把每次檢查的結果輸出 Prometheus Metrics、OTLP 或 SIEM JSON 事件。

## 限制與注意事項

- 使用 OpenSSL security level 0 測試 TLS 1.1 **只允許在內部隔離環境**。RFC 8996 已棄用 TLS 1.1。
- 此專案**不是**公開 CA 私鑰偽造器、流量攔截器、釣魚代理或對外憑證自動化核發服務。
- 在憑證可以通過完整 PKI 驗證、又沒有授權基準或外部證據的情況下，SVC2 無法單憑一張憑證判斷它是否為惡意誤發。
- 尚未實作 CT、CAA、撤銷查核、弱簽章檢查與正式環境的 SPKI 換鑰治理。

參考：[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) · [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) · [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) · [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525)
