# 部署與維運指南（v2）

這份文件說明 v2 各項功能的原理、安裝方式和實際踩過的坑，供在新主機上建置時參考。範例中的路徑以 `/opt/mailcow-dockerized` 表示 Mailcow 安裝目錄，網域以 `example.com` 表示。

> **先備份。** 下列每一項都會改動郵件處理流程。請先在測試環境驗證，並以 Mailcow 的 `backup_and_restore.sh` 做完整備份。

---

## 0. 建置順序

在一台新的 Mailcow 主機上：

1. 依 README 安裝 v1 的基本功能（頁面、整合補丁、主機層名單）。
2. `sudo helper-scripts/setup-updater-agent.sh`：設定**更新密碼**。後面所有主機端代理程式都用它做二次驗證，所以必須第一個執行。
3. 依需要安裝下面各節的功能，各節互相獨立。
4. 套用 `docker-compose.override.yml.example` 的唯讀掛載（自訂設定檢查、狀態檔共用目錄 `data/updater`），執行 `docker compose up -d php-fpm-mailcow`。
5. **重啟 php-fpm 並清快取**（見 §9）。
6. 執行 `python3 -I helper-scripts/reapply-local-customizations.py --check`，全部應為 OK。

---

## 1. 全部外部來信留存

### 為什麼

Mailcow 原生只留存 reject／add header／rewrite subject 的信。分數落在 greylist 與 add header 之間的信（例如 7.89 分，門檻 7／8）只會被延遲，**沒有任何副本**。等使用者回報釣魚信時，管理員已經看不到內文了。

### 做法

- `patches/metadata_exporter.conf.patch`：`reject_no_global_bl` selector 改成「非本機驗證寄件者、收件者為本機信箱」的每一封都留存。
- **黑名單命中的拒收也要留存**：+2050 的規則命中後，rspamd 會提前結束掃描，`RCPT_MAILCOW_DOMAIN` 可能還沒算到。所以 selector 另外判斷「結果是 reject」就留存，由 `pipe.php` 濾掉非本機收件者。
- `patches/pipe.php.patch`：`no action`／`greylist`／`soft reject` 的副本寫入時就標 `notified=1`。否則隔離通知設為「所有類別」的信箱，每小時會收到一封列出自己所有正常信件的摘要。
- 保留天數用 Mailcow 原生的 `Q_MAX_AGE`（Redis），每個信箱的筆數上限用 `Q_RETENTION_SIZE`。

### 一定要處理：過期清除

Mailcow 的 dovecot 容器裡有 `clean_q_aged.sh`，但容器是 supervisord、**沒有 cron**，這支腳本從來不會執行，`Q_MAX_AGE` 等於沒有作用。只留存被攔截的信時影響不大；全部留存之後，資料表會一直長大。

```cron
30 3 * * * /opt/mailcow-dockerized/helper-scripts/purge-aged-quarantine.sh >> /opt/mailcow-dockerized/data/logs/purge-aged-quarantine.log 2>&1
```

### 注意

- `Q_EXCLUDE_DOMAINS` 是 nil 時，舊版 `pipe.php` 的 `in_array()` 會出錯，導致**完全不留存**。新版官方已修正，套用補丁前請先確認版本。
- SMTP 連線階段就被拒的信（postscreen、DNSBL）沒有內文可以留存。

---

## 2. 郵件檢視保留 HTML 原貌

`files/data/web/qpreview.php` 會以 DOMDocument **白名單重建** HTML，結果放進 `<iframe sandbox srcdoc>`，CSP 為 `default-src 'none'`：

| 內容 | 處理 |
|---|---|
| script、iframe、object、form、svg、base、meta | 刪除 |
| 事件屬性（onerror 等）、`javascript:` | 刪除 |
| 白名單外的標籤 | 拆殼保留文字 |
| 連結 | **一律失效**，後面標示 `[連結→ 真實網址]` |
| 外部圖片 | 預設封鎖；`?images=1` 明確放行，CSP 也只在那次請求放寬 |
| `cid:` 內嵌圖片 | 轉成 data URI |
| CSS `url()` | 封鎖外部圖片時一併移除 |

連結刻意不可點：看釣魚信的目的，是比對「顯示文字」和「實際網址」。外部圖片預設封鎖，是因為載入就等於告訴寄件者這個信箱有效、有人在讀。

---

## 3. 連結網域黑名單

- `patches/multimap.conf.patch` 新增 `GLOBAL_URL_BL`：`type = "url"`、`filter = "tld"`、+2050 分。
- 名單 `data/conf/rspamd/custom/global_url_blacklist.map`：一行一個**可註冊網域**（`example.com`），會涵蓋所有子網域。不要寫 `http://`、路徑或萬用字元。
- `patches/vars.inc.php.patch` 會在 `$RSPAMD_MAPS['url']` 登錄這個名單，之後就能從「全域名單」頁編輯。**這步不能省**：原生 `rspamd_maps('edit')` 會拒絕沒有登錄的名單。

---

## 4. 群組別名專屬門檻

公開的群組別名（`service@`、`info@`）通常最先被釣魚，適合比全域門檻更早標記。

**不要用 Mailcow 原生的個別門檻設定別名。** `ucl_rcpts()` 不會輸出別名本身，產生的 settings 區塊**沒有任何收件者條件**，會套用到**所有信件**。

改用 `patches/settings.php.patch` 加上 `data/conf/rspamd/dynmaps/alias-spamlevels.json`：

```json
{
  "shared@example.com": { "greylist": 4, "add_header": 5 }
}
```

補丁產生 `alias_score_N` 區塊時處理了三個坑：

1. 這個檔案的 `parse_email()` 回傳的 domain **含 `@`**。
2. UCL 雙引號字串裡的 `\+` 不會保留成正規表示式的跳脫，要寫成 `[+]`。
3. rspamd 依 HTTP map 的 `Last-Modified` 決定是否重新讀取，原本的值只看資料表更新時間。補丁把 JSON 檔的 mtime 也算進去，改完 JSON 才會生效。

驗證方式：`rspamc -r shared@example.com symbols < test.eml` 應出現 `ALIAS_SPAMLEVEL`。

---

## 5. 網頁一鍵更新

### 安全設計

- 網頁（php-fpm，uid 82）只能寫一個請求檔到 `data/updater/`，自己不執行任何東西。
- systemd path unit 偵測到請求後，由 root 代理程式驗證**更新密碼**（只存加鹽 SHA-256，`/etc/mailcow-updater/`，僅 root 可讀）。就算管理員登入被盜，也不足以觸發更新。
- 請求 180 秒後失效；兩次成功更新之間至少間隔 10 分鐘。

### 流程（`mailcow-oneclick-update.sh`）

1. 快照所有被我們改過的追蹤檔案。
2. 更新前的自訂設定檢查。
3. 官方 `update.sh`。新版會**先更新 `_modules`，再以結束碼 2 要求重跑**；腳本會自動再跑一次。
4. `reapply-local-customizations.py --apply` 重新套用。
5. 清快取、重啟 rspamd／postfix／php-fpm，`rspamadm configtest`、容器狀態、功能測試；最後列出和快照不同的自訂檔案，名單檔（`.map`）被改動會標成問題。

### 重新套用工具的設計原則

- **依結構比對，不比對整段字串**：官方在 INSERT 加了一個欄位（`qhash`），整段字串比對就會失效。
- **保留檔案原本的換行**：官方部分檔案是 CRLF；寫回時若改成 LF，整份檔案都會變成差異，之後每次更新都容易衝突。
- 找不到錨點時回報 `NEEDS-MANUAL`，**完全不動該檔案**，不亂猜。
- 內建的補回內容必須和實際生效版本同步。否則更新把檔案蓋回官方版後，只會補回舊內容，檢查卻顯示 OK。

### 更新頁的進度顯示

`sm_parse_update_log()` 會去除顏色與游標控制碼（docker pull 會用 `ESC[1A`／`ESC[2K` 重畫進度），把逐層下載、git 檔案清單、逐項通過的測試各收成一行摘要，並解析出 5 個步驟的狀態、問題清單、更新前後版本。實測一次完整更新的紀錄從約 3000 行整理成約 500 行，內容完整保留。

---

## 6. NAS 加密備份與還原、主機系統更新

- `setup-nas-webconfig.sh`（從網頁設定 NAS）或 `setup-nas-backup.sh`（主機上設定）。SMB 密碼只存在 `/etc/mailcow-nas/`（root 專屬，容器讀不到），網頁不儲存、不回顯。
- 備份會加密。**第一次設定成功後，請立刻把 `/etc/mailcow-nas/backup.key` 取出、離線保管**；金鑰遺失就無法還原任何備份。
- 網頁只能還原設定類元件（mysql、redis、rspamd、postfix）；信件（vmail）與 crypt 必須在主機上還原，避免一次誤操作覆蓋所有信箱。還原前會自動快照目前的 mysql 與 redis。
- `setup-host-update.sh`：一般與安全性更新每天自動安裝（Mailcow 在容器裡，主機函式庫不影響郵件）；`docker.io`／`containerd`／`runc` 會重啟容器執行環境，所以保留給管理員手動套用；新核心要重開機才生效，重開機永遠是另外的明確操作。

---

## 7. 登入地區限制

### 範圍

只限制需要帳號密碼的埠：

| 埠 | 服務 | 限制 |
|---|---|---|
| 110／995 | POP3 | ✅ |
| 143／993 | IMAP | ✅ |
| 465／587 | SMTP 寄信（需登入） | ✅ |
| 4190 | Sieve | ✅ |
| 443 | webmail、管理介面、ActiveSync | ✅ |
| **25** | 外部寄信進來 | ❌ 一律放行 |
| **80** | https 導向、Let's Encrypt | ❌ 一律放行 |
| 私有網段 | 內網、容器 | ❌ 一律放行 |

**25 埠可以安全地對全世界開放**，前提是它不接受登入。Mailcow 預設的 `master.cf` 是 postscreen → `smtpd pass`，並帶 `-o smtpd_sasl_auth_enable=no`。請在你的主機上實際確認：

```python
import smtplib, ssl
s = smtplib.SMTP('127.0.0.1', 25); s.ehlo(); s.starttls(context=ssl._create_unverified_context()); s.ehlo()
print(s.esmtp_features.get('auth', '（不提供）'))   # 必須是（不提供）
```

### 實作

- `nftables` 獨立表 `inet mailcow_geo`，不碰 Docker 或 Mailcow netfilter 的鏈。
- 掛在 forward 與 input hook，比對 **`ct original proto-dst`**，也就是 Docker DNAT 之前的原始目的埠。只檢查新連線，所以變更名單不會切斷現有連線，伺服器自己往外的連線也不受影響。
- 國家資料：五個 RIR（APNIC、ARIN、RIPE NCC、LACNIC、AFRINIC）的 delegated 檔，每天更新。
- 變更要輸入更新密碼，由 root 代理程式驗證；代理程式會再驗證一次所有欄位。
- **防呆**：國家資料下載不完整，或開放國家的 IP 數量異常少時，拒絕套用並維持原狀，避免把所有人擋在外面。
- 臨時開放最長 90 天；每 10 分鐘的排程會移除過期項目、更新頁面上的計數與擋下紀錄。

### 安裝

```sh
sudo helper-scripts/setup-geo-allowlist.sh                         # 預設：啟用，只開放 TW
sudo GEO_COUNTRIES="TW JP" helper-scripts/setup-geo-allowlist.sh   # 指定國家
sudo GEO_ENABLE=0 helper-scripts/setup-geo-allowlist.sh            # 先安裝、不啟用
```

### 使用注意

- **出差前要先開好目的地。** 人在國外時，管理頁面（443）也會被擋，無法自己打開。
- 用國外 VPN、iPhone「私密轉送」的使用者會被判定為其他國家。
- 緊急解除：`sudo helper-scripts/mailcow-geo-agent.py --disable`。停用後要從頁面重新啟用，排程**不會**自動打開。
- 前面若有會做 SNAT 的防火牆，主機看到的來源 IP 全都是防火牆，這個功能就無法運作。請確認 Mailcow 日誌裡的 `rip=` 是真實的外部 IP。

### 為什麼不只靠 netfilter

Mailcow netfilter 預設「60 秒內失敗 5 次才封鎖」。低速暴力破解（每個 IP 每隔幾分鐘試一次）永遠碰不到這個門檻。實際觀察到 7 個境外 IP 在 18 小時內試了 168 次，沒有一個被封。

---

## 7.5 多國語言

- 介面以**繁體中文為原文**，原文就是翻譯的鍵值。語言檔：`data/web/inc/spammanager-i18n/<mailcow 語言代碼>.json`，例如 `en-gb.json`。
- 語言依 mailcow 的 `$_SESSION['mailcow_locale']` 決定；沒有對應語言檔時退回 `en-gb`。
- **管理頁**：`js/site/spammanager.i18n.js` 在瀏覽器端翻譯，並用 MutationObserver 跟著頁面重繪；`confirm()`／`alert()` 的對話框也會翻譯。
- **郵件檢視頁**：`inc/spammanager.i18n.inc.php` 的 `sm_i18n_html()` 在伺服器端翻譯，因為這一頁的 CSP 不允許執行 JS。
- **保護郵件資料**：
  1. 一段文字必須**完全由已知片段組成**才翻譯，所以含有其他中文的主旨會保持原樣。
  2. 郵件資料欄位（主旨、寄件者、收件者、附件、內文）標記 `data-sm-raw`，一律不翻；這是為了防止主旨剛好等於某個介面詞。
- **新增一種語言**：複製 `en-gb.json`，把 `strings` 的值換成該語言，再把 `meta.lang` 改成語言代碼。非原文校對的語言設 `"machine": true`，並在 `notice` 放一句提示，頁面頂端會顯示。
- 帶數字的句子用樣板鍵值，`{n}` 會比對一個數字，讓數字可以放在各語言自然的位置，例如 `"第 {n} 行": "Line {n}: "`。

## 7.6 重新驗證

更新頁只記錄「最後一次更新」的結果，事後手動修好的問題會一直顯示紅色。「重新驗證」會由 `mailcow-updater-agent.sh` 的 `verify` 動作，以 root 執行 `helper-scripts/mailcow-verify.sh`：

- 檢查四項：自訂設定、`rspamadm configtest`、容器狀態、功能測試。
- **只檢查、不修改**，所以不需要更新密碼；兩次之間至少隔 2 分鐘。
- 結果寫在 `data/updater/verify-status.json` 與 `verify.log`，**不會改動**上一次更新的紀錄。

## 7.7 範本化：不寫死網域與帳號

| 需要的資訊 | 來源 |
|---|---|
| 範例信箱的網域 | 資料庫中第一個啟用的郵件網域；取不到時改用 `MAILCOW_HOSTNAME` 去掉第一段 |
| 容器名稱 | `mailcow.conf` 的 `COMPOSE_PROJECT_NAME`，預設 `mailcowdockerized` |
| 本機專屬資料 | `data/web/inc/spammanager.local.php`（選用，**不要提交**） |

本機專屬資料一律存成 `.php`，不要存成 `.json`。Mailcow 的 `/inc/` 目錄可以從外部直接下載，`.json` 會原樣送出；`.php` 只會被執行，不會輸出內容。

## 8. 驗證清單

| 項目 | 方法 |
|---|---|
| 自訂設定 | `reapply-local-customizations.py --check` 全部 OK |
| 留存 | 寄一封測試信，確認出現在「郵件留存．看內文」 |
| 黑名單拒收也留存 | 測試信內放一個名單上的網域連結，應為 reject 且有留存 |
| 別名門檻 | `rspamc -r <別名>` 出現 `ALIAS_SPAMLEVEL` |
| 25 埠不收登入 | §7 的 Python 片段 |
| 地區限制 | 頁面「擋下的來源」出現境外 IP；用台灣的手機網路（非 Wi-Fi）收信正常 |
| 功能測試 | 更新頁按「重新驗證」，或在主機執行 `sudo helper-scripts/mailcow-verify.sh` |

---

## 9. 三個會讓「改了沒變」的快取

（主機腳本裡的 `docker exec` 請以 `${MC_PROJECT}-php-fpm-mailcow-1` 的形式取得容器名稱，見 §7.7。）

| 快取 | 位置 | 處理 |
|---|---|---|
| PHP opcache | php-fpm，`opcache.validate_timestamps=Off` | `docker compose restart php-fpm-mailcow` |
| JS 打包檔 | php-fpm `/tmp/<sha1>.js` | `rm -f /tmp/*.js` |
| Twig | `/web/templates/cache/` | 清空 |

**改完任何 PHP（包含 rspamd 的 `pipe.php`）都要重啟 php-fpm。** 只清 Twig 和 JS 快取，網頁看起來會更新，後端卻還在跑舊程式。

---

## 10. 從 v1 升級

1. 備份 Mailcow 與現有的 SpamManager 檔案。
2. 複製 `files/` 與 `helper-scripts/`。
3. 用 `git apply --check` 逐一檢查 `patches/`。已經套用過的（`git apply -R --check` 成功），就不要重複套用。
4. 依需要安裝 §1–§7。
5. 重啟 rspamd、php-fpm，清快取，執行 §8 的驗證清單。
