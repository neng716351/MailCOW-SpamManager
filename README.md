# MailCOW SpamManager

Mailcow 管理介面的 SpamManager 擴充功能，提供繁體中文的垃圾郵件評分、全域名單、個別信箱／網域政策、防冒名規則與變更紀錄管理。

此專案是社群維護的 Mailcow 擴充功能，並非 Mailcow 官方專案。它只包含擴充檔案與整合補丁，不包含完整 Mailcow 原始碼、伺服器設定、客戶資料、郵件、憑證或商標圖片。

## 功能

- 檢視及調整 Rspamd 全域動作門檻與評分項目。
- 管理 Mailcow/Rspamd 全域名單、信箱／網域政策與專屬門檻。
- 全域地址名單提供條件類型助手：精確地址、整個網域、網域含子網域、寄件者帳號，自動產生並轉義正規表示式。
- 主機層名單：來源 IP／網段、寄件主機 HELO、反解（PTR）名稱與來源 ASN，各自以對應格式驗證。
- 建立以寄件者顯示名稱為條件的防冒名規則。
- 查看管理操作前的設定快照與近期紀錄。
- 使用繁體中文介面及評分規則說明。
- 檢視隔離區留存的郵件，可依動作篩選（拒收／加標記／全部）；拒收的可放行投遞到本機收件信箱。
- 留存往外寄但被拒收的郵件（誤判常見於此），由管理員決定放行給外部收件人或刪除。
- 兩種攔截都可設定通知收件人；命中病毒的外寄郵件放行時需額外確認。
- 在總覽頁即時檢查本機自訂設定是否被 Mailcow 更新覆蓋。
- **全部外部來信留存**（可設定天數），被延遲、正常投遞的信也能事後查看內文，方便追查釣魚信。
- **郵件檢視保留 HTML 原貌**：白名單重建 HTML、放進無腳本沙箱；連結一律失效並標示真實網址，外部圖片預設封鎖。
- **連結網域黑名單**：信件內任何連結指向名單上的網域就拒收。
- **群組別名專屬門檻**：讓常被鎖定的公開別名（如 service@）比全域門檻更早標記。
- **維護選單**：系統更新（含步驟進度與完整紀錄）、設定驗證、備份與還原、登入地區，各自獨立。
- **網頁一鍵更新**：快照自訂設定 → 官方 `update.sh` → 重新套用 → 驗證，需另一組更新密碼。
- **NAS 加密備份與還原**、**主機系統更新**，都由主機端 root 代理程式執行，網頁只送出請求。
- **登入地區限制**：只有允許的國家可以連登入用的埠（POP3／IMAP／SMTP 寄信／Sieve／HTTPS），25 埠收信不受影響；出差可臨時開放，到期自動關閉。
- **多國語言**：介面跟著 mailcow 右上角的語言設定切換，附繁體中文（原文）、英文、日文；簡體中文介面退回繁體中文，其他語言退回英文。郵件主旨、寄件者、內文一律不翻譯。
- **重新驗證**：更新後事後修好的問題，按一下重跑檢查與功能測試，更新頁就會標成「已解決」。
- **範本化**：不寫死任何網域、帳號或容器名稱；範例信箱依安裝網域產生，容器名稱從 `mailcow.conf` 讀取。

## 相容性與注意事項

- 需要已部署 Mailcow、PHP-FPM、Rspamd Unix socket、Redis，以及 Mailcow 原生 `rsettings()`、`rspamd_maps()` 等函式。
- 程式透過 Mailcow 管理員 session 與原生 CSRF 機制保護寫入操作；不要將 API 端點暴露給未受信任的網路。
- 防冒名功能比對郵件的 From 顯示名稱及允許信箱；它不會驗證寄件者身分，也不能取代 SPF、DKIM 或 DMARC。
- 既有但未含 `mailcow-impersonation-form-v1` 中繼資料的自訂規則，不會自動出現在表單中。請先備份並於測試環境確認，再透過管理介面重建為表單規則。
- 主機層名單的 HELO 名稱可被寄件端任意宣告，不要單憑 HELO 放行；反解名稱需要來源有 PTR 紀錄才會命中。
- IP 與 ASN 名單不接受正規表示式，寫入前分別以 IP／CIDR 與 ASN 格式驗證。
- 變更可能影響郵件投遞。請先在測試環境驗證並備份 Mailcow 設定。

## 安裝

1. 備份 Mailcow 設定，確認使用的 Mailcow 版本及本機修改。
2. 將 `files/data/web/` 的內容複製到 Mailcow 安裝目錄中的 `data/web/`，保留相同子目錄結構。
3. 在 Mailcow 安裝目錄套用整合補丁：

   ```sh
   git apply /path/to/MailCOW-SpamManager/patches/functions.rspamd.inc.php.patch
   ```

   若補丁不適用目前的 Mailcow 版本，請勿強制套用；手動檢視 `require_once` 及 `rsettings()` 的前置驗證區塊，並依目前版本調整。

4. 若要使用郵件留存／放行功能，另外安裝：

   - 將 `files/data/conf/rspamd/meta_exporter/` 的 `pipe_outbound.php` 與 `pipe_inbound_notify.php`
     複製到 Mailcow 的 `data/conf/rspamd/meta_exporter/`。
   - 套用 `patches/metadata_exporter.conf.patch`（新增 `OUTBOUND_HOLD` 與 `INBOUND_NOTIFY` 規則，
     並放寬原有的隔離 selector，使命中黑名單的拒收郵件也會留存一份副本）。
   - 套用 `patches/init_db.inc.php.patch`（新增 `outbound_hold` 資料表定義），或自行建立該資料表。
   - 套用 `patches/base.twig.patch`（在管理選單加入 Spam Manager 入口）。
   - 執行 `rspamadm configtest` 確認設定無誤後重啟 `rspamd-mailcow`。

5. 若要使用主機層名單（來源 IP／HELO／反解名稱／ASN），另外安裝：

   - 將 `files/data/conf/rspamd/custom/` 的 5 個 `.map` 範本複製到 Mailcow 的
     `data/conf/rspamd/custom/`，擁有者與權限沿用同目錄其他 map（通常為 uid 82、`0644`）。
     範本只有註解，條件請從管理頁加入。
   - 套用 `patches/multimap.conf.patch`（新增 `GLOBAL_IP_BL`、`GLOBAL_HELO_WL/BL`、
     `GLOBAL_HOSTNAME_WL/BL` 五條規則）。
   - 套用 `patches/vars.inc.php.patch`（把新名單登錄到 `$RSPAMD_MAPS`。**這步不能省**：
     原生 `rspamd_maps('edit')` 會拒絕未登錄的名單，少了它頁面讀得到卻存不進去）。
   - 執行 `rspamadm configtest` 確認設定無誤後重啟 `rspamd-mailcow`。

   `ip_wl.map` 與 `bad_asn.map` 是 Mailcow 原生既有的名單，此補丁只是把它們登錄成可在頁面上編輯；
   刻意沒有提供 ASN 白名單，因為放行整個 ASN 等於替該 ISP 所有客戶跳過過濾。

6. 若要使用總覽頁的「本機自訂設定狀態」檢查：

   - 參考 `docker-compose.override.yml.example` 設定 php-fpm 的唯讀掛載，
     並以 `docker compose up -d --no-deps php-fpm-mailcow` 套用。
   - 將 `files/data/web/inc/spammanager.customizations.example.php` 複製為
     `spammanager.customizations.php` 並依你的部署調整。該檔描述你的部署細節，請勿提交至公開 repo。

7. 確認檔案擁有者與權限沿用 Mailcow 原設定，然後重新載入 Twig 快取並重啟 `php-fpm-mailcow`，讓 OPcache 載入新程式。
8. 以 Mailcow 管理員登入並開啟 `/admin/SpamManager`。先讀取設定、檢查記錄，再進行任何寫入。

9. 若要使用 v2 的功能，依需要安裝（各項互相獨立）。完整說明見 [`docs/OPERATIONS.md`](docs/OPERATIONS.md)：

   | 功能 | 要裝的東西 |
   |---|---|
   | 全部來信留存 | `patches/metadata_exporter.conf.patch`、`patches/pipe.php.patch`、`helper-scripts/purge-aged-quarantine.sh`（主機 crontab 每天執行） |
   | HTML 原貌檢視 | `files/data/web/qpreview.php`、`patches/qhandler.twig.patch` |
   | 連結網域黑名單 | `patches/multimap.conf.patch`、`patches/vars.inc.php.patch`、`custom/global_url_blacklist.map` |
   | 群組別名門檻 | `patches/settings.php.patch`，再把 `dynmaps/alias-spamlevels.json.example` 複製成 `alias-spamlevels.json` 並改成你的別名 |
   | 網頁一鍵更新 | `sudo helper-scripts/setup-updater-agent.sh`（設定更新密碼） |
   | 主機系統更新 | `sudo helper-scripts/setup-host-update.sh` |
   | NAS 備份／還原 | `sudo helper-scripts/setup-nas-webconfig.sh` 或 `setup-nas-backup.sh` |
   | 登入地區限制 | `sudo helper-scripts/setup-geo-allowlist.sh`（預設只開放台灣；可用 `GEO_COUNTRIES="TW JP"` 指定，`GEO_ENABLE=0` 先不啟用） |

   `helper-scripts/` 的檔案放到 Mailcow 的 `helper-scripts/`。主機端代理程式都要先有更新密碼，所以 **`setup-updater-agent.sh` 要第一個執行**。

10. **本機專屬設定**（選用，都不要提交到 repo）：
    - `files/data/web/inc/vars.local.inc.php.example` → Mailcow 的 `data/web/inc/vars.local.inc.php`：語言選單把繁體中文排第一。
    - `files/data/web/css/build/099-local-overrides.css` → Mailcow 的 `data/web/css/build/`：語言選單太長時可以捲動。
    - `files/data/web/inc/spammanager.local.php.example`：只有在需要辨識「防冒名表單出現前就建立的舊規則」時才用。

11. **改完 PHP 一定要重啟 php-fpm**：Mailcow 的 opcache 預設不檢查檔案時間，不重啟就會繼續跑舊程式。另外清除 JS 打包快取與 Twig 快取：

    ```sh
    docker compose restart php-fpm-mailcow
    docker compose exec php-fpm-mailcow sh -c 'rm -f /tmp/*.js; rm -rf /web/templates/cache/*'
    ```

## 郵件留存與放行

被拒收的郵件要能「放行」，前提是系統留有副本：

- **SMTP 連線階段拒收**（postscreen DNSBL、HELO 檢查等）在對方送出信件內容之前就被拒，
  系統沒有、也不可能有副本，因此**無法列出或放行**。
- **內容掃描後拒收**才會留存副本，分成兩個方向：
  - 寄給本機信箱的郵件由 Mailcow 原生隔離機制留存，放行會重新投遞到該信箱。
  - 由已驗證使用者往外寄的郵件由 `pipe_outbound.php` 留存於 `outbound_hold`，
    放行會透過 Postfix 的重新注入埠寄給外部收件人。

放行會略過當初攔截該郵件的檢查（包含病毒掃描），屬於管理員的明確決定，操作前請先確認郵件安全。
所有放行與刪除都會寫入變更紀錄。外寄留存預設保留 30 天。

## 更新

這是手動更新流程：GitHub 上的程式碼不會自動部署到 Mailcow；Mailcow 裡的門檻、名單、政策及規則也不會同步回 GitHub。

以下假設擴充功能 repo 和 Mailcow 安裝目錄都已存在於同一台主機。先將路徑換成實際位置，並在 Mailcow 維護時段執行：

```sh
SPAMMANAGER=/path/to/MailCOW-SpamManager
MAILCOW=/path/to/mailcow-dockerized
BACKUP_DIR=/path/to/private-backup
```

1. **確認版本與本機變更。** 檢查兩個 repo 的 `git status --short`；若有未提交的本機修改，先自行備份並釐清，勿直接覆蓋。
2. **備份 Mailcow 檔案。** 將下列已安裝檔案及整合入口備份到 Mailcow 目錄以外、Web 無法存取的位置。備份可能包含本機修改，不要提交至公開 repo。

   ```sh
   mkdir -p "$BACKUP_DIR"
   tar -C "$MAILCOW" -czf "$BACKUP_DIR/spammanager-files-$(date +%Y%m%d-%H%M%S).tar.gz" \
     data/web/admin/SpamManager.php \
     data/web/admin/SpamManagerApi.php \
     data/web/inc/impersonation.inc.php \
     data/web/inc/spammanager.inc.php \
     data/web/inc/functions.rspamd.inc.php \
     data/web/js/site/impersonation.js \
     data/web/js/site/spammanager.js \
     data/web/js/site/spammanager.translations.js \
     data/web/templates/spammanager-controls.twig \
     data/web/templates/spammanager.twig
   ```

   此步只備份程式檔案。Mailcow/Rspamd 的執行中設定、資料庫及 Redis 備份請依 Mailcow 的備份流程另行處理。
3. **取得程式碼更新並檢查。**

   ```sh
   git -C "$SPAMMANAGER" status --short
   git -C "$SPAMMANAGER" pull --ff-only
   php "$SPAMMANAGER/tests/impersonation.php"
   php -l "$SPAMMANAGER/files/data/web/inc/impersonation.inc.php"
   ```

   更新前若 repo 有本機修改，先停止並處理，不要用 `reset` 或強制覆蓋。
4. **更新擴充檔案。** 確認已安裝版本的本機修改已備份或合併，再複製擴充檔案：

   ```sh
   cp -R "$SPAMMANAGER/files/data/web/." "$MAILCOW/data/web/"
   ```

   複製後確認檔案擁有者及權限與原 Mailcow 安裝一致。
5. **檢查整合補丁。** `functions.rspamd.inc.php.patch` 是針對尚未整合此功能的 Mailcow 原始檔案。更新時不要盲目重複套用：

   ```sh
   git -C "$MAILCOW" apply --reverse --check "$SPAMMANAGER/patches/functions.rspamd.inc.php.patch"
   ```

   若反向檢查成功，表示補丁已存在，不需重複套用。若失敗，先執行一般的 `git apply --check`；只有檢查成功且確認目前整合入口尚未加入時才套用。兩種檢查都失敗時，停止更新並依 Mailcow 版本手動檢視差異，勿使用 `--force`。
6. **重新載入並驗證。** 依部署方式重新載入 Twig 快取，再從 Mailcow 安裝目錄重啟 PHP-FPM：

   ```sh
   cd "$MAILCOW"
   docker compose restart php-fpm-mailcow
   ```

   以 Mailcow 管理員開啟 `/admin/SpamManager`，確認頁面可載入、設定可讀取，再於測試環境驗證寫入操作與郵件處理結果。若有錯誤，先停止修改設定，並使用先前備份回復程式檔案及整合入口。

不要把 Mailcow 的真實門檻、名單、信箱／網域政策、規則內容、郵件或備份推送到此公開 repo。若要分享程式碼修改，請只挑選擴充功能程式檔，先檢查差異並移除環境資料，再提交至 GitHub。

解除安裝前先備份設定。移除新增的 SpamManager 檔案，並還原 `functions.rspamd.inc.php` 中此擴充功能的整合區塊；已儲存的 Rspamd、政策、名單及防冒名規則需另行還原。

## 檢查

```sh
php tests/impersonation.php
php -l files/data/web/inc/impersonation.inc.php
```

部署後仍需在測試 Mailcow 環境驗證管理員登入、CSRF、讀取及寫入行為。

## 版本紀錄

版號採語意化版本（SemVer）。目前版本見 `VERSION`。

### v2.2.0

- 新增日文語言檔（`files/data/web/inc/spammanager-i18n/ja-jp.json`，機器翻譯並經過兩輪審查，頁面頂端會標示）。
- 簡體中文介面退回繁體中文原文，其他沒有語言檔的語言退回英文。
- 修正郵件檢視頁遇到含「、」的句子整句不翻譯的問題。原因是 PHP（PCRE2）的 `\p{Han}` 會把「、」等標點算成漢字，現在改用和 JS 端相同的明確字元範圍。
- 日文的「」（）括號內側不留空格。

### v2.1.1

- 自訂設定檢查清單改存成 `spammanager.customizations.php`（內容仍是 JSON）。Mailcow 的 `/inc/` 目錄可以從外部直接存取，舊的 `.json` 會被原樣下載，透露部署細節；`.php` 只會被執行，不會輸出內容。舊的 `.json` 仍可讀取，但「設定驗證」頁會提示改用新格式。

升級：把原本的 `spammanager.customizations.json` 內容貼進 `spammanager.customizations.example.php` 的 JSON 區塊，另存為 `spammanager.customizations.php`，再刪除舊的 `.json`。

### v2.1.0

- 多國語言：以繁體中文為原文、原文即鍵值；管理頁在瀏覽器端翻譯，郵件檢視頁在伺服器端翻譯。附英文語言檔（`files/data/web/inc/spammanager-i18n/en-gb.json`）。郵件資料以 `data-sm-raw` 標記，一律不翻。
- 更新頁新增「重新驗證」（`helper-scripts/mailcow-verify.sh`，經由更新代理程式的 `verify` 動作執行，唯讀、不需要更新密碼）。
- 範本化：範例信箱依安裝網域產生；主機腳本從 `COMPOSE_PROJECT_NAME` 推算容器名稱；防冒名舊規則改由選用的本機檔 `spammanager.local.php` 提供。
- 日期、國家名稱依網站語言顯示；國家輸入框支援各語言名稱、英文名稱與兩碼代碼。
- 新增本機覆寫範例：語言選單排序（`vars.local.inc.php.example`）、語言選單可捲動（`099-local-overrides.css`）。

### v2.0.1

- 修正網頁「重新開機」實際上不會重開：原本以背景程式等待 60 秒後重開，但它在 systemd oneshot 服務中執行，服務結束時 systemd 會清掉殘留程式，重開機從未發生。改為立即以 `systemctl reboot --no-block` 交給 systemd 執行，失敗時頁面顯示錯誤。

### v2.0.0

- 全部外部來信留存，被動留存的副本不會進每小時摘要；dovecot 容器沒有 cron，改由主機 crontab 清除過期留存。
- 黑名單命中時 rspamd 會提前結束掃描，`RCPT_MAILCOW_DOMAIN` 來不及計算；拒收的信現在也一律留存。
- 郵件檢視改為 HTML 原貌（白名單清洗＋沙箱＋CSP），連結失效並標示真實網址。
- 新增連結網域黑名單 `GLOBAL_URL_BL`。
- 新增群組別名專屬門檻（原生的個別門檻設在別名上，會變成套用到所有信件的規則）。
- 維護功能拆成獨立選單；更新頁顯示步驟、問題清單、版本變化與完整紀錄。
- 新增網頁一鍵更新、主機系統更新、NAS 加密備份與還原、登入地區限制（nftables，依 RIR 國家資料）。
- 重新套用工具：依語句結構比對（不怕官方新增欄位）、保留檔案原本的換行格式、更新前快照涵蓋全部自訂檔案。
- 一鍵更新：自動處理新版 `update.sh` 先更新 `_modules` 再要求重跑的情況。

從 v1.x 升級：見 `docs/OPERATIONS.md` 的「從 v1 升級」。

### v1.1.1

- 修正 ASN 名單的欄位說明：第二欄是**分數倍數**而非絕對分數（規則預設 5 分，寫 `2` 即 10 分）。
  原本標為「自訂分數」會誤導。
- 實測確認 `LOCAL_BL_ASN` 的 `!MAILCOW_WHITE` 條件在執行期有效，`rspamadm configtest` 的
  「cannot register delayed dependency」警告不影響功能，不需要為它改動設定。

### v1.1.0

- 新增主機層名單：來源 IP／網段、寄件主機 HELO、反解（PTR）名稱，並把原生既有的
  `ip_wl.map` 與 `bad_asn.map` 納入頁面管理。需套用 `patches/multimap.conf.patch`
  與 `patches/vars.inc.php.patch`。
- 名單依種類驗證：IP／CIDR、ASN、正規表示式各用對應規則，不再一律當成正規表示式。
- 名單條件助手支援精確地址、整個網域、網域含子網域、寄件者帳號、精確主機名、
  主機名尾碼、IP、CIDR 與 ASN，自動轉義並產生條目。
- 留存清單可依動作篩選（拒收／加標記／全部）。放寬留存 selector 後加標記的郵件也會留存，
  但原本在此頁完全看不到。加標記項目不提供放行按鈕。

從 v1.0.0 升級：複製 `files/` 的變更檔案、套用兩個新補丁、複製
`files/data/conf/rspamd/custom/` 的 5 個 map 範本，然後 `rspamadm configtest`
並重啟 `rspamd-mailcow` 與 `php-fpm-mailcow`。資料庫與既有名單內容不需變更。

### v1.0.0

首次發佈：Rspamd 門檻與評分管理、全域地址名單、信箱／網域政策與專屬門檻、
防冒名規則、變更紀錄、郵件留存與放行（含外寄攔截）、更新後的自訂設定檢查。

## 授權

本擴充功能依 GNU GPL-3.0 授權發佈，詳見 [LICENSE](./LICENSE)，與 [mailcow: dockerized](https://github.com/mailcow/mailcow-dockerized) 使用相同的授權。

- `patches/` 是對 mailcow: dockerized 原始檔的修改，內含原始碼片段（diff 的上下文行）。這些片段的著作權屬於 mailcow: dockerized 的原作者與貢獻者，依 GPL-3.0 散佈；修改的部分在補丁中逐行可見，並以 `Local change`／`Local addition` 註解說明原因。
- `files/` 與 `helper-scripts/` 是本專案新增的檔案，同樣以 GPL-3.0 授權。其中 `pipe_outbound.php`、`pipe_inbound_notify.php`、`qpreview.php` 改寫自 mailcow: dockerized 的對應程式（`pipe.php`、`qhandler`），保留原作者的著作權。
- 本專案不包含 mailcow 的完整原始碼。使用前請先取得官方版本，並遵守其授權。

「mailcow」是其權利人的商標。本專案名稱中的 mailcow 只用來說明相容的系統；本專案**並非** mailcow 官方專案，也未獲其背書或支援。問題請在本 repo 回報，不要向 mailcow 官方回報。
