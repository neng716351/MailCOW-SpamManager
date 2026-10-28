# MailCOW SpamManager

Mailcow 管理介面的 SpamManager 擴充功能，提供繁體中文的垃圾郵件評分、全域名單、個別信箱／網域政策、防冒名規則與變更紀錄管理。

此專案是社群維護的 Mailcow 擴充功能，並非 Mailcow 官方專案。它只包含擴充檔案與整合補丁，不包含完整 Mailcow 原始碼、伺服器設定、客戶資料、郵件、憑證或商標圖片。

## 功能

- 檢視及調整 Rspamd 全域動作門檻與評分項目。
- 管理 Mailcow/Rspamd 全域名單、信箱／網域政策與專屬門檻。
- 建立以寄件者顯示名稱為條件的防冒名規則。
- 查看管理操作前的設定快照與近期紀錄。
- 使用繁體中文介面及評分規則說明。
- 檢視被拒收且已留存的郵件，並放行投遞到本機收件信箱。
- 留存往外寄但被拒收的郵件（誤判常見於此），由管理員決定放行給外部收件人或刪除。
- 兩種攔截都可設定通知收件人；命中病毒的外寄郵件放行時需額外確認。
- 在總覽頁即時檢查本機自訂設定是否被 Mailcow 更新覆蓋。

## 相容性與注意事項

- 需要已部署 Mailcow、PHP-FPM、Rspamd Unix socket、Redis，以及 Mailcow 原生 `rsettings()`、`rspamd_maps()` 等函式。
- 程式透過 Mailcow 管理員 session 與原生 CSRF 機制保護寫入操作；不要將 API 端點暴露給未受信任的網路。
- 防冒名功能比對郵件的 From 顯示名稱及允許信箱；它不會驗證寄件者身分，也不能取代 SPF、DKIM 或 DMARC。
- 既有但未含 `mailcow-impersonation-form-v1` 中繼資料的自訂規則，不會自動出現在表單中。請先備份並於測試環境確認，再透過管理介面重建為表單規則。
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

5. 若要使用總覽頁的「本機自訂設定狀態」檢查：

   - 參考 `docker-compose.override.yml.example` 設定 php-fpm 的唯讀掛載，
     並以 `docker compose up -d --no-deps php-fpm-mailcow` 套用。
   - 將 `files/data/web/inc/spammanager.customizations.example.json` 複製為
     `spammanager.customizations.json` 並依你的部署調整。該檔描述你的部署細節，請勿提交至公開 repo。

6. 確認檔案擁有者與權限沿用 Mailcow 原設定，然後重新載入 Twig 快取並重啟 `php-fpm-mailcow`，讓 OPcache 載入新程式。
7. 以 Mailcow 管理員登入並開啟 `/admin/SpamManager`。先讀取設定、檢查記錄，再進行任何寫入。

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

## 授權

本擴充功能依 GNU GPL-3.0 授權發佈，詳見 [LICENSE](./LICENSE)。它與 Mailcow 整合，並遵循 Mailcow 專案的 GPL 授權條款。
