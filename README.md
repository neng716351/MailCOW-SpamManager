# MailCOW SpamManager

Mailcow 管理介面的 SpamManager 擴充功能，提供繁體中文的垃圾郵件評分、全域名單、個別信箱／網域政策、防冒名規則與變更紀錄管理。

此專案是社群維護的 Mailcow 擴充功能，並非 Mailcow 官方專案。它只包含擴充檔案與整合補丁，不包含完整 Mailcow 原始碼、伺服器設定、客戶資料、郵件、憑證或商標圖片。

## 功能

- 檢視及調整 Rspamd 全域動作門檻與評分項目。
- 管理 Mailcow/Rspamd 全域名單、信箱／網域政策與專屬門檻。
- 建立以寄件者顯示名稱為條件的防冒名規則。
- 查看管理操作前的設定快照與近期紀錄。
- 使用繁體中文介面及評分規則說明。

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

4. 確認檔案擁有者與權限沿用 Mailcow 原設定，然後重新載入 Twig 快取並重啟 `php-fpm-mailcow`，讓 OPcache 載入新程式。
5. 以 Mailcow 管理員登入並開啟 `/admin/SpamManager`。先讀取設定、檢查記錄，再進行任何寫入。

解除安裝前先備份設定。移除新增的 SpamManager 檔案，並還原 `functions.rspamd.inc.php` 中此擴充功能的整合區塊；已儲存的 Rspamd、政策、名單及防冒名規則需另行還原。

## 檢查

```sh
php tests/impersonation.php
php -l files/data/web/inc/impersonation.inc.php
```

部署後仍需在測試 Mailcow 環境驗證管理員登入、CSRF、讀取及寫入行為。

## 授權

本擴充功能依 GNU GPL-3.0 授權發佈，詳見 [LICENSE](./LICENSE)。它與 Mailcow 整合，並遵循 Mailcow 專案的 GPL 授權條款。
