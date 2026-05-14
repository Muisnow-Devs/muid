# AI Agent 程式碼風格與慣例（muid）

本專案目前**沒有**前端設計稿、Tailwind 或獨立的設計 token 套件；可視化的「設計系統」主要體現在 **API 合約（Protobuf + buf validate）**、**服務邊界**與 **Go 程式結構**。撰寫或修改程式時請對齊下列既有模式，不要發明與程式庫衝突的慣例。

## 模組與目錄

- **Go module**：`sanzi.io/muid`；產生的 API stub 在 **`sanzi.io/muid/api`**（以 `replace` 指向本倉 `./api`）。
- **Protobuf**：集中在 `api/proto/`，以 [Buf](https://buf.build) 管理（`buf.yaml`、`buf.gen.yaml`）。
- **服務進入點**：`cmd/<服務名>/main.go`（例如 `cmd/authn`、`cmd/profile`、`cmd/mailer`）。
- **領域實作**：`internal/<領域>/`（例如 `internal/authn`、`internal/profile`、`internal/mailer`）。
- **基礎設施套件（infra）**：路徑為 **`infra/<後端>/`**（例如 `infra/redis`、`infra/nats`、`infra/smtp`、`infra/r2`、`infra/mocked`）。每個套件內 **`interface.go` 只放對外匯出的型別／介面定義**（例如 `ObjectStore`、`KVStore` 型別別名、設定結構）；**不得**在該檔撰寫具體實作。**具體實作**放在同目錄其他 `.go` 檔（例如 `kvstore.go`、`objectstore.go`、`pubsub.go`、`mailer.go`、`public_url.go`），檔名不可為 `interface.go`。
- **Authn 專用基建**：與認證流程緊耦合、但仍可單測替換的程式（Redis 上的 OTP／transition session、Email／OIDC／Passkey provider 實作）放在 **`internal/authn/infra/`**（`kv/`、`identity/`）。**不要**把它們混進頂層 `infra/*`（頂層僅通用後端驅動與介面）。
- **工廠函式（`New*`）回傳介面**：若建構出的具體型別滿足專案對外合約介面（例如 Redis 實作 `kv.KVStore`、R2 實作 `r2.ObjectStore`、SMTP 實作 `mailer.Mailer`），**函式簽章應宣告回傳該介面型別**，不要回傳裸的 `*Concrete`，以降低依賴並便於替換實作或測試替身。

```go
// 建議：回傳介面
func NewRedisKVStore(redisURL string) redis.KVStore { /* ... */ }

// 避免：迫使呼叫端依賴 *RedisKVStore
func NewRedisKVStore(redisURL string) *RedisKVStore { /* ... */ }
```
- **Ent 產物**：各領域自有 `internal/<領域>/ent/`，schema 在 `ent/schema/`；以 `go generate` 驅動 `ent generate`（見各目錄 `generate.go`）。

## Protobuf 與驗證

- **套件命名**：`muid.<domain>.v1`（例如 `muid.profile.v1`）；**Go package** 使用 `option go_package` 中宣告的路徑與套件別名。
- **驗證**：欄位規則優先使用 **`buf.validate`**（`import "buf/validate/validate.proto"`），與現有 `shared/v1/claims.proto` 等檔案一致。
- **選填語意**：需要「有無欄位」區別時使用 `optional`（例如未帶入 claims 時由後端決定預設顯示名稱與頭像）。
- **Profile 部分更新**：`UpdateProfile` 使用 `google.protobuf.FieldMask`（`update_mask`）搭配巢狀的 `UpdateProfileFields`（`profile`）；僅處理 allowlist 內的路徑（正規化後為 `profile.<proto snake_case 欄位>`，例如 `profile.display_name`）。路徑解析與單元測試在 **`internal/profile/updatemask`**，實際寫入 DB 的 mutator 註冊在 **`internal/profile/grpc`** 的 `profilePatchRegistry`。
- **Profile 頭像**：`GetProfile` 回傳的 `avatar_url` 由 **`UserAvatar`** 決定（同一 `user_id`、**`uploaded_at` 非空** 的列中 **`id` 最大** 者；`id` 為 UUID v7）。**`UserAvatar` 為 append-only**：完成上傳或 bootstrap 一律 **INSERT** 新列，**不以 UPDATE 覆寫既有列** 代表「更換頭像」。暫存列（`uploaded_at` 為空、僅供 presign 上傳）不參與顯示挑選；在 **`CreateProfile`** 完成前若尚未有已上傳列，`GetProfile` 依既有規則回退 **`goavatar` 產生的 PNG data URL**（種子為 profile `user_id` 字串）。
- **`CreateProfile` 順序與非同步頭像**：RPC 在單一交易中先 **`INSERT user_profiles`**（含預先配置的 `id`＝新 `user_id`）、再 **`INSERT user_preferences`**，**`COMMIT` 成功後** 才對客戶端回傳成功。OIDC `picture`（若有）經 HTTPS 下載；否則或失敗時改以 **`goavatar`** 本機產生 PNG，再經驗證、轉 WebP、寫入 R2 與 **`INSERT user_avatars`**，由 **`internal/profile/avataringest`** 的 **`ExternalAvatarIngestor.GoBootstrap`** 排程（`go func`＋逾時 context＋panic recovery＋`traceid`）；該管線為 **profile 專用子系統**，**不是** gRPC handler 的核心職責，且 **不得** 在 handler 內 await，以免阻塞建立回應。
- **`UserAvatar` 不可變欄位**：`user_id`、`object_key`、`content_type` 在寫入後視為歷史列的一部分，**禁止**以 `UpdateOne` 或任何後續 UPDATE 變更；新狀態僅能靠新列表達（含 staging：每次 presign 嘗試為新列；完成上傳為另 insert 正式資產列，與 `CompleteAvatarUpload` 行為一致）。

## gRPC

- **攔截器鏈**：與 `internal/authn/app/service.go` 相同，使用 `pkg/grpc_utils` 的 **`TraceUnaryInterceptor`**（注入 trace id，見 `pkg/traceid`）、`RecoveryInterceptor`、`LoggerInterceptor`、`TimeoutInterceptor`。
- **逾時**：由設定的 `*_REQUEST_TIMEOUT_SECONDS`（authn 為 `AUTHN_`，profile 為 `PROFILE_`）控制。
- **錯誤**：優先使用 `google.golang.org/grpc/status` 的標準 codes（例如 `InvalidArgument`、`NotFound`、`AlreadyExists`、`FailedPrecondition`）。**非預期**失敗回傳客戶端時應使用固定、不洩漏內部細節的訊息（例如 `internal error`），細節僅寫入伺服器 log（見下文「錯誤處理與 trace id」）。

## 錯誤處理與 trace id

### `fmt.Errorf` 與錯誤鏈（專案慣例）

- **避免**在內層到處使用 `fmt.Errorf("...: %w", err)` 疊上下文；內層優先回傳 **sentinel**（`var ErrFoo = errors.New(...)`）、**實作小型介面的型別錯誤**（例如帶 `Detail() string` 的驗證／網域錯誤）、或 **不額外包裝的底層錯誤**。需要多個獨立失敗時使用 **`errors.Join(err1, err2, ...)`**，不要用多層 `fmt.Errorf` 假裝「多原因」。
- **單一頂層邊界**（例如 `cmd/*/main.go` 啟動流程、對外 RPC 邊界）若需標註「整體作業」語意，**允許**一層 `fmt.Errorf("load config: %w", err)` 之類的包裝；內層業務／infra 套件則應收斂到 sentinel／typed error／`errors.Join`。
- **語意穩定**的錯誤（例如 `storage.ErrObjectNotFound`）：**直接回傳** sentinel，不要為了型別一致再 `%w` 包一層，除非該層就是上述「單一頂層邊界」且需要作業名稱。
- **需要結構化細節的預期錯誤**：在對應 **`errors.go`**（與 `interface.go` 同目錄者優先）定義 **型別 + 小介面**（例如 `Detail() string`），不要只靠 `fmt.Errorf` 字串承載可程式化解讀的內容。

**範例（多原因）**

```go
return errors.Join(ErrWriteIndex, errFlush, errSync)
```

**範例（預期失敗 + 底層原因，內層）**

```go
return errors.Join(ErrMalformedMailEventPayload, err) // errors.Is(..., ErrMalformedMailEventPayload) 仍成立
```

**範例（帶安全細節的型別錯誤，示意）**

```go
type InvalidSegmentError struct { Field, Value string }

func (e *InvalidSegmentError) Error() string { /* 固定前綴 + 欄位 */ return "..." }
func (e *InvalidSegmentError) Unwrap() error { return ErrInvalidTemplatePath }
func (e *InvalidSegmentError) Detail() string { return e.Field + "=" + e.Value }
```

### `errors.go` 與 `interface.go`

- 凡在套件根目錄以 **`interface.go`** 定義對外合約（介面／型別別名）者，**預期可由呼叫端辨識的失敗**應集中在同目錄的 **`errors.go`**：以 `var ErrFoo = errors.New(...)` 或必要時小型 `type ValidationError struct`／`DetailError` 介面與實作型別等形式宣告；呼叫端以 **`errors.Is`／`errors.As`** 辨識，**不要**把預期語意散落在魔術字串比對。
- **非預期**錯誤（I/O、第三方 SDK、程式缺陷）不強制新增 sentinel；應在邊界 **log** 後對外回傳 **泛用**錯誤（見下節）。若套件極小且沒有「可預期失敗」語意，**不要**為了慣例硬加空的 `errors.go`。

### 預期 vs 非預期

- **預期**：業務規則或輸入可預見的拒絕（例如範本路徑不合法、Protobuf 無法反序列化為約定訊息、物件不存在且屬合約內語意）。使用 sentinel／typed error，對 **gRPC** 對應適當 **codes** 與**穩定、不含敏感資料**的訊息（可略具體若已是公開合約）。
- **非預期**：資料庫／網路／儲存等未預期失敗。在 **handler 或最靠近邊界處** 以 **`pkg/traceid.LogUnexpected`**（或等價格式）記錄：`reason`（短）、`detail`（安全內部字串，通常為 `err.Error()`）、以及成對的 **非敏感** 索引欄位（例如 `topic=...`、`user_id_prefix=...` 前綴八碼、bucket 名稱），**不得**記錄秘密、token、完整 payload。對 **客戶端** 只回傳泛用訊息與 `Internal`（或適當 code），**不要**回傳 stack、不要回傳原始 `err.Error()`。

### Trace id

- **進入點**：`pkg/traceid` 提供 **`TraceIDFromContext`**（與 **`FromContext`** 同義）及 **`With`**。gRPC 上由 **`grpcutils.TraceUnaryInterceptor`** 注入：優先讀取 metadata **`x-trace-id`**、其次 **`x-request-id`**；皆無則產生新的 UUID 字串。
- **NATS 等無上游 metadata 的訊息**：`infra/nats` 對每則訊息以新 UUID 寫入 context，使訂閱端 log 仍能帶上 **`trace_id`**。
- **日誌格式範例**（非預期）：`unexpected trace_id=<id> reason=<短原因> detail=<內部說明> topic=mail.send.otp`（鍵值對可增減）。`pkg/grpc_utils` 的 **`LoggerInterceptor`** 會在 method 日誌附帶 **`trace_id=`**。

### Handler 與 gRPC 回應

- **大型 gRPC handler**：依關切點與檔案大小將 RPC 實作拆成同套件多檔（例如 CRUD、頭像、訂閱、內部錯誤輔助），維持單一 **`GRPCHandler`**／**`New*Handler`** 對外註冊面；避免單檔堆疊所有方法。
- Profile 等 gRPC handler 對非預期錯誤應透過 **`grpcutils.GRPCInternalError()`**（或等價）回傳 **`codes.Internal`** 與固定英文 **`internal error`**，與 **`RecoveryInterceptor`** 對 panic 的客戶端回應一致。
- Mailer 主題處理：`internal/mailer/handlers` 內 **`ErrMalformedMailEventPayload`** 等為預期錯誤根因（常與底層 `proto.Unmarshal` 以 **`errors.Join`** 合併）；SMTP 非驗證類失敗以 **`errors.Join(mailer.ErrEmailSendFailed, err)`** 保留語意並由基礎設施層 log。

## 設定（環境變數）

- 使用 **`github.com/kelseyhightower/envconfig`**，以 **`LoadConfig[T](prefix)`**（`pkg/shared`）載入。
- **Prefix 慣例**：服務專用前綴 + 底線，例如 `AUTHN_`、`PROFILE_`、`MAILER_`；結構體內欄位用 `envconfig` tag 對應去掉前綴後的環境變數名（例如 `PROFILE_DATABASE_URL` → 欄位 `DATABASE_URL`）。
- **Mailer（SMTP）**：`MAILER_NATS_URL`、`MAILER_SMTP_HOST`、`MAILER_SMTP_PORT`、`MAILER_SMTP_FROM`、選填 `MAILER_SMTP_USERNAME` / `MAILER_SMTP_PASSWORD` / `MAILER_SMTP_SSL`。
- **Profile 頭像（R2）**：`PROFILE_R2_ACCOUNT_ID`、`PROFILE_R2_ACCESS_KEY_ID`、`PROFILE_R2_SECRET_ACCESS_KEY`；暫存上傳桶 `PROFILE_R2_UPLOAD_BUCKET`、正式資產桶 `PROFILE_R2_ASSETS_BUCKET`、對外 CDN／資產基底 **`PROFILE_PUBLIC_ASSETS_URL`**（與 `object_key` 拼接產生對外 `avatar_url`；**不**將 OIDC `picture` 等第三方 URL 當作長期權威來源持久化）。

## 訊息與 NATS

- **介面**：`pkg/shared/pubsub.PubSub`（`Publish` / `Subscribe`）。
- **NATS 實作**：`infra/nats`（`NewNATSPubSub`）。
- **Redis KV**：`infra/redis`（`NewRedisKVStore`）；測試用記憶體實作在 `infra/mocked`（`NewMockKVStore`）。
- **SMTP 寄信**：郵件合約在 `pkg/shared/mailer`；SMTP 傳輸實作在 `infra/smtp`（`NewSMTPMailer`）。
- **物件儲存（S3 / R2）**：合約在 **`infra/r2`** 的 `interface.go`（`ObjectStore`、`ObjectHead`）；R2 實作為同套件 `objectstore.go` 的 `NewR2ObjectStore`（同一組帳號憑證，呼叫時傳入不同 bucket 名稱以區隔暫存與正式資產）；公開 URL 拼接見 `public_url.go` 的 `PublicObjectURL`。HTTP 404／物件不存在時實作會回傳 **`pkg/shared/storage.ErrObjectNotFound`**（見同模組 **`errors.go`**），供 handler 對應為客戶端安全訊息。
- **主題常數**：`pkg/shared/topics` 底下依領域分檔（如 `mail.go`、`profile.go`），字串格式為 **`domain.action`** 或更細的階層（參考 `mail.send.otp` 與 `profile.change`）。
- **Payload**：與 `internal/authn/infra/identity/email.go` 相同，使用 **Protobuf 序列化**（`google.golang.org/protobuf/proto.Marshal`）後再發布。

## 郵件範本（mailer）

- **內嵌資源**：`internal/templates` 以 `go:embed` 提供 `layouts/`、`pages/<名稱>/content.html|txt` 與 `locales/<語系>/<頁面>.json`。
- **`locale`／`page` 安全**：`Render` 會驗證兩者為單一路徑區段（拒絕空字串、`.`、`..`、含 `..` 子字串、斜線、反斜線與 NUL），避免目錄逃出嵌入範本樹；可偵測錯誤根因為同套件 **`errors.go`** 內之 `templates.ErrInvalidTemplatePath`（與 `interface.go` 同目錄）。
- **渲染**：`NewTemplateLoader` 回傳 `MailRenderer`；`internal/mailer/handlers` 透過 `TopicHandler` 訂閱 `mail.send.*` 主題後以 `Render(locale, page, data)` 產出 HTML／純文字／主旨，再填入 `pkg/shared/mailer.Message` 交 `infra/smtp` 寄送。

### Mailer 多事件版面（multi-event layout）

- **原則**：每個 NATS 主題／郵件情境各自有清楚歸屬；`internal/mailer/app` 只做 **組態、基礎設施建構與註冊**（`bootstrap.go`、`NewInfra`、`RegisterSubscribers`），不要把多種事件的解析、範本資料組裝、寄送邏輯塞在同一個巨大檔案。
- **子套件**：當 mailer 處理多個事件時，將 **該事件專屬邏輯** 放在 `internal/mailer/handlers/<事件短名>/`（例如 `handlers/otp/register.go`、`handlers/loginalert/register.go`）。共用合約在 **`internal/mailer/handlers`**：`MailerDeps`（`Mailer` + `MailRenderer`）、`TopicHandler`（`Topic`、`SubscribeOptions`、`Handle(ctx, deps, payload) error`），以及 **`RegisterTopicHandlers(pubsub, MailerDeps, ...TopicHandler)`** 負責逐一訂閱；各事件套件實作 **`TopicHandler` 的具體型別**（例如 `otp.Handler`、`loginalert.Handler`），在 `Handle` 內做 Protobuf 反序列化與寄送，避免 `handlers` 反向依賴 `app` 造成 import cycle。`internal/mailer/app/subscribers.go` 只組裝 `MailerDeps` 並呼叫 `handlers.RegisterTopicHandlers`。
- **訂閱選項**：`pkg/shared/pubsub.SubscribeOptions`（例如 `QueueGroup`）由各 `TopicHandler.SubscribeOptions()` 回傳；`infra/nats` 依此選擇一般訂閱或 queue 訂閱。訊息處理錯誤由 `Handle` 以 `error` 回傳，NATS 實作層會記錄含主題的 log。
- **何時再拆檔**：單一事件內若還有明顯子流程（例如驗證、範本 DTO、重試策略），再在該 handler 目錄下拆成多個 `.go` 檔；跨事件共用的寄送輔助函式可放在 `internal/mailer/...` 的共用小套件或同層 `internal` 工具檔（仍應保持單一職責）。

### 領域模組 vs 服務專屬程式（domain modules）

- **跨服務／可測的處理鏈**（例如：點陣圖解碼、裁切、縮放、編碼 WebP）應放在 **`internal/<領域能力>/`** 這類「能力套件」，以 **介面** 描述行為、以 **獨立檔案** 放具體實作；gRPC／HTTP 服務只依賴介面，並在 **`bootstrap` 或 `New*App`** 注入實作（便於單元測試替換、也避免業務套件塞滿影像演算法）。
- **命名**：本倉 avatar 管線使用 **`RasterAvatarProcessor`**（`ProcessToSquareWebP`）：語意上強調「點陣大頭貼」而非泛用任意向量或 PDF；預設實作為 **`WebPRasterAvatarProcessor`**（`internal/media`），與 Protobuf／Ent 無耦合，僅處理 bytes 與 Content-Type。可預期的像素／MIME 失敗語意見 **`internal/media/errors.go`**（例如 `ErrRasterDecodeFailed`），與 `interface.go` 同目錄。
- **安全（CompleteAvatarUpload）**：以 **R2 `HeadObject` 的 `ContentLength` 為唯一權威**（客戶端 `byte_size` 僅能與其一致）；下載本體長度須與 HEAD 一致。`internal/media` 的 **`ValidateAvatarStagingObject`** 負責 magic-byte 辨識（JPEG/PNG/GIF/WebP）、對已知 raster 的 **HEAD `Content-Type` 與 sniff 交叉比對**、對前綴再跑 **`http.DetectContentType` 與 sniff 互相佐證**，並在完整 raster 解碼前以 **`DecodeConfig` + 像素上限**（見 `raster_limits.go`）阻擋異常尺寸／解壓炸彈類風險；`ProcessToSquareWebP` 內仍會再做一層處理前驗證以防繞過。完成後對 **`user_avatars` 為 INSERT 新列**（append-only），不 UPDATE 既有 staging 列。
- **服務內常數**：staging 位元組上限與像素上限以 **`internal/media` 的常數**（`MaxAvatarStagingBytes`、`MaxRasterDimension`、`MaxRasterPixelCount`）為準；profile handler 僅組裝 `AvatarStagingTrust` 與讀取邊界。

### Ent（資料層）

- **Schema**：欄位型別、索引、`edge` 與 `internal/authn/ent/schema` 風格一致（UUID 主鍵、`created_at` / `updated_at` 等，**`UserAvatar` 僅 `created_at`、無 `updated_at`**）。指向「登入使用者／帳號主體」的外鍵欄位命名為 **`user_id`**（與 Protobuf `user_id`、JSON `userId` 對齊）；Ent 產生之 Go 欄位為 **`UserID`**。
- **遷移**：目前以 **`client.Schema.Create`** 於服務啟動時建立表（profile 服務在重啟時若表已存在會記錄 log 並略過常見的「已存在」錯誤）；正式環境建議後續導入 Atlas 或明確的 migration 流程。

## 使用者識別（user id）跨層命名

「同一個 UUID，語意上代表已註冊使用者（profile 服務的 `user_profiles.id`）」時，依層級使用下列 casing，**不要**混用 `profile_id` 等舊名：

| 層級 | 慣例 | 範例 |
|------|------|------|
| **Protobuf 欄位名**（buf 風格 snake_case） | `user_id` | `string user_id = 1;` |
| **JSON**（含 proto `json_name`、對外 REST 若沿用 proto JSON） | `userId` | `json=userId`（`user_id` 欄位預設對應 camelCase） |
| **手寫 Go**（變數／參數／非 protoc 產生之欄位） | `userID`（小寫 u）或匯出語意清楚的 `UserID` | `userID := uuid.Parse(...)` |

**與產生碼的差異**：`protoc-gen-go` 對 `user_id` 產生的 struct 欄位／getter 通常為 **`UserId`／`GetUserId()`**（產生器慣例）；呼叫端以產生碼為準。Ent 由 schema `field.UUID("user_id", ...)` 產生之欄位則為 **`UserID`**。應用層維持語意一致即可。

NATS 事件 payload 亦使用上述 Protobuf 訊息定義（例如 `api/proto/event/v1/profile.proto` 的 `user_id`）。

## 命名與程式風格（Go）

### 刻意捨棄回傳值與魔術字串

- **捨棄 `error`**：若語意上必須忽略（例如 `defer` 裡的 `Close`／`Rollback`），**不要**在各處重複 `_ = x()`；請用 **`pkg/errutil` 的 `Discard(err error)`**（或等價的單一集中輔助）表達「已知且刻意忽略」。若表達式可寫成**裸陳述式**（無須指派），則優先裸呼叫。
- **魔術字串**：重複出現或承載跨套件語意的字串，改為**具名常數**、**小套件內的鍵／路徑輔助**（例如頭像 object key 見 `internal/profile/avatarkey`），或沿用既有集中處（如 **`pkg/shared/topics`**）。僅單點使用且已封裝者，可用 `func Name() string { return "literal" }` 保留字面量。

- **可匯出 API**：簡潔英文，避免縮寫過度；錯誤處理對齊上文「`fmt.Errorf` 與錯誤鏈」一節（內層 sentinel／typed／`errors.Join`，頂層邊界才考慮單層包裝）。
- **gRPC handler**：實作對應的 `Unimplemented*Server` 嵌入型別，避免 forward-compat 編譯問題。
- **註解**：僅在商業規則或非顯而易見的整合點（例如 R2 presign、預設頭像策略）加上短說明即可。

## 與本文件一起參考的程式入口

- Profile gRPC 註冊：`internal/profile/app/service.go`
- Profile：`internal/profile/grpc`（套件 `profilegrpc`，gRPC RPC 與 gRPC 專用輔助）；`internal/profile/subscriber`（NATS 訂閱）；其餘組態／啟動／gRPC 伺服器包裝於 `internal/profile/app`。
- Profile 啟動／基礎設施：`internal/profile/app/bootstrap.go`、`cmd/profile/main.go`
- Authn 啟動／基礎設施：`internal/authn/app/bootstrap.go`、`cmd/authn/main.go`
- Authn 內部基建（OTP／transition／identity providers）：`internal/authn/infra/kv`、`internal/authn/infra/identity`
- Mailer（NATS → SMTP）：`internal/mailer/app/bootstrap.go`、`internal/mailer/app/subscribers.go`（僅註冊）、`internal/mailer/handlers/otp`、`internal/mailer/handlers/loginalert`、`cmd/mailer/main.go`
- 點陣頭像管線：`internal/media`（介面 `RasterAvatarProcessor`、預設 `WebPRasterAvatarProcessor`）；profile 於 `internal/profile/app/bootstrap.go` 注入
- Mailer 事件：`api/proto/event/v1/mail.proto`
- Profile 事件：`api/proto/event/v1/profile.proto`
- 主題常數：`pkg/shared/topics/profile.go`、`pkg/shared/topics/mail.go`
