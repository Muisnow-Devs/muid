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

## gRPC

- **攔截器鏈**：與 `internal/authn/app/service.go` 相同，使用 `pkg/grpc_utils` 的 `RecoveryInterceptor`、`LoggerInterceptor`、`TimeoutInterceptor`。
- **逾時**：由設定的 `*_REQUEST_TIMEOUT_SECONDS`（authn 為 `AUTHN_`，profile 為 `PROFILE_`）控制。
- **錯誤**：優先使用 `google.golang.org/grpc/status` 的標準 codes（例如 `InvalidArgument`、`NotFound`、`AlreadyExists`、`FailedPrecondition`）。

## 設定（環境變數）

- 使用 **`github.com/kelseyhightower/envconfig`**，以 **`LoadConfig[T](prefix)`**（`pkg/shared`）載入。
- **Prefix 慣例**：服務專用前綴 + 底線，例如 `AUTHN_`、`PROFILE_`、`MAILER_`；結構體內欄位用 `envconfig` tag 對應去掉前綴後的環境變數名（例如 `PROFILE_DATABASE_URL` → 欄位 `DATABASE_URL`）。
- **Mailer（SMTP）**：`MAILER_NATS_URL`、`MAILER_SMTP_HOST`、`MAILER_SMTP_PORT`、`MAILER_SMTP_FROM`、選填 `MAILER_SMTP_USERNAME` / `MAILER_SMTP_PASSWORD` / `MAILER_SMTP_SSL`。
- **Profile 頭像（R2）**：`PROFILE_R2_ACCOUNT_ID`、`PROFILE_R2_ACCESS_KEY_ID`、`PROFILE_R2_SECRET_ACCESS_KEY`；暫存上傳桶 `PROFILE_R2_UPLOAD_BUCKET`、正式資產桶 `PROFILE_R2_ASSETS_BUCKET`、對外網址前綴 `PROFILE_PUBLIC_ASSETS_URL`（用於 `avatar_url` 與資產桶 key 拼接）。

## 訊息與 NATS

- **介面**：`pkg/shared/pubsub.PubSub`（`Publish` / `Subscribe`）。
- **NATS 實作**：`infra/nats`（`NewNATSPubSub`）。
- **Redis KV**：`infra/redis`（`NewRedisKVStore`）；測試用記憶體實作在 `infra/mocked`（`NewMockKVStore`）。
- **SMTP 寄信**：郵件合約在 `pkg/shared/mailer`；SMTP 傳輸實作在 `infra/smtp`（`NewSMTPMailer`）。
- **物件儲存（S3 / R2）**：合約在 **`infra/r2`** 的 `interface.go`（`ObjectStore`、`ObjectHead`）；R2 實作為同套件 `objectstore.go` 的 `NewR2ObjectStore`（同一組帳號憑證，呼叫時傳入不同 bucket 名稱以區隔暫存與正式資產）；公開 URL 拼接見 `public_url.go` 的 `PublicObjectURL`。
- **主題常數**：`pkg/shared/topics` 底下依領域分檔（如 `mail.go`、`profile.go`），字串格式為 **`domain.action`** 或更細的階層（參考 `mail.send.otp` 與 `profile.change`）。
- **Payload**：與 `internal/authn/infra/identity/email.go` 相同，使用 **Protobuf 序列化**（`google.golang.org/protobuf/proto.Marshal`）後再發布。

## 郵件範本（mailer）

- **內嵌資源**：`internal/templates` 以 `go:embed` 提供 `layouts/`、`pages/<名稱>/content.html|txt` 與 `locales/<語系>/<頁面>.json`。
- **`locale`／`page` 安全**：`Render` 會驗證兩者為單一路徑區段（拒絕空字串、`.`、`..`、含 `..` 子字串、斜線、反斜線與 NUL），避免目錄逃出嵌入範本樹；可偵測錯誤根因為 `templates.ErrInvalidTemplatePath`。
- **渲染**：`NewTemplateLoader` 回傳 `MailRenderer`；`internal/mailer/handlers` 透過 `TopicHandler` 訂閱 `mail.send.*` 主題後以 `Render(locale, page, data)` 產出 HTML／純文字／主旨，再填入 `pkg/shared/mailer.Message` 交 `infra/smtp` 寄送。

### Mailer 多事件版面（multi-event layout）

- **原則**：每個 NATS 主題／郵件情境各自有清楚歸屬；`internal/mailer/app` 只做 **組態、基礎設施建構與註冊**（`bootstrap.go`、`NewInfra`、`RegisterSubscribers`），不要把多種事件的解析、範本資料組裝、寄送邏輯塞在同一個巨大檔案。
- **子套件**：當 mailer 處理多個事件時，將 **該事件專屬邏輯** 放在 `internal/mailer/handlers/<事件短名>/`（例如 `handlers/otp/register.go`、`handlers/loginalert/register.go`）。共用合約在 **`internal/mailer/handlers`**：`MailerDeps`（`Mailer` + `MailRenderer`）、`TopicHandler`（`Topic`、`SubscribeOptions`、`Handle(ctx, deps, payload) error`），以及 **`RegisterTopicHandlers(pubsub, MailerDeps, ...TopicHandler)`** 負責逐一訂閱；各事件套件實作 **`TopicHandler` 的具體型別**（例如 `otp.Handler`、`loginalert.Handler`），在 `Handle` 內做 Protobuf 反序列化與寄送，避免 `handlers` 反向依賴 `app` 造成 import cycle。`internal/mailer/app/subscribers.go` 只組裝 `MailerDeps` 並呼叫 `handlers.RegisterTopicHandlers`。
- **訂閱選項**：`pkg/shared/pubsub.SubscribeOptions`（例如 `QueueGroup`）由各 `TopicHandler.SubscribeOptions()` 回傳；`infra/nats` 依此選擇一般訂閱或 queue 訂閱。訊息處理錯誤由 `Handle` 以 `error` 回傳，NATS 實作層會記錄含主題的 log。
- **何時再拆檔**：單一事件內若還有明顯子流程（例如驗證、範本 DTO、重試策略），再在該 handler 目錄下拆成多個 `.go` 檔；跨事件共用的寄送輔助函式可放在 `internal/mailer/...` 的共用小套件或同層 `internal` 工具檔（仍應保持單一職責）。

### 領域模組 vs 服務專屬程式（domain modules）

- **跨服務／可測的處理鏈**（例如：點陣圖解碼、裁切、縮放、編碼 WebP）應放在 **`internal/<領域能力>/`** 這類「能力套件」，以 **介面** 描述行為、以 **獨立檔案** 放具體實作；gRPC／HTTP 服務只依賴介面，並在 **`bootstrap` 或 `New*App`** 注入實作（便於單元測試替換、也避免業務套件塞滿影像演算法）。
- **命名**：本倉 avatar 管線使用 **`RasterAvatarProcessor`**（`ProcessToSquareWebP`）：語意上強調「點陣大頭貼」而非泛用任意向量或 PDF；預設實作為 **`WebPRasterAvatarProcessor`**（`internal/media`），與 Protobuf／Ent 無耦合，僅處理 bytes 與 Content-Type。
- **服務內常數**：與儲存流程綁定的限制（例如 staging 物件讀取上限）可留在該服務的 handler；與像素／編碼品質相關的預設則放在 `internal/media` 實作側，必要時再透過建構子或選項擴充。

### Ent（資料層）

- **Schema**：欄位型別、索引、`edge` 與 `internal/authn/ent/schema` 風格一致（UUID 主鍵、`created_at` / `updated_at` 等）。指向「登入使用者／帳號主體」的外鍵欄位命名為 **`user_id`**（與 Protobuf `user_id`、JSON `userId` 對齊）；Ent 產生之 Go 欄位為 **`UserID`**。
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

- **可匯出 API**：簡潔英文，避免縮寫過度；錯誤用 `fmt.Errorf` 包裝上下文。
- **gRPC handler**：實作對應的 `Unimplemented*Server` 嵌入型別，避免 forward-compat 編譯問題。
- **註解**：僅在商業規則或非顯而易見的整合點（例如 R2 presign、identicon 策略）加上短說明即可。

## 與本文件一起參考的程式入口

- Profile gRPC 註冊：`internal/profile/app/service.go`
- Profile 業務邏輯：`internal/profile/app/handler.go`
- Profile 啟動／基礎設施：`internal/profile/app/bootstrap.go`、`cmd/profile/main.go`
- Authn 啟動／基礎設施：`internal/authn/app/bootstrap.go`、`cmd/authn/main.go`
- Authn 內部基建（OTP／transition／identity providers）：`internal/authn/infra/kv`、`internal/authn/infra/identity`
- Mailer（NATS → SMTP）：`internal/mailer/app/bootstrap.go`、`internal/mailer/app/subscribers.go`（僅註冊）、`internal/mailer/handlers/otp`、`internal/mailer/handlers/loginalert`、`cmd/mailer/main.go`
- 點陣頭像管線：`internal/media`（介面 `RasterAvatarProcessor`、預設 `WebPRasterAvatarProcessor`）；profile 於 `internal/profile/app/bootstrap.go` 注入
- Mailer 事件：`api/proto/event/v1/mail.proto`
- Profile 事件：`api/proto/event/v1/profile.proto`
- 主題常數：`pkg/shared/topics/profile.go`、`pkg/shared/topics/mail.go`
