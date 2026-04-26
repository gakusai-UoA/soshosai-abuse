```txt
npm install
npm run dev
```

```txt
npm run deploy
```

## 透明性について

このプロジェクトは、利用者が実装内容を確認できるようにソースコードを公開しています。

- 公開リポジトリ: https://github.com/gakusai-UoA/soshosai-abuse
- フォーム画面にも同じリンクを表示しています。

利用者が確認しやすい観点:

- 入力データはクライアント側で暗号化して送信していること
- サーバー側で宛先決定とメール送信を行っていること
- データ保存処理（DB書き込み）が実装されていないこと

## 稼働コードの検証方法

利用者が「公開されているコードが実際に動いているか」を確認できるよう、以下を提供しています。

- 公開検証エンドポイント: `/api/public/provenance`
- レスポンスヘッダー: `X-Source-Repo`, `X-Source-Commit`

### 管理者側（デプロイ時）

コミットIDをWorkerに埋め込んでデプロイします。

```txt
npm run deploy:verified
```

上記は `SOURCE_COMMIT`（Gitコミット）と `BUILD_AT`（UTC時刻）を設定します。

### 利用者側（照合手順）

1. 稼働中サイトの `/api/public/provenance` を開く
2. 返ってきた `sourceCommit` を確認する
3. `https://github.com/gakusai-UoA/soshosai-abuse/commit/<sourceCommit>` を開いて内容を確認する

`sourceCommit` が `unknown` の場合は、検証可能なデプロイになっていません。

[For generating/synchronizing types based on your Worker configuration run](https://developers.cloudflare.com/workers/wrangler/commands/#types):

```txt
npm run cf-typegen
```

Pass the `CloudflareBindings` as generics when instantiation `Hono`:

```ts
// src/index.ts
const app = new Hono<{ Bindings: CloudflareBindings }>()
```
