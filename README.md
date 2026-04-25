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

[For generating/synchronizing types based on your Worker configuration run](https://developers.cloudflare.com/workers/wrangler/commands/#types):

```txt
npm run cf-typegen
```

Pass the `CloudflareBindings` as generics when instantiation `Hono`:

```ts
// src/index.ts
const app = new Hono<{ Bindings: CloudflareBindings }>()
```
