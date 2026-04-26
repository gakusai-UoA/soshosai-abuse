import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { EmailMessage } from 'cloudflare:email'

type EmailBinding = {
  send: (message: EmailMessage) => Promise<void>
}

// 環境変数の型定義
type Bindings = {
  // 32文字(256bit)の暗号化共有キー（wrangler.toml等で設定）
  ENCRYPTION_KEY: string
  // デプロイ時に埋め込むソースコミット
  SOURCE_COMMIT?: string
  // デプロイ時刻（UTC ISO8601）
  BUILD_AT?: string
  // 送信元メールアドレス（Cloudflareで認証済みドメイン）
  EMAIL_FROM?: string
  // Cloudflare Email Sending binding
  EMAIL: EmailBinding
  // 送信先メールアドレス群
  EMAIL_CHAIR: string
  EMAIL_VICE_CHAIR_1: string
  EMAIL_VICE_CHAIR_2: string
  EMAIL_VICE_CHAIR_3: string
  EMAIL_HEAD_PR: string
  EMAIL_HEAD_RESPONSE: string
  EMAIL_HEAD_PLAN_1: string
  EMAIL_HEAD_PLAN_2: string
  EMAIL_HEAD_IT: string
}

const app = new Hono<{ Bindings: Bindings }>()

const SOURCE_REPO_URL = 'https://github.com/gakusai-UoA/soshosai-abuse'
const DEFAULT_EMAIL_FROM = 'abuse-report@soshosai.com'

const getProvenance = (env: Bindings) => {
  const sourceCommit = env.SOURCE_COMMIT?.trim() || 'unknown'
  const buildAt = env.BUILD_AT?.trim() || 'unknown'
  const commitUrl =
    sourceCommit !== 'unknown'
      ? `${SOURCE_REPO_URL}/commit/${sourceCommit}`
      : SOURCE_REPO_URL

  return {
    sourceRepository: SOURCE_REPO_URL,
    sourceCommit,
    commitUrl,
    buildAt,
    verifiable: sourceCommit !== 'unknown',
  }
}

app.use('/api/*', cors())

app.use('*', async (c, next) => {
  await next()

  const provenance = getProvenance(c.env)
  c.res.headers.set('X-Source-Repo', provenance.sourceRepository)
  c.res.headers.set('X-Source-Commit', provenance.sourceCommit)
})

// 利用者が稼働中のコードを照合するための公開エンドポイント
app.get('/api/public/provenance', (c) => {
  const provenance = getProvenance(c.env)
  c.header('Cache-Control', 'no-store')

  return c.json({
    ...provenance,
    checkedAt: new Date().toISOString(),
  })
})

const EMAIL_ENV_KEYS = [
  'EMAIL_CHAIR',
  'EMAIL_VICE_CHAIR_1',
  'EMAIL_VICE_CHAIR_2',
  'EMAIL_VICE_CHAIR_3',
  'EMAIL_HEAD_PR',
  'EMAIL_HEAD_RESPONSE',
  'EMAIL_HEAD_PLAN_1',
  'EMAIL_HEAD_PLAN_2',
  'EMAIL_HEAD_IT',
] as const

// 環境変数の設定状態を確認するテスト用エンドポイント
app.get('/api/test/env', (c) => {
  const env = c.env as Record<string, unknown>
  const getString = (key: string) => {
    const value = env[key]
    return typeof value === 'string' ? value.trim() : ''
  }

  const encryptionKey = getString('ENCRYPTION_KEY')
  const emailFromOverride = getString('EMAIL_FROM')
  const effectiveEmailFrom = emailFromOverride || DEFAULT_EMAIL_FROM
  const sourceCommit = getString('SOURCE_COMMIT')
  const buildAt = getString('BUILD_AT')
  const sourceCommitLooksLikeSha = /^[0-9a-f]{40}$/i.test(sourceCommit)
  const encryptionKeyConfigured = encryptionKey.length > 0
  const emailFromConfigured = effectiveEmailFrom.length > 0
  const emailFromLooksLikeEmail = effectiveEmailFrom.includes('@')
  const emailBindingConfigured =
    typeof (env.EMAIL as { send?: unknown } | undefined)?.send === 'function'

  const missing: string[] = []
  const invalid: string[] = []

  if (!encryptionKeyConfigured) {
    missing.push('ENCRYPTION_KEY')
  } else if (encryptionKey.length < 32) {
    invalid.push('ENCRYPTION_KEY (32文字未満)')
  }

  if (emailFromOverride && !emailFromOverride.includes('@')) {
    invalid.push('EMAIL_FROM (メール形式ではない可能性)')
  }

  if (!emailFromLooksLikeEmail) {
    invalid.push('送信元メールアドレスが不正です')
  }

  if (!emailBindingConfigured) {
    invalid.push('EMAIL binding (未設定またはsend関数なし)')
  }

  if (!sourceCommit) {
    missing.push('SOURCE_COMMIT')
  } else if (!sourceCommitLooksLikeSha) {
    invalid.push('SOURCE_COMMIT (40桁SHA形式ではない)')
  }

  if (!buildAt) {
    missing.push('BUILD_AT')
  }

  const emails = Object.fromEntries(
    EMAIL_ENV_KEYS.map((key) => {
      const value = getString(key)
      const configured = value.length > 0
      const looksLikeEmail = configured && value.includes('@')

      if (!configured) {
        missing.push(key)
      } else if (!looksLikeEmail) {
        invalid.push(`${key} (メール形式ではない可能性)`)
      }

      return [
        key,
        {
          configured,
          looksLikeEmail,
        },
      ]
    }),
  )

  const ok = missing.length === 0 && invalid.length === 0

  return c.json(
    {
      ok,
      endpoint: '/api/test/env',
      encryptionKey: {
        configured: encryptionKeyConfigured,
        length: encryptionKey.length,
        recommendedMinLength: 32,
      },
      emailService: {
        bindingConfigured: emailBindingConfigured,
        from: {
          configured: emailFromConfigured,
          source: emailFromOverride ? 'EMAIL_FROM' : 'default',
          value: effectiveEmailFrom,
          looksLikeEmail: emailFromLooksLikeEmail,
        },
      },
      provenance: {
        sourceRepository: SOURCE_REPO_URL,
        sourceCommit: sourceCommit || 'unknown',
        sourceCommitLooksLikeSha,
        buildAt: buildAt || 'unknown',
      },
      emails,
      missing,
      invalid,
      checkedAt: new Date().toISOString(),
    },
    ok ? 200 : 500,
  )
})

// --- バックエンド：復号化ユーティリティ ---
async function decryptData(encryptedHex: string, ivHex: string, rawKey: string) {
  const keyBuffer = new TextEncoder().encode(rawKey.padEnd(32, '0').slice(0, 32))
  const key = await crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM' }, false, ['decrypt'])
  const encryptedBytes = new Uint8Array(encryptedHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)))
  const ivBytes = new Uint8Array(ivHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)))

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, encryptedBytes)
  return new TextDecoder().decode(decrypted)
}

// --- フロントエンド：UIコンポーネント (Hono/JSX) ---
const Layout = (props: { children: any }) => (
  <html lang="ja">
    <head>
      <meta charSet="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>コンプライアンス・ハラスメント相談窓口 | 蒼翔祭実行委員会</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 text-gray-800 font-sans p-4 md:p-8">
      <div class="max-w-2xl mx-auto bg-white p-6 md:p-8 rounded-lg shadow-md">{props.children}</div>
    </body>
  </html>
)

// トップページのルーティング（フォーム表示）
app.get('/', (c) => {
  // クライアント側で暗号化するためのキーを安全に渡す（実運用では公開鍵暗号方式RSA等を推奨）
  const clientKey = c.env.ENCRYPTION_KEY || 'default_secret_key_32_chars_long!'

  return c.html(
    <Layout>
      <h1 class="text-2xl font-bold text-red-600 mb-4">コンプライアンス相談窓口</h1>
      <p class="mb-6 text-sm text-gray-600">
        学園祭実行委員会での活動において、ハラスメントや規程違反に関する報告を行うための匿名フォームです。入力データはブラウザ上で暗号化されてから送信され、データベース等には一切保存されません。
      </p>

      <div class="mb-6 rounded-md border border-gray-200 bg-gray-50 p-4">
        <p class="text-sm text-gray-700">利用者が挙動を確認できるよう、このフォームの実装は公開しています。</p>
        <a
          href={SOURCE_REPO_URL}
          target="_blank"
          rel="noopener noreferrer"
          class="mt-2 inline-block text-sm font-semibold text-blue-700 underline"
        >
          GitHubでソースコードを見る
        </a>
        <div id="deployedCommitInfo" class="mt-2 text-xs text-gray-600">稼働コミットを確認中...</div>
      </div>

      <form id="reportForm" class="space-y-5">
        <div>
          <label class="block font-semibold mb-1">送信先（必須）</label>
          <p class="text-xs text-gray-500 mb-2">報告を直接確認する担当者を1名選択してください。他の委員に内容が漏れることはありません。</p>
          <select id="destinationKey" required class="w-full border-gray-300 rounded-md p-2 border">
            <option value="" disabled selected>
              担当者を選択してください
            </option>
            <option value="chair">委員長 (前野)</option>
            <option value="vice_chair_1">副委員長（中村）</option>
            <option value="vice_chair_2">副委員長（竹尾）</option>
            <option value="vice_chair_3">副委員長（山崎）</option>
            <option value="head_pr">広報部門長 (小森)</option>
            <option value="head_response">対応部門長 (植村)</option>
            <option value="head_plan_1">第一企画部門長 (平井)</option>
            <option value="head_plan_2">第二企画部門長 (杉林)</option>
            <option value="head_it">IT部門長 (羽尻)</option>
            <option value="other">その他（外部のメールアドレスを直接指定）</option>
          </select>
        </div>

        <div id="otherEmailWrapper" class="hidden">
          <label class="block font-semibold mb-1">送信先メールアドレス（必須）</label>
          <input type="email" id="otherEmail" placeholder="例: example@gmail.com" class="w-full border-gray-300 rounded-md p-2 border" />
        </div>

        <div>
          <label class="block font-semibold mb-1">ハラスメントの種類（必須）</label>
          <select id="harassmentType" required class="w-full border-gray-300 rounded-md p-2 border">
            <option value="" disabled selected>
              種類を選択してください
            </option>
            <option value="パワーハラスメント">パワーハラスメント</option>
            <option value="セクシュアルハラスメント">セクシュアルハラスメント</option>
            <option value="モラルハラスメント">モラルハラスメント</option>
            <option value="差別的言動">差別的言動</option>
            <option value="SNS・オンライン上の嫌がらせ">SNS・オンライン上の嫌がらせ</option>
            <option value="その他">その他</option>
          </select>
        </div>

        <div>
          <label class="block font-semibold mb-1">求める対応（必須）</label>
          <select id="requestedResponse" required class="w-full border-gray-300 rounded-md p-2 border">
            <option value="" disabled selected>
              希望する対応を選択してください
            </option>
            <option value="相談のみ（記録のみ）">相談のみ（記録のみ）</option>
            <option value="事実確認をしてほしい">事実確認をしてほしい</option>
            <option value="相手への注意・指導をしてほしい">相手への注意・指導をしてほしい</option>
            <option value="接触を避けるための調整をしてほしい">接触を避けるための調整をしてほしい</option>
            <option value="正式な調査をしてほしい">正式な調査をしてほしい</option>
            <option value="外部窓口へ連携してほしい">外部窓口へ連携してほしい</option>
          </select>
        </div>

        <div>
          <label class="block font-semibold mb-1">事象の詳細（必須）</label>
          <textarea
            id="incidentDetails"
            required
            rows={5}
            placeholder="いつ、どこで、誰から、どのような事があったか具体的にご記入ください。"
            class="w-full border-gray-300 rounded-md p-2 border"
          ></textarea>
        </div>

        <div>
          <label class="block font-semibold mb-1">加害者の氏名・所属（任意）</label>
          <input type="text" id="accusedName" class="w-full border-gray-300 rounded-md p-2 border" />
        </div>

        <div>
          <label class="block font-semibold mb-1">あなたの連絡先メールアドレス（任意）</label>
          <p class="text-xs text-gray-500 mb-1">※必要に応じて窓口担当者から連絡するために使用します。未入力の場合は完全匿名となります。</p>
          <input type="email" id="reporterEmail" class="w-full border-gray-300 rounded-md p-2 border" />
        </div>

        <button type="submit" class="w-full bg-red-600 text-white font-bold py-3 px-4 rounded hover:bg-red-700 transition">
          暗号化して送信する
        </button>
      </form>

      <div id="statusMessage" class="mt-4 font-bold text-center hidden"></div>

      {/* クライアントサイドの処理スクリプト */}
      <script
        dangerouslySetInnerHTML={{
          __html: `
        const select = document.getElementById('destinationKey');
        const otherEmailWrapper = document.getElementById('otherEmailWrapper');

        select.addEventListener('change', (e) => {
          if (e.target.value === 'other') {
            otherEmailWrapper.classList.remove('hidden');
            document.getElementById('otherEmail').required = true;
          } else {
            otherEmailWrapper.classList.add('hidden');
            document.getElementById('otherEmail').required = false;
          }
        });

        // 稼働中のコミット情報を表示（公開コードとの照合用）
        (async () => {
          const infoEl = document.getElementById('deployedCommitInfo');
          if (!infoEl) return;

          try {
            const res = await fetch('/api/public/provenance');
            const data = await res.json();

            if (data?.sourceCommit && data.sourceCommit !== 'unknown') {
              infoEl.innerHTML = '稼働コミット: <a class="underline text-blue-700" href="' + data.commitUrl + '" target="_blank" rel="noopener noreferrer">' + data.sourceCommit.slice(0, 12) + '</a>';
            } else {
              infoEl.textContent = '稼働コミット: 未設定（管理者に確認してください）';
            }
          } catch (e) {
            infoEl.textContent = '稼働コミット情報の取得に失敗しました。';
          }
        })();

        // 共通鍵暗号化処理（AES-GCM）
        async function encryptData(text, rawKey) {
          const keyBuffer = new TextEncoder().encode(rawKey.padEnd(32, '0').substring(0, 32));
          const key = await crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM' }, false, ['encrypt']);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const encodedText = new TextEncoder().encode(text);
          const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encodedText);

          return {
            encryptedHex: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join(''),
            ivHex: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
          };
        }

        document.getElementById('reportForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const btn = e.target.querySelector('button');
          btn.disabled = true;
          btn.innerText = '暗号化および送信中...';

          const payload = {
            destinationKey: document.getElementById('destinationKey').value,
            otherEmail: document.getElementById('otherEmail').value,
            harassmentType: document.getElementById('harassmentType').value,
            requestedResponse: document.getElementById('requestedResponse').value,
            incidentDetails: document.getElementById('incidentDetails').value,
            accusedName: document.getElementById('accusedName').value,
            reporterEmail: document.getElementById('reporterEmail').value,
          };

          try {
            // ペイロードをJSON化して暗号化
            const jsonString = JSON.stringify(payload);
            const encryptedData = await encryptData(jsonString, '${clientKey}');

            const res = await fetch('/api/report', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(encryptedData) // 暗号化されたデータのみを送信
            });

            const result = await res.json();
            const statusMsg = document.getElementById('statusMessage');
            statusMsg.classList.remove('hidden');

            if (res.ok) {
              statusMsg.innerText = '報告を安全に送信しました。';
              statusMsg.classList.add('text-green-600');
              e.target.reset();
            } else {
              statusMsg.innerText = 'エラー: ' + result.error;
              statusMsg.classList.add('text-red-600');
            }
          } catch (err) {
            alert('送信に失敗しました。ネットワークを確認してください。');
          } finally {
            btn.disabled = false;
            btn.innerText = '送信する';
          }
        });
        `,
        }}
      ></script>
    </Layout>
  )
})

// --- バックエンド：APIエンドポイント ---
app.post('/api/report', async (c) => {
  try {
    const { encryptedHex, ivHex } = await c.req.json()

    // 環境変数からキーを取得して復号化
    const secretKey = c.env.ENCRYPTION_KEY || 'default_secret_key_32_chars_long!'
    const decryptedJson = await decryptData(encryptedHex, ivHex, secretKey)
    const body = JSON.parse(decryptedJson)

    const { destinationKey, otherEmail, harassmentType, requestedResponse, incidentDetails, accusedName, reporterEmail } = body

    // 宛先の決定ロジック
    let targetEmail = ''
    let destinationName = ''

    switch (destinationKey) {
      case 'chair':
        targetEmail = c.env.EMAIL_CHAIR
        destinationName = '委員長'
        break
      case 'vice_chair_1':
        targetEmail = c.env.EMAIL_VICE_CHAIR_1
        destinationName = '副委員長 (中村)'
        break
      case 'vice_chair_2':
        targetEmail = c.env.EMAIL_VICE_CHAIR_2
        destinationName = '副委員長 (竹尾)'
        break
      case 'vice_chair_3':
        targetEmail = c.env.EMAIL_VICE_CHAIR_3
        destinationName = '副委員長 (山崎)'
        break
      case 'head_pr':
        targetEmail = c.env.EMAIL_HEAD_PR
        destinationName = '広報部門長 (小森)'
        break
      case 'head_response':
        targetEmail = c.env.EMAIL_HEAD_RESPONSE
        destinationName = '対応部門長 (植村)'
        break
      case 'head_plan_1':
        targetEmail = c.env.EMAIL_HEAD_PLAN_1
        destinationName = '第一企画部門長 (平井)'
        break
      case 'head_plan_2':
        targetEmail = c.env.EMAIL_HEAD_PLAN_2
        destinationName = '第二企画部門長 (杉林)'
        break
      case 'head_it':
        targetEmail = c.env.EMAIL_HEAD_IT
        destinationName = 'IT部門長 (羽尻)'
        break
      case 'other':
        if (!otherEmail || !otherEmail.includes('@')) {
          return c.json({ error: '有効な送信先メールアドレスが指定されていません。' }, 400)
        }
        targetEmail = otherEmail
        destinationName = '指定された外部アドレス'
        break
      default:
        return c.json({ error: '無効な送信先が選択されました。' }, 400)
    }

    if (!harassmentType || !requestedResponse) {
      return c.json({ error: 'ハラスメントの種類と求める対応を選択してください。' }, 400)
    }

    const adminEmailText = `
【コンプライアンス窓口：新規報告（親展）】

本メールは指定された窓口担当者（${destinationName}）のみに送信されています。
情報漏洩に厳重に注意し、対象者の保護を最優先に対応してください。

■ 加害者の氏名・所属（任意）
${accusedName || '未入力'}

■ ハラスメントの種類（必須）
${harassmentType}

■ 求める対応（必須）
${requestedResponse}

■ 事象の詳細
${incidentDetails}

■ 報告者の連絡先（任意）
${reporterEmail || '未入力（完全匿名での報告）'}
    `.trim()

    // 担当者へ送信（実際のメール送信関数に置き換えてください）
    await sendEmail(c.env, targetEmail, '【重要/親展】ハラスメント・コンプライアンス報告', adminEmailText)

    return c.json({ success: true })
  } catch (err) {
    console.error('Decryption or processing failed:', err)
    return c.json({ error: 'データの復号化または処理に失敗しました。' }, 500)
  }
})

const sanitizeHeaderValue = (value: string) => value.replace(/[\r\n]+/g, ' ').trim()

// Cloudflare Email Sending binding を使ったメール送信関数
async function sendEmail(env: Bindings, to: string, subject: string, text: string) {
  const from = env.EMAIL_FROM?.trim() || DEFAULT_EMAIL_FROM

  if (!from.includes('@')) {
    throw new Error('送信元メールアドレスが不正な形式です。')
  }

  const safeFrom = sanitizeHeaderValue(from)
  const safeTo = sanitizeHeaderValue(to)
  const safeSubject = sanitizeHeaderValue(subject)

  if (!safeTo || !safeTo.includes('@')) {
    throw new Error('送信先メールアドレスが不正です。')
  }

  const rawMessage = [
    `From: ${safeFrom}`,
    `To: ${safeTo}`,
    `Subject: ${safeSubject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    text,
  ].join('\r\n')

  const message = new EmailMessage(safeFrom, safeTo, rawMessage)

  await env.EMAIL.send(message)
}

export default app