import { Hono } from 'hono'
import { sValidator } from '@hono/standard-validator'
import { EmailMessage } from 'cloudflare:email'
import { z } from 'zod'

type EmailBinding = {
  send: (message: EmailMessage) => Promise<void>
}

// 環境変数の型定義
type Bindings = {
  // デプロイ時に埋め込むソースコミット
  SOURCE_COMMIT?: string
  // デプロイ時刻（UTC ISO8601）
  BUILD_AT?: string
  // 診断エンドポイント保護トークン（未設定時はエンドポイント無効）
  DIAG_TOKEN?: string
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

const ALLOWED_HARASSMENT_TYPES = [
  'パワーハラスメント',
  'セクシュアルハラスメント',
  'モラルハラスメント',
  '差別的言動',
  'SNS・オンライン上の嫌がらせ',
  'その他',
] as const

const ALLOWED_REQUESTED_RESPONSES = [
  '相談のみ（記録のみ）',
  '事実確認をしてほしい',
  '相手への注意・指導をしてほしい',
  '接触を避けるための調整をしてほしい',
  '正式な調査をしてほしい',
  '外部窓口へ連携してほしい',
] as const

const DESTINATION_KEYS = [
  'chair',
  'vice_chair_1',
  'vice_chair_2',
  'vice_chair_3',
  'head_pr',
  'head_response',
  'head_plan_1',
  'head_plan_2',
  'head_it',
] as const

type DestinationKey = (typeof DESTINATION_KEYS)[number]

const DESTINATION_LABELS: Record<DestinationKey, string> = {
  chair: '委員長 (前野)',
  vice_chair_1: '副委員長（中村）',
  vice_chair_2: '副委員長（竹尾）',
  vice_chair_3: '副委員長（山崎）',
  head_pr: '広報部門長 (小森)',
  head_response: '対応部門長 (植村)',
  head_plan_1: '第一企画部門長 (平井)',
  head_plan_2: '第二企画部門長 (杉林)',
  head_it: 'IT部門長 (羽尻)',
}

const reportPayloadSchema = z.object({
  destinationKeys: z.array(z.enum(DESTINATION_KEYS)).min(1, '送信先を1件以上選択してください。').max(9),
  escalationDestinationKeys: z.array(z.enum(DESTINATION_KEYS)).max(9).optional().default([]),
  harassmentType: z.enum(ALLOWED_HARASSMENT_TYPES),
  requestedResponse: z.enum(ALLOWED_REQUESTED_RESPONSES),
  incidentDetails: z.string().trim().min(1, '事象の詳細を入力してください。').max(4000, '事象の詳細が長すぎます。'),
  accusedName: z.string().trim().max(200, '加害者情報は200文字以内で入力してください。').optional().default(''),
  reporterEmail: z
    .union([z.literal(''), z.string().trim().email('連絡先メールアドレスの形式が不正です。')])
    .optional()
    .default(''),
})

type RuntimeConfigCheck = {
  ok: boolean
  missing: string[]
  invalid: string[]
  emailService: {
    bindingConfigured: boolean
    from: {
      configured: boolean
      source: 'EMAIL_FROM' | 'default'
      value: string
      looksLikeEmail: boolean
    }
  }
  provenance: {
    sourceRepository: string
    sourceCommit: string
    sourceCommitLooksLikeSha: boolean
    buildAt: string
  }
  emails: Record<string, { configured: boolean; looksLikeEmail: boolean }>
}

const checkRuntimeConfig = (env: Bindings): RuntimeConfigCheck => {
  const getString = (key: string) => {
    const value = (env as Record<string, unknown>)[key]
    return typeof value === 'string' ? value.trim() : ''
  }

  const emailFromOverride = getString('EMAIL_FROM')
  const effectiveEmailFrom = emailFromOverride || DEFAULT_EMAIL_FROM
  const sourceCommit = getString('SOURCE_COMMIT')
  const buildAt = getString('BUILD_AT')
  const sourceCommitLooksLikeSha = /^[0-9a-f]{40}$/i.test(sourceCommit)
  const emailFromConfigured = effectiveEmailFrom.length > 0
  const emailFromLooksLikeEmail = effectiveEmailFrom.includes('@')
  const emailBindingConfigured = typeof env.EMAIL?.send === 'function'

  const missing: string[] = []
  const invalid: string[] = []

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

  return {
    ok,
    missing,
    invalid,
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
  }
}

// 環境変数の設定状態を確認するテスト用エンドポイント
app.get('/api/test/env', (c) => {
  const env = c.env as Record<string, unknown>
  const getString = (key: string) => {
    const value = env[key]
    return typeof value === 'string' ? value.trim() : ''
  }

  const diagToken = getString('DIAG_TOKEN')
  const providedToken = (c.req.header('x-diag-token') || c.req.query('token') || '').trim()

  if (!diagToken || providedToken !== diagToken) {
    return c.notFound()
  }
  const runtimeConfig = checkRuntimeConfig(c.env)

  return c.json(
    {
      ok: runtimeConfig.ok,
      endpoint: '/api/test/env',
      emailService: runtimeConfig.emailService,
      provenance: runtimeConfig.provenance,
      emails: runtimeConfig.emails,
      missing: runtimeConfig.missing,
      invalid: runtimeConfig.invalid,
      checkedAt: new Date().toISOString(),
    },
    runtimeConfig.ok ? 200 : 500,
  )
})

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
  const runtimeConfig = checkRuntimeConfig(c.env)

  return c.html(
    <Layout>
      <h1 class="text-2xl font-bold text-red-600 mb-4">コンプライアンス相談窓口</h1>
      <p class="mb-6 text-sm text-gray-600">
        学園祭実行委員会での活動において、ハラスメントや規程違反に関する報告を行うための匿名フォームです。通信はHTTPSで保護され、データベース等には一切保存されません。
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

      <div class={`mb-6 rounded-md border p-4 text-sm ${runtimeConfig.ok ? 'border-green-200 bg-green-50 text-green-800' : 'border-red-200 bg-red-50 text-red-800'}`}>
        {runtimeConfig.ok
          ? '送信システムの設定チェックに成功しました。'
          : '現在、送信システムの設定に不備があるため受付を停止しています。時間をおいて再度お試しください。'}
      </div>

      <form id="reportForm" class="space-y-5">
        <div>
          <label class="block font-semibold mb-1">送信先（必須）</label>
          <p class="text-xs text-gray-500 mb-2">報告を直ちに送信する担当者を1名以上選択してください。</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 rounded-md border border-gray-300 p-3">
            {DESTINATION_KEYS.map((key) => (
              <label class="inline-flex items-center gap-2 text-sm" key={`now-${key}`}>
                <input type="checkbox" name="destinationKeys" value={key} class="h-4 w-4" />
                <span>{DESTINATION_LABELS[key]}</span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <label class="block font-semibold mb-1">将来のエスカレーション候補（任意）</label>
          <p class="text-xs text-gray-500 mb-2">ここで選んだ相手には現時点では送信されません。必要時の連携候補として記録されます。</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 rounded-md border border-gray-300 p-3">
            {DESTINATION_KEYS.map((key) => (
              <label class="inline-flex items-center gap-2 text-sm" key={`esc-${key}`}>
                <input type="checkbox" name="escalationDestinationKeys" value={key} class="h-4 w-4" />
                <span>{DESTINATION_LABELS[key]}</span>
              </label>
            ))}
          </div>
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

        <button type="submit" disabled={!runtimeConfig.ok} class={`w-full text-white font-bold py-3 px-4 rounded transition ${runtimeConfig.ok ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-400 cursor-not-allowed'}`}>
          送信する
        </button>
      </form>

      <div id="statusMessage" class="mt-4 font-bold text-center hidden"></div>

      {/* クライアントサイドの処理スクリプト */}
      <script
        dangerouslySetInnerHTML={{
          __html: `
        const canSubmit = ${runtimeConfig.ok ? 'true' : 'false'};

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

        if (!canSubmit) {
          const statusMsg = document.getElementById('statusMessage');
          statusMsg.classList.remove('hidden');
          statusMsg.classList.add('text-red-600');
          statusMsg.innerText = '現在、送信システムの設定不備により受付を停止しています。';
        }

        document.getElementById('reportForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          if (!canSubmit) return;

          const btn = e.target.querySelector('button');
          btn.disabled = true;
          btn.innerText = '送信中...';

          const destinationKeys = Array.from(document.querySelectorAll('input[name="destinationKeys"]:checked')).map((el) => el.value);
          const escalationDestinationKeys = Array.from(document.querySelectorAll('input[name="escalationDestinationKeys"]:checked')).map((el) => el.value);

          if (destinationKeys.length === 0) {
            const statusMsg = document.getElementById('statusMessage');
            statusMsg.classList.remove('hidden');
            statusMsg.classList.add('text-red-600');
            statusMsg.innerText = '送信先を1件以上選択してください。';
            btn.disabled = false;
            btn.innerText = '送信する';
            return;
          }

          const payload = {
            destinationKeys,
            escalationDestinationKeys,
            harassmentType: document.getElementById('harassmentType').value,
            requestedResponse: document.getElementById('requestedResponse').value,
            incidentDetails: document.getElementById('incidentDetails').value,
            accusedName: document.getElementById('accusedName').value,
            reporterEmail: document.getElementById('reporterEmail').value,
          };

          try {
            const res = await fetch('/api/report', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
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
app.post(
  '/api/report',
  sValidator('json', reportPayloadSchema, (result, c) => {
    if (!result.success) {
      const firstIssue = result.error[0]
      return c.json({ error: firstIssue?.message || '入力内容を確認してください。' }, 400)
    }
  }),
  async (c) => {
    try {
      const {
        destinationKeys,
        escalationDestinationKeys,
        harassmentType,
        requestedResponse,
        incidentDetails,
        accusedName,
        reporterEmail,
      } = c.req.valid('json')

      const destinationMap: Record<DestinationKey, { email: string; name: string }> = {
        chair: { email: c.env.EMAIL_CHAIR, name: DESTINATION_LABELS.chair },
        vice_chair_1: { email: c.env.EMAIL_VICE_CHAIR_1, name: DESTINATION_LABELS.vice_chair_1 },
        vice_chair_2: { email: c.env.EMAIL_VICE_CHAIR_2, name: DESTINATION_LABELS.vice_chair_2 },
        vice_chair_3: { email: c.env.EMAIL_VICE_CHAIR_3, name: DESTINATION_LABELS.vice_chair_3 },
        head_pr: { email: c.env.EMAIL_HEAD_PR, name: DESTINATION_LABELS.head_pr },
        head_response: { email: c.env.EMAIL_HEAD_RESPONSE, name: DESTINATION_LABELS.head_response },
        head_plan_1: { email: c.env.EMAIL_HEAD_PLAN_1, name: DESTINATION_LABELS.head_plan_1 },
        head_plan_2: { email: c.env.EMAIL_HEAD_PLAN_2, name: DESTINATION_LABELS.head_plan_2 },
        head_it: { email: c.env.EMAIL_HEAD_IT, name: DESTINATION_LABELS.head_it },
      }

      const uniqueDestinationKeys = [...new Set(destinationKeys)] as DestinationKey[]
      const uniqueEscalationKeys = [...new Set(escalationDestinationKeys)] as DestinationKey[]

      const immediateDestinations = uniqueDestinationKeys.map((key) => ({ key, ...destinationMap[key] }))

      const invalidImmediate = immediateDestinations.find((d) => !d.email || !d.email.includes('@'))
      if (invalidImmediate) {
        return c.json({ error: `送信先メール設定が不正です: ${invalidImmediate.name}` }, 500)
      }

      const escalationNames = uniqueEscalationKeys.map((key) => destinationMap[key].name)

      const adminEmailText = `
【コンプライアンス窓口：新規報告（親展）】

本メールは指定された窓口担当者にのみ送信されています。
情報漏洩に厳重に注意し、対象者の保護を最優先に対応してください。

■ 今回送信した宛先（複数）
${immediateDestinations.map((d) => `- ${d.name}`).join('\n')}

■ 将来のエスカレーション候補（今回は未送信）
${escalationNames.length > 0 ? escalationNames.map((name) => `- ${name}`).join('\n') : '未選択'}

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

      // 今回送信対象にのみ送る（エスカレーション候補は未送信）
      await Promise.all(
        immediateDestinations.map((destination) =>
          sendEmail(c.env, destination.email, '【重要/親展】ハラスメント・コンプライアンス報告', adminEmailText),
        ),
      )

      return c.json({ success: true, sentCount: immediateDestinations.length })
    } catch (err) {
      console.error('Report processing failed:', err)
      return c.json({ error: 'データの処理に失敗しました。' }, 500)
    }
  },
)

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