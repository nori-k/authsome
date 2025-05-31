# authsome（日本語版）

NestJS + Fastify + Prisma認証バックエンド

---

## 概要

- **TypeScript/Node.js (Node 24)**
- **NestJS (Fastifyプラットフォーム)**
- **Prisma ORM/PostgreSQL**
- メール/パスワード認証
- Google/Apple OAuth認証
- FIDO2/パスキー（WebAuthn）対応
- JWT/リフレッシュトークン管理
- 高い型安全性、厳格なESLint、テストカバレッジ
- Fastify特有の型、厳密なDTOバリデーション
- CI/CD、自動テスト、自動マイグレーション推奨

---

## フロントエンドについて

`frontend/` ディレクトリはauthsomeバックエンドAPIと連携するサンプルWebクライアント（SPA）です。

- **主な目的**: 認証API（メール/パスワード、OAuth、パスキー）やユーザー管理APIのUI例・動作検証
- **技術スタック**: **静的HTML/JavaScriptデモ**（`frontend/public/index.html`と`script.js`を参照。React/ViteではなくシンプルなSPAデモ）
- **API連携**: `script.js`内でfetchを使い`/auth/*`エンドポイントを呼び出し
- **認証フロー**: CookieベースのJWT/リフレッシュトークン管理、OAuthリダイレクト、パスキー/WebAuthn対応

### 使い方

```bash
cd frontend
pnpm install
pnpm run dev
```

- フロントエンドは `http://localhost:8080` で起動（Docker利用時は自動公開）
- バックエンド（authsome）は `http://localhost:3000` で起動
- **APIサーバーURLは `frontend/public/script.js` の `API_BASE_URL` で設定**
- Docker利用時はfrontend/backendが一括起動

### 主な機能

- ユーザー登録/ログイン（メール/パスワード）
- Google/Apple OAuth認証
- パスキー（FIDO2/WebAuthn）登録/ログイン
- プロフィール・連携ID管理
- APIレスポンス表示・エラー例

### バックエンド連携例

```js
// 例: メール/パスワードログイン
fetch(`${API_BASE_URL}/auth/login/email-password`, {
  method: 'POST',
  credentials: 'include', // Cookie送信
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password }),
});
```

- パスキー/WebAuthnは `@simplewebauthn/browser` などのSDKも参照
- OAuthはリダイレクトURL・コールバックハンドラ実装が必要

### ビルド・デプロイ

```bash
pnpm run build
# 静的ファイルは dist/ に出力
```

- 本番運用時は `frontend/dist` をNginx等で静的配信し、APIはバックエンドへリバースプロキシ
- CORSやCookieのsecure/sameSite設定に注意

---

## セットアップ

```bash
# Node.js 24推奨（mise, nvm等で管理）
pnpm install

# .envファイル作成（推奨）
pnpm run gen:jwt-secret-env # .envとJWTシークレットを自動生成
# または
cp .env.example .env
```

- **mise（[https://mise.jdx.dev/](https://mise.jdx.dev/)）でNode.js, pnpm, Prisma, TypeScript, Postgresのバージョン管理推奨。`mise.toml`参照**
- PostgreSQLが必要（ローカルは `docker-compose up -d` 推奨）
- DBスキーマは `prisma/schema.prisma` で管理
- DB接続/JWTシークレット/OAuthクレデンシャル等は`.env`で設定

---

## Docker Compose（ローカル開発推奨）

```bash
docker-compose up -d
```

- バックエンド（NestJS）、フロントエンド（静的デモ）、PostgreSQL DBを一括起動
- フロントエンド: `http://localhost:8080`、バックエンドAPI: `http://localhost:3000`
- `.env`はbackend/frontend両方に自動反映
- 停止は `docker-compose down`

---

## OAuthクレデンシャル取得

### Google OAuth

1. [Google Cloud Console](https://console.cloud.google.com/apis/credentials)でプロジェクト作成/選択
2. 「認証情報」→「OAuth 2.0 クライアントIDを作成」
3. アプリケーション種別:「ウェブアプリケーション」
4. `http://localhost:3000/api/auth/google/callback`等をリダイレクトURIに追加
5. 発行された「クライアントID」「クライアントシークレット」を`.env`の`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`に設定

### Apple OAuth

1. [Apple Developer](https://developer.apple.com/account/resources/identifiers/list/serviceId)でServices ID作成
2. Key ID, Team ID, P8秘密鍵を発行
3. `.env`の`APPLE_CLIENT_ID`/`APPLE_TEAM_ID`/`APPLE_KEY_ID`/`APPLE_PRIVATE_KEY`に設定（P8は1行で）

---

## JWTシークレット自動生成

- `JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET`は十分長いランダム文字列を推奨
- 下記コマンドで安全なシークレットを.envに自動生成・設定可能

```sh
pnpm run gen:jwt-secret-env
```

- `.env`が無い場合は`.env.example`から生成し、該当行を安全な値で上書き
- 既存`.env`がある場合も該当行のみ安全に上書き

---

## 開発・運用

- **ホットリロード**: `pnpm run start:dev` で自動再起動
- **ESLint/Prettier**: 厳格な型・フォーマットチェック
- **テスト**: ユニット/E2E/カバレッジ対応
- **Prisma**: 自動マイグレーション・型生成
- **Fastify**: 高速・型安全なAPIサーバー
- **CI/CD**: lint/test/build自動化

---

## 主要スクリプト

- 開発サーバー: `pnpm run start:dev`
- 本番ビルド: `pnpm run build && pnpm run start:prod`
- Lint: `pnpm run lint`
- フォーマット: `pnpm run format`
- ユニットテスト: `pnpm run test`
- E2Eテスト: `pnpm run test:e2e`
- カバレッジ: `pnpm run test:cov`
- Prismaマイグレーション: `pnpm exec prisma migrate dev`
- Prisma型生成: `pnpm exec prisma generate`

---

## APIエンドポイント例

### メール/パスワード認証

- `POST /auth/register/email-password` : 登録
- `POST /auth/login/email-password` : ログイン
- `POST /auth/logout` : ログアウト
- `POST /auth/refresh-tokens` : トークン再発行

### OAuth認証

- `GET /auth/google` : Google認証開始
- `GET /auth/google/callback` : Google認証コールバック
- `GET /auth/apple` : Apple認証開始
- `POST /auth/apple/callback` : Apple認証コールバック

### パスキー（FIDO2）

- `POST /auth/passkey/register/start` : 登録オプション取得
- `POST /auth/passkey/register/finish` : 登録完了
- `POST /auth/passkey/login/start` : ログインオプション取得
- `POST /auth/passkey/login/finish` : ログイン完了
- `GET /auth/passkey/credentials` : 登録済みパスキー一覧
- `DELETE /auth/passkey/credentials/:id` : パスキー削除

### プロフィール・ID管理

- `GET /auth/profile` : プロフィール取得
- `GET /auth/identities` : 連携ID一覧
- `DELETE /auth/identities/:id` : 連携ID削除

---

## テスト・カバレッジ

```bash
pnpm run test        # ユニットテスト
pnpm run test:e2e    # E2Eテスト
pnpm run test:cov    # カバレッジ
```

- Jestによるユニット/E2E/カバレッジ対応
- `src/auth/auth.controller.spec.ts`等で厳密な型安全テスト
- E2Eテストは`test/app.e2e-spec.ts`
- カバレッジ出力は`coverage/`配下HTML

---

## セキュリティ・運用Tips

- JWT/Cookie: httpOnly, secure, sameSite等を厳格に設定
- シークレットは.envで管理（JWT_SECRET, DB接続, OAuthクレデンシャル等）
- **.envやシークレットはgit管理しないこと**
- Apple OAuth P8キー等は安全に保管
- Fastifyのみ、厳格なESLint/型チェック
- Prismaマイグレーション・型生成は自動化
- 本番はFastify logger有効化
- DBコネクションプール・ヘルスチェックも適宜設定
- CORS/Cookie/CSRF設定は本番運用に合わせて見直し

---

## FAQ・トラブルシューティング

### Q. テストが失敗する

- DB状態や`.env`設定を確認
- Prismaマイグレーション・型生成を再実行
- Docker利用時は全コンテナが正常か確認

### Q. OAuth/パスキー認証が動作しない

- Google/Apple OAuthクレデンシャルやWebAuthn RP_ID/ORIGINが`.env`で正しいか確認
- ブラウザ/クライアント側の挙動も確認
- OAuthはリダイレクトURIがGoogle/Appleコンソール登録値と一致しているか確認

### Q. Dockerコンテナが起動しない

- ポート競合（3000, 8080, 5432等）を確認
- Docker Desktop等が起動しているか確認
- `docker-compose logs`でログ確認

### Q. フロントエンドからAPIリクエストが失敗（CORSや401）

- `frontend/public/script.js`の`API_BASE_URL`がバックエンドURLと一致しているか確認
- バックエンドのCORS/Cookie設定を確認

---

## コントリビュート・開発Tips

- CIでlint/format/test自動化
- DTO/サービス/コントローラーの型安全性・テスト担保
- PR前にtest/coverage/ESLintパスを確認
- Issue/PR/コントリビュート歓迎！

---

## 参考リンク

- [NestJS公式](https://docs.nestjs.com/)
- [Fastify公式](https://www.fastify.io/docs/latest/)
- [Prisma公式](https://www.prisma.io/docs/)
- [SimpleWebAuthn (FIDO2)](https://simplewebauthn.dev/)
- [pnpm公式](https://pnpm.io/)

---

## ライセンス

MIT

---
