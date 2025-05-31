// scripts/show-simplewebauthn-types.ts
import type { verifyAuthenticationResponse } from '@simplewebauthn/server';

// 型定義を出力して確認するためのスクリプト
// tscで型エラーが出る場合は、型定義の確認用

// verifyAuthenticationResponseの型定義を型エイリアスとしてexport
export type VerifyAuthParams = Parameters<
  typeof verifyAuthenticationResponse
>[0];
// 型定義はtscで確認してください。
