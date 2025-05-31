const fs = require('fs');
const path = require('path');

const envPath = path.resolve(__dirname, '../.env');
const envExamplePath = path.resolve(__dirname, '../.env.example');
const secret1 = require('crypto').randomBytes(64).toString('base64');
const secret2 = require('crypto').randomBytes(64).toString('base64');

const updateEnvFile = (envFilePath) => {
  const envRaw = fs.readFileSync(envFilePath, 'utf8');
  let updated = false;
  const env = envRaw
    .replace(/JWT_ACCESS_SECRET=".*"/, () => {
      updated = true;
      return `JWT_ACCESS_SECRET="${secret1}"`;
    })
    .replace(/JWT_REFRESH_SECRET=".*"/, () => {
      updated = true;
      return `JWT_REFRESH_SECRET="${secret2}"`;
    });
  if (!updated) {
    console.error(
      'JWT_ACCESS_SECRET/JWT_REFRESH_SECRET の行が見つかりませんでした。',
    );
    process.exit(1);
  }
  fs.writeFileSync(envFilePath, env, 'utf8');
  console.log('.envファイルのJWTシークレットを更新しました。');
};

if (!fs.existsSync(envPath)) {
  if (!fs.existsSync(envExamplePath)) {
    console.error('.envも.env.exampleも存在しません。処理を中断します。');
    process.exit(1);
  }
  fs.copyFileSync(envExamplePath, envPath);
  console.log('.envがなかったため.env.exampleからコピーしました。');
}
updateEnvFile(envPath);
