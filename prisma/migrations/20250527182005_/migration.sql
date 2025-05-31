/*
  Warnings:

  - The values [twitter] on the enum `ProviderType` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "ProviderType_new" AS ENUM ('email', 'google', 'apple');
ALTER TABLE "Identity" ALTER COLUMN "provider" TYPE "ProviderType_new" USING ("provider"::text::"ProviderType_new");
ALTER TYPE "ProviderType" RENAME TO "ProviderType_old";
ALTER TYPE "ProviderType_new" RENAME TO "ProviderType";
DROP TYPE "ProviderType_old";
COMMIT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "password" TEXT;
