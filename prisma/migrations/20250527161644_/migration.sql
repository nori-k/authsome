/*
  Warnings:

  - Changed the type of `provider` on the `Identity` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- CreateEnum
CREATE TYPE "ProviderType" AS ENUM ('email', 'google', 'apple', 'twitter');

-- AlterTable
ALTER TABLE "Identity" DROP COLUMN "provider",
ADD COLUMN     "provider" "ProviderType" NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Identity_provider_providerId_key" ON "Identity"("provider", "providerId");
