import { NestFactory } from '@nestjs/core';
import { FastifyAdapter } from '@nestjs/platform-fastify';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import type { Server } from 'http';
import type { AddressInfo } from 'net';
import fastifyCookie from '@fastify/cookie';
import fastifyCors from '@fastify/cors';
// import type { FastifyInstance } from 'fastify';

async function bootstrap(): Promise<void> {
  const adapter = new FastifyAdapter();
  const fastify = adapter.getInstance();
  await fastify.register(fastifyCookie, {
    secret: process.env.COOKIE_SECRET ?? 'default_secret',
  });
  // CORS設定をFastifyに登録
  await fastify.register(fastifyCors, {
    origin: true,
    credentials: true,
  });
  const app = await NestFactory.create(AppModule, adapter);
  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
  // ポート番号を明示的にLoggerで出力
  const server = app.getHttpServer() as Server;
  const address = server.address() as AddressInfo | null;
  if (address && typeof address === 'object' && 'port' in address) {
    Logger.log(`Server listening on port: ${address.port}`, 'NestApplication');
  } else {
    Logger.log('Server started (port unknown)', 'NestApplication');
  }
}

void bootstrap();
