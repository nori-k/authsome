import { Test, type TestingModule } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
const request = require('supertest');
import type { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { ConfigService } from '@nestjs/config';

describe('AppController (e2e)', () => {
  let app: INestApplication<App>;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(ConfigService)
      .useValue({
        get: (key: string) => {
          if (key === 'JWT_ACCESS_SECRET') {
            return process.env.JWT_ACCESS_SECRET || 'test-secret';
          }
          return undefined;
        },
      })
      .compile();

    const { FastifyAdapter } = await import('@nestjs/platform-fastify');
    const adapter = new FastifyAdapter();
    app = moduleFixture.createNestApplication(adapter);
    await app.init();
    await app.listen(0); // Fastifyサーバを明示的に起動
  });

  afterAll(async () => {
    await app.close(); // サーバをクリーンアップ
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });
});
