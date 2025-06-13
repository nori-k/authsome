// Vitestのグローバルdescribe/it/expect/beforeEachを利用し、importはviのみ
import { vi } from 'vitest';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { Test, type TestingModule } from '@nestjs/testing';

describe('AppController', () => {
  let appController: AppController;
  let appServiceMock: { getHello: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    appServiceMock = { getHello: vi.fn().mockReturnValue('Hello World!') };
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [
        {
          provide: AppService,
          useValue: appServiceMock,
        },
      ],
    }).compile();

    appController = app.get<AppController>(AppController);
    // 依存注入が失敗する場合はprivateプロパティに直接代入
    appController._appService = appServiceMock;
  });

  describe('root', () => {
    it('should return "Hello World!"', () => {
      expect(appController.getHello()).toBe('Hello World!');
    });
  });
});
