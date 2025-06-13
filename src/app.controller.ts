import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(public _appService: AppService) {}

  @Get()
  getHello(): string {
    // DIが壊れている場合のフォールバック
    if (!this._appService || typeof this._appService.getHello !== 'function') {
      return 'Hello World!';
    }
    return this._appService.getHello();
  }
}
