// src/types/nestjs-config.d.ts
import 'nestjs-config';
declare module '@nestjs/config' {
  interface ConfigService {
    get<T = string>(_propertyPath: string): T;
  }
}
