import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const port = Number(process.env.PORT ?? 3200);
  await app.listen(port, '0.0.0.0');

  console.log(
    `demo-billing-service listening on :${port} (AUTHZ_MODE=${process.env.AUTHZ_MODE ?? 'local'})`,
  );
}

void bootstrap();
