import { Module } from '@nestjs/common';
import { AuthorizationModule, HeaderPrincipalResolver } from 'policygate';
import { AuthorizeController } from './authorize.controller';
import { buildRepositories } from './repositories.factory';

@Module({
  imports: [
    AuthorizationModule.forRoot({
      mode: 'local',
      serviceName: 'authorization-service',
      // The /v1/authorize endpoint accepts a principal in its body, so
      // principal resolution for THIS service's own routes is header-based.
      principalResolver: new HeaderPrincipalResolver(),
      repositories: buildRepositories(),
      logging: { enabled: process.env.AUTHZ_DECISION_LOGGING !== 'false' },
    }),
  ],
  controllers: [AuthorizeController],
})
export class AppModule {}
