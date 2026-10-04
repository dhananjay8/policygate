import { Injectable, Logger } from '@nestjs/common';
import type { AuthorizationDecisionLog } from '../authorization/authorization.types';

/**
 * Replaceable sink for decision logs. Swap in Winston/Pino/OTel/Kafka/SIEM
 * by providing your own implementation of this token.
 *
 * NEVER log tokens, secrets, API keys, passwords, or unnecessary PII.
 */
export interface AuthorizationDecisionLogger {
  log(decision: AuthorizationDecisionLog): Promise<void>;
}

@Injectable()
export class ConsoleDecisionLogger implements AuthorizationDecisionLogger {
  private readonly logger = new Logger('AuthorizationDecision');

  async log(decision: AuthorizationDecisionLog): Promise<void> {
    const line = JSON.stringify(decision);
    if (decision.decision === 'ALLOW') this.logger.log(line);
    else this.logger.warn(line);
  }
}

@Injectable()
export class NoopDecisionLogger implements AuthorizationDecisionLogger {
  async log(_decision: AuthorizationDecisionLog): Promise<void> {
    /* intentionally empty */
  }
}
