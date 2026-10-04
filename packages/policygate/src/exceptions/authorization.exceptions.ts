import { HttpException, HttpStatus } from '@nestjs/common';

/** Safe, non-sensitive failed-check description for error responses. */
export interface FailedCheck {
  action: string;
  resource: string;
}

/** Policy allowed nothing -> 403. Internal policy details are never exposed. */
export class AuthorizationDeniedException extends HttpException {
  readonly failedChecks: FailedCheck[];

  constructor(failedChecks: FailedCheck[], message = 'Authorization failed') {
    super(
      {
        statusCode: HttpStatus.FORBIDDEN,
        error: 'Forbidden',
        code: 'AUTHORIZATION_DENIED',
        message,
        failedChecks,
      },
      HttpStatus.FORBIDDEN,
    );
    this.failedChecks = failedChecks;
  }
}

/** Identity could not be resolved at all -> 401. */
export class UnauthenticatedException extends HttpException {
  constructor(message = 'Authentication required') {
    super(
      {
        statusCode: HttpStatus.UNAUTHORIZED,
        error: 'Unauthorized',
        code: 'UNAUTHENTICATED',
        message,
      },
      HttpStatus.UNAUTHORIZED,
    );
  }
}

/** Evaluation infrastructure failure (PRP/PIP/PDP/remote). Fails closed -> 500. */
export class AuthorizationEvaluationException extends HttpException {
  constructor(message = 'Authorization evaluation failed', cause?: unknown) {
    super(
      {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        error: 'Internal Server Error',
        code: 'AUTHORIZATION_EVALUATION_FAILED',
        message,
      },
      HttpStatus.INTERNAL_SERVER_ERROR,
      cause instanceof Error ? { cause } : undefined,
    );
  }
}

/** Misconfigured module / malformed persisted policy. */
export class AuthorizationConfigurationException extends Error {
  readonly code = 'AUTHORIZATION_CONFIGURATION_ERROR';
  constructor(message: string) {
    super(message);
    this.name = 'AuthorizationConfigurationException';
  }
}
