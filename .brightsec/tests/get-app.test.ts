import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = (() => {
  const value = Number(process.env.SECTESTER_SCAN_POOL_SIZE);
  return value ? value : undefined;
})();

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /app/', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'http_method_fuzzing',
        'unvalidated_redirect',
        'html_injection',
        'xss',
        'server_side_js_injection',
        'open_database',
        'secret_tokens'
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER, AttackParamLocation.PATH, AttackParamLocation.BODY, AttackParamLocation.FRAGMENT],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/dvna:master',
        databases: ['MySQL', 'Sequelize'],
        user_roles: ['admin']
      },
      poolSize
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/app/`
    });
});