import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = Number(process.env.SECTESTER_SCAN_POOL_SIZE);

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('GET /', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'http_method_fuzzing',
        'xss',
        'html_injection',
        'full_path_disclosure',
        'open_database',
        'secret_tokens',
        'jwt',
        'improper_asset_management'
      ],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/dvna:master',
        databases: ['MySQL', 'Sequelize'],
        user_roles: ['admin']
      },
      poolSize: poolSize ? poolSize : undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/`,
      headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        Connection: 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
      }
    });
});