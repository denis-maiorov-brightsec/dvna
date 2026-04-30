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

test('GET /resetpw?login=:login&token=:token', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'id_enumeration', 'html_injection', 'xss', 'secret_tokens', 'open_database'],
      attackParamLocations: [AttackParamLocation.QUERY],
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
      url: `${baseUrl}/resetpw?login=alice&token=c160f8cc69a4f0bf2b0362752353d060`
    });
});