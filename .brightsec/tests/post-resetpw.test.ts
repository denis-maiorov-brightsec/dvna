import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = process.env.SECTESTER_SCAN_POOL_SIZE ? Number(process.env.SECTESTER_SCAN_POOL_SIZE) || undefined : undefined;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /resetpw', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'html_injection',
        'xss',
        'id_enumeration',
        'sqli',
        'secret_tokens',
        'open_database'
      ],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.BODY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/resetpw?login=john.doe&token=4c2a8fe7eaf24721cc7a9f0175115bd4`,
      body: {
        password: 'NewP@ssw0rd123',
        cpassword: 'NewP@ssw0rd123',
        login: 'john.doe',
        token: '4c2a8fe7eaf24721cc7a9f0175115bd4'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});