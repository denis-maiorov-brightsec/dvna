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

test('POST /register', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'html_injection',
        'xss',
        'proto_pollution',
        'nosql',
        'sqli',
        'email_injection',
        'secret_tokens'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'denis-maiorov-brightsec/dvna:master',
        databases: ['MySQL', 'Sequelize'],
        user_roles: ['admin']
      },
      poolSize: poolSize || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/register`,
      body: {
        name: 'John Doe',
        username: 'johndoe',
        email: 'john.doe@example.com',
        password: 'P@ssw0rd123',
        cpassword: 'P@ssw0rd123'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});