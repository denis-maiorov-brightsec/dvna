import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;
const poolSize = process.env.SECTESTER_SCAN_POOL_SIZE ? +process.env.SECTESTER_SCAN_POOL_SIZE || undefined : undefined;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /app/modifyproduct', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'csrf',
        'id_enumeration',
        'bopla',
        'sqli',
        'html_injection',
        'xss',
        'proto_pollution',
        'business_constraint_bypass'
      ],
      attackParamLocations: [AttackParamLocation.BODY],
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
      url: `${baseUrl}/app/modifyproduct`,
      body: {
        id: '123',
        code: 'PRD-1001',
        name: 'Sample Product',
        description: 'Sample product description',
        tags: 'demo,sample'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});