import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const caddy=fs.readFileSync(new URL('../deploy/Caddyfile.production',import.meta.url),'utf8');

test('production Caddy policy preserves the accepted strict script boundary',()=>{
  assert.match(caddy,/reverse_proxy aegis:8080/);
  assert.match(caddy,/Content-Security-Policy/);
  assert.match(caddy,/script-src 'self';/);
  assert.doesNotMatch(caddy,/script-src 'self' 'unsafe-inline'/);
  assert.match(caddy,/style-src 'self' 'unsafe-inline'/);
  assert.match(caddy,/Strict-Transport-Security "max-age=31536000; includeSubDomains"/);
  assert.match(caddy,/-Server/);
});
