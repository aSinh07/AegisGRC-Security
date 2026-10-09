import test from 'node:test';
import assert from 'node:assert/strict';
import { mapFinding } from '../src/grc.js';

test('maps XSS to OWASP injection and ISO/NIST controls', () => {
  const f: any = {
    id: '1',
    assessmentId: 'a',
    source: 'wapiti',
    title: 'Cross Site Scripting',
    description: 'CWE-79 XSS',
    severity: 'HIGH',
    asset: 'x',
    evidenceHash: 'h',
    createdAt: new Date().toISOString(),
    mappings: {},
  };

  const m = mapFinding(f);
  assert.ok(m.mappings.owasp?.includes('A03 Injection'));
  assert.ok((m.mappings.iso27001?.length ?? 0) > 0);
  assert.ok((m.mappings.nist?.length ?? 0) > 0);
});
