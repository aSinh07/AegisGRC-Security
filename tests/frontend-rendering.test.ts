import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
test('dashboard HTML has no literal escaped newline between sections',async()=>{
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.doesNotMatch(html,/<\/section>\\n<section/);
});
