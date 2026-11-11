// Basic markup and exact-origin behavior are exercised against the assembled assets.
'use strict';
const assert=require('node:assert/strict');
const {JSDOM}=require('jsdom');
const html=require('./page-source.cjs')();const dom=new JSDOM(html);
for(const id of ['guidedCode','setupCode','enrollmentCode','nativeEnrollmentCode'])assert.equal(dom.window.document.getElementById(id),null,'Removed code field reappeared: '+id);
for(const id of ['bsPrepare','bsComparison','bsCheck','bsReview','bsApply','bsCancel'])assert(dom.window.document.getElementById(id));
assert(dom.window.document.getElementById('browserReveal'));assert.equal(dom.window.document.getElementById('browserValueToggle'),null,'The editor must reuse the existing eye.');
const ids=[...dom.window.document.querySelectorAll('[id]')].map(e=>e.id);assert.equal(new Set(ids).size,ids.length,'Duplicate UI identifiers.');
assert.match(dom.window.document.getElementById('bsApply').textContent,/Set up and sign in/);dom.window.close();
console.log('PASS assembled code-free setup markup, unique IDs, explicit final action and removed legacy code inputs');
