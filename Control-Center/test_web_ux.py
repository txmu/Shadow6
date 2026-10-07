"""Small DOM harness for read-only dashboard recovery, without browser packages."""
from pathlib import Path
import shutil
import subprocess
import unittest


class WebUXTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node is unavailable for the JS DOM harness')
    def test_diagnostics_endpoint_formatting_and_disconnect_during_refresh(self):
        script = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor() { this.children = []; this.textContent = ''; this.dataset = {}; this.listeners = {}; this.attributes = {}; this.classList = {remove() {}}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
}
const elements = new Map();
const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
let requests = [];
const context = vm.createContext({navigator: {language: 'en', platform: 'test'},
  document: {getElementById: get, createElement: () => new Element(), querySelectorAll: () => [], documentElement: {}},
  Headers, AbortController, setTimeout, clearTimeout,
  fetch: () => new Promise(resolve => requests.push(resolve))});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
vm.runInContext(`renderProfiles({result: {profiles: [{core: 'cpp', profile: 'cpp-sctp-tls13',
  diagnostics: [{message: 'SCTP unavailable', action: 'Enable kernel SCTP.'}]}], availableProfiles: []}})`, context);
assert.equal(get('profile-total').textContent, '1');
assert.match(get('profiles').children[0].children[3].textContent, /Enable kernel SCTP/);
vm.runInContext(`renderServices({total: 1, offset: 0, items: [{name: 'home/nas', state: 'running',
  readiness: 'listener-ready', endpoint: {host: '127.0.0.1', port: 1234}}]})`, context);
assert.match(get('services').children[0].children[3].children[0].textContent, /listener-ready/);
assert.match(get('services').children[0].children[4].textContent, /127.0.0.1/);
assert.doesNotMatch(get('services').children[0].children[4].textContent, /object Object/);
const pending = vm.runInContext(`bearer = 'temporary-token'; refreshAll()`, context);
assert.equal(requests.length, 3);
get('disconnect').listeners.click();
for (const resolve of requests) resolve({ok: true, json: async () => ({result: {}, items: [], total: 0, offset: 0})});
pending.then(() => {
  assert.equal(get('service-total').textContent, '—');
  assert.equal(get('profile-total').textContent, '—');
  assert.equal(get('main').attributes['aria-busy'], 'false');
  assert.equal(get('previous').disabled, true);
  assert.equal(get('next').disabled, true);
  assert.equal(get('refresh').disabled, true);
  assert.equal(get('loading').hidden, true);
  assert.match(get('services').children[0].children[0].textContent, /View local status to load/);
  console.log('dashboard recovery passed');
}).catch(error => { console.error(error); process.exitCode = 1; });
'''
        result = subprocess.run(['node', '-e', script, str(Path(__file__).parent/'web/ui.js')],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dashboard recovery passed', result.stdout)


if __name__ == '__main__': unittest.main()
