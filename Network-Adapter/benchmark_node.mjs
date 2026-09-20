// Compatibility entrypoint: same complete matrix, never a Node-only ranking.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
const localPython = fileURLToPath(new URL('../.venv/bin/python', import.meta.url));
const python = process.env.PYTHON || (fs.existsSync(localPython) ? localPython : 'python3');
const child = spawn(python, [fileURLToPath(new URL('./benchmark_backends.py', import.meta.url)),
  ...process.argv.slice(2)], {stdio: 'inherit'});
// The common runner enforces the per-case process-group deadline.
child.on('error', error => {console.error(error.message); process.exitCode = 1;});
child.on('exit', code => {process.exitCode = code === null ? 1 : code;});
