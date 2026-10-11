const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const schema = JSON.parse(fs.readFileSync(path.join(__dirname, '../schemas/application.schema.json'), 'utf8'));
const directory = schema.properties.launchers.items.properties.workingDirectory;
const pattern = new RegExp(directory.pattern);
const valid = ['Artha/bin', 'Program Files/Example', 'resources', 'App.1/bin'];
const invalid = ['', '.', '..', '../other', 'Artha/../other', 'Artha/./bin',
  'Artha//bin', 'Artha/bin/', '/tmp', 'C:/Artha', 'C:\\Artha', 'Artha\\bin',
  'Artha/\0bin', 'Artha/bin\n', 'Artha\n/../bin', 'Artha\n/bin\0',
  'Artha\n/bin\\other', 'Artha\n/bin:other', 'Artha/bin\t', 'Artha/bin\x7f'];
for (const value of valid) assert.equal(pattern.test(value), true, JSON.stringify(value));
for (const value of invalid) assert.equal(pattern.test(value), false, JSON.stringify(value));
console.log(`${valid.length + invalid.length} launcher directory schema cases passed`);
