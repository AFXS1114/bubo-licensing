import { createClient } from '@libsql/client';
import { readFile } from 'node:fs/promises';

const url = process.env.TURSO_DATABASE_URL;
const token = process.env.TURSO_AUTH_TOKEN;
if (!url || !token) throw new Error('TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are required');
const db = createClient({ url, authToken: token });
const tables = await db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
if (tables.rows.length) {
  console.log(`Deleting ${tables.rows.length} Turso tables and all data...`);
  for (const row of tables.rows) await db.execute(`DROP TABLE IF EXISTS "${String(row.name).replaceAll('"','""')}"`);
}
const schema = await readFile(new URL('../sql/001_turso_schema.sql', import.meta.url), 'utf8');
for (const statement of schema.split(';').map(x => x.trim()).filter(Boolean)) await db.execute(statement);
console.log('Turso database reset and schema initialized.');
