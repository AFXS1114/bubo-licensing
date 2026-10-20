import { createClient, type Client } from '@libsql/client';

const url = process.env.TURSO_DATABASE_URL;
const token = process.env.TURSO_AUTH_TOKEN;
if (!url || !token || token.startsWith('replace-with-')) throw new Error('A real TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are required');

export const db: Client = createClient({
  url,
  authToken: token,
});

export function sql(text: string, values: unknown[] = []) {
  const statement = text.replace(/\$(\d+)/g, '?$1');
  const args = values.map(value => value === undefined ? null : value);
  return { sql: statement, args: args as any[] };
}

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export async function query<T = any>(text: string, values: unknown[] = []) {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const result = await db.execute(sql(text, values));
      return { rows: result.rows as unknown as T[], rowCount: result.rows.length };
    } catch (error) {
      lastError = error;
      if (attempt < 2) await delay(250 * (attempt + 1));
    }
  }
  throw lastError;
}

export async function exec(text: string) {
  for (const statement of text.split(';').map(x => x.trim()).filter(Boolean)) await db.execute(statement);
}
