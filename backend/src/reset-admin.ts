import { createClient } from '@libsql/client';
import argon2 from 'argon2';

const email = process.env.ADMIN_EMAIL || 'admin@bubo.com';
const password = process.env.ADMIN_PASSWORD || '12345678';
const db = createClient({ url: process.env.TURSO_DATABASE_URL!, authToken: process.env.TURSO_AUTH_TOKEN! });
const hash = await argon2.hash(password, { type: argon2.argon2id });
const result = await db.execute({
  sql: "UPDATE admins SET password_hash = ?, role = 'SUPER_ADMIN', status = 'ACTIVE', updated_at = datetime('now') WHERE lower(email) = lower(?)",
  args: [hash, email],
});
if (result.rowsAffected !== 1) throw new Error(`Admin not found: ${email}`);
console.log(`Password updated for ${email}`);
