import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import argon2 from 'argon2';
import { SignJWT, jwtVerify } from 'jose';
import { z } from 'zod';
import { query, db, exec } from './db.js';
import { readFile } from 'node:fs/promises';
import { hashSecret, makeLicenseSecret } from './security.js';

const app = Fastify({ logger: true });
const secret = new TextEncoder().encode(process.env.SESSION_SECRET || 'development-only-change-me');
await app.register(helmet); await app.register(cors, { origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(value => value.trim()) : true, credentials: true }); await app.register(cookie); await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

type Admin = { id: string; email: string; role: string };
async function session(admin: Admin) { return new SignJWT(admin).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('8h').sign(secret); }
async function auth(request: any, reply: any): Promise<Admin | undefined> { const token = request.cookies.bubo_session; if (!token) return reply.code(401).send({ error: 'UNAUTHORIZED' }); try { const { payload } = await jwtVerify(token, secret); return payload as unknown as Admin; } catch { return reply.code(401).send({ error: 'UNAUTHORIZED' }); } }
async function audit(admin: Admin, action: string, type: string, id: string, metadata: object = {}) { await query('INSERT INTO audit_logs(admin_id, action, target_type, target_id, metadata_json) VALUES($1,$2,$3,$4,$5)', [admin.id, action, type, id, JSON.stringify(metadata)]); }
function asIsoDate(value: unknown) { const text = String(value ?? ''); const date = /^\d+(\.\d+)?$/.test(text) ? new Date(Number(text)) : new Date(text); return Number.isNaN(date.getTime()) ? null : date.toISOString(); }
app.get('/health', async () => ({ status: 'ok', database: process.env.TURSO_DATABASE_URL ? 'turso' : 'missing' }));
app.post('/api/auth/login', async (request, reply) => { const body = z.object({ email: z.string().email(), password: z.string().min(6) }).parse(request.body); const result = await query<Admin & { password_hash: string }>('SELECT id,email,role,password_hash FROM admins WHERE email=$1', [body.email]); const admin = result.rows[0]; if (!admin || !(await argon2.verify(admin.password_hash, body.password))) return reply.code(401).send({ error: 'INVALID_CREDENTIALS' }); reply.setCookie('bubo_session', await session({ id: admin.id, email: admin.email, role: admin.role }), { httpOnly: true, sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', secure: process.env.NODE_ENV === 'production', path: '/', maxAge: 28800 }); return { admin: { id: admin.id, email: admin.email, role: admin.role } }; });
app.post('/api/auth/logout', async (_request, reply) => reply.clearCookie('bubo_session', { path: '/' }).send({ ok: true }));
app.get('/api/auth/me', async (request, reply) => { const admin = await auth(request, reply); return admin ? { admin } : undefined; });

app.get('/api/dashboard', async (request, reply) => { const admin = await auth(request, reply); if (!admin) return; const [counts, recent] = await Promise.all([query("SELECT COUNT(*) FILTER (WHERE status='ACTIVE') active, COUNT(*) FILTER (WHERE status='EXPIRED' OR datetime(expires_at) < datetime('now')) expired, COUNT(*) FILTER (WHERE datetime(expires_at) BETWEEN datetime('now') AND datetime('now','+30 days')) expiring FROM licenses"), query('SELECT action,target_type,target_id,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 8')]); return { counts: counts.rows[0], recent: recent.rows }; });
app.get('/api/customers', async (request, reply) => { if (!(await auth(request, reply))) return; const q = String((request.query as any)?.q || ''); return (await query('SELECT c.*, COUNT(l.id) license_count FROM customers c LEFT JOIN licenses l ON l.customer_id=c.id WHERE c.name LIKE $1 OR c.customer_code LIKE $1 GROUP BY c.id ORDER BY c.created_at DESC', [`%${q}%`])).rows; });
app.post('/api/customers', async (request, reply) => { const admin = await auth(request, reply); if (!admin) return; const b = z.object({ name:z.string().min(2), contactNumber:z.string().optional(), email:z.string().email().optional().or(z.literal('')), address:z.string().optional(), notes:z.string().optional() }).parse(request.body); const r = await query('INSERT INTO customers(customer_code,name,contact_number,email,address,notes) VALUES(\'CUST-\'||printf(\'%06d\', (SELECT COALESCE(MAX(CAST(substr(customer_code,6) AS INTEGER)),0)+1 FROM customers)),$1,$2,$3,$4,$5) RETURNING *',[b.name,b.contactNumber,b.email,b.address,b.notes]); await audit(admin,'CUSTOMER_CREATED','customer',r.rows[0].id); return reply.code(201).send(r.rows[0]); });

app.get('/api/licenses', async (request, reply) => { if (!(await auth(request, reply))) return; const q = String((request.query as any)?.q || ''); return (await query('SELECT l.*, c.name customer_name, l.license_reference reference, p.name plan_name, (SELECT count(*) FROM devices d WHERE d.license_id=l.id AND d.status=\'ACTIVE\'\) active_devices FROM licenses l JOIN customers c ON c.id=l.customer_id JOIN license_plans p ON p.id=l.plan_id WHERE l.license_reference LIKE $1 OR c.name LIKE $1 ORDER BY l.created_at DESC',[`%${q}%`])).rows.map((row: any) => ({ ...row, expires_at: asIsoDate(row.expires_at) })); });
app.post('/api/licenses', async (request, reply) => { const admin = await auth(request, reply); if (!admin) return; const b=z.object({ customerId:z.string().min(16), planId:z.string().min(16), notes:z.string().optional() }).parse(request.body); const plan=(await query('SELECT * FROM license_plans WHERE id=$1 AND status=\'ACTIVE\'',[b.planId])).rows[0]; if(!plan) return reply.code(400).send({error:'INVALID_PLAN'}); const raw=makeLicenseSecret(); const expires=new Date(Date.now()+plan.duration_days*86400000); const r=await query('INSERT INTO licenses(license_reference,license_key_hash,customer_id,plan_id,max_devices,expires_at,notes) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,license_reference AS reference,status,expires_at,max_devices',[raw,hashSecret(raw),b.customerId,b.planId,plan.max_devices,expires.toISOString(),b.notes]); await audit(admin,'LICENSE_CREATED','license',r.rows[0].id); return reply.code(201).send({...r.rows[0], expires_at:asIsoDate(r.rows[0].expires_at), licenseKey:raw}); });
app.post('/api/licenses/:id/revoke', async (request, reply) => { const admin=await auth(request,reply); if(!admin)return; const id=(request.params as any).id; await query("UPDATE licenses SET status='REVOKED', revoked_at=datetime('now') WHERE id=$1 AND status<>'REVOKED'",[id]); await audit(admin,'LICENSE_REVOKED','license',id); return {ok:true}; });
app.post('/api/licenses/:id/renew', async (request, reply) => { const admin=await auth(request,reply); if(!admin)return; const id=(request.params as any).id; const days=z.object({days:z.number().int().positive().max(3650)}).parse(request.body).days; const r=await query<any>("UPDATE licenses SET expires_at=datetime(expires_at, $2 || ' days'), status=CASE WHEN status='EXPIRED' THEN 'ACTIVE' ELSE status END WHERE id=$1 RETURNING expires_at",[id,`+${days}`]); if(!r.rows[0])return reply.code(404).send({error:'NOT_FOUND'}); await audit(admin,'LICENSE_RENEWED','license',id,{days}); return r.rows[0]; });
app.post('/api/licenses/:id/reset-device', async (request, reply) => { const admin=await auth(request,reply); if(!admin)return; const id=(request.params as any).id; await query("UPDATE devices SET status='REPLACED',replaced_at=datetime('now') WHERE license_id=$1 AND status='ACTIVE'",[id]); await audit(admin,'DEVICE_RESET','license',id); return {ok:true}; });
app.get('/api/plans', async (request, reply) => { if(!(await auth(request,reply)))return; return (await query('SELECT * FROM license_plans ORDER BY name')).rows; });
app.get('/api/audit', async (request, reply) => { if(!(await auth(request,reply)))return; return (await query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100')).rows; });

app.post('/api/licenses/activate', async (request, reply) => {
  const body = z.object({
    license: z.string().trim().min(1),
    device: z.object({
      name: z.string().max(120).optional(),
      id: z.string().min(1).max(255),
      appVersion: z.string().max(40).optional(),
      platformVersion: z.string().max(40).optional(),
    }),
  }).parse(request.body);
  const key = body.license.replace(/\s+/g, '').toUpperCase();
  const license = (await query<any>('SELECT l.*, c.name AS customer_name FROM licenses l JOIN customers c ON c.id=l.customer_id WHERE l.license_key_hash=$1', [hashLicenseKey(key)])).rows[0];
  if (!license) return reply.code(400).send({ error: 'INVALID_LICENSE' });
  const expiresAt = new Date(license.expires_at);
  if (license.status === 'REVOKED' || license.status === 'SUSPENDED') return reply.code(403).send({ error: license.status === 'REVOKED' ? 'LICENSE_REVOKED' : 'LICENSE_SUSPENDED' });
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) return reply.code(403).send({ error: 'LICENSE_EXPIRED' });
  const deviceHash = hashSecret(body.device.id);
  let device = (await query<any>("SELECT * FROM devices WHERE license_id=$1 AND device_identifier_hash=$2 AND status='ACTIVE'", [license.id, deviceHash])).rows[0];
  if (!device) {
    const count = await query<any>("SELECT count(*) AS count FROM devices WHERE license_id=$1 AND status='ACTIVE'", [license.id]);
    if (Number(count.rows[0]?.count || 0) >= Number(license.max_devices)) return reply.code(409).send({ error: 'DEVICE_LIMIT_REACHED' });
    device = (await query<any>('INSERT INTO devices(license_id,device_identifier_hash,device_label,app_version,platform_version) VALUES($1,$2,$3,$4,$5) RETURNING id', [license.id, deviceHash, body.device.name || 'Android device', body.device.appVersion, body.device.platformVersion])).rows[0];
    await query("UPDATE licenses SET status='ACTIVE', activated_at=COALESCE(activated_at,datetime('now')) WHERE id=$1", [license.id]);
  }
  await query("INSERT INTO license_activations(license_id,device_id,event,app_version,platform_version) VALUES($1,$2,'ACTIVATED',$3,$4)", [license.id, device.id, body.device.appVersion, body.device.platformVersion]);
  const validatedAt = new Date().toISOString();
  return { customerName: license.customer_name, licenseKey: key, status: 'ACTIVE', expiresAt: expiresAt.toISOString(), deviceName: body.device.name || 'Android device', deviceId: device.id, validatedAt, graceUntil: new Date(expiresAt.getTime()).toISOString() };
});

function hashLicenseKey(key: string) { return hashSecret(key); }

app.post('/api/licenses/validate', async (request, reply) => {
  const body = z.object({ license: z.string().trim().min(1), device: z.object({ id: z.string().min(1).max(255) }) }).parse(request.body);
  const key = body.license.replace(/\s+/g, '').toUpperCase();
  const license = (await query<any>('SELECT l.*, c.name AS customer_name FROM licenses l JOIN customers c ON c.id=l.customer_id WHERE l.license_key_hash=$1', [hashLicenseKey(key)])).rows[0];
  const expiresAt = license?.expires_at ? new Date(license.expires_at) : null;
  const device = license ? (await query<any>("SELECT id FROM devices WHERE license_id=$1 AND device_identifier_hash=$2 AND status='ACTIVE'", [license.id, hashSecret(body.device.id)])).rows[0] : null;
  if (!license) return reply.code(400).send({ error: 'INVALID_LICENSE' });
  if (license.status === 'REVOKED') return reply.code(403).send({ error: 'LICENSE_REVOKED' });
  if (license.status === 'SUSPENDED') return reply.code(403).send({ error: 'LICENSE_SUSPENDED' });
  if (!expiresAt || expiresAt <= new Date()) return reply.code(403).send({ error: 'LICENSE_EXPIRED' });
  if (!device) return reply.code(403).send({ error: 'DEVICE_REPLACEMENT_REQUIRED' });
  await query("INSERT INTO license_validations(license_id,device_id,valid,status) VALUES($1,$2,1,'ACTIVE')", [license.id, device.id]);
  return { customerName: license.customer_name, licenseKey: key, status: 'ACTIVE', expiresAt: expiresAt.toISOString(), validatedAt: new Date().toISOString() };
});

app.post('/api/v1/licenses/activate', async (request, reply) => { const b=z.object({ licenseKey:z.string(), deviceId:z.string().min(8), deviceLabel:z.string().max(120).optional(), appVersion:z.string().max(40).optional(), platformVersion:z.string().max(40).optional() }).parse(request.body); const r=await query<any>('SELECT * FROM licenses WHERE license_key_hash=$1',[hashSecret(b.licenseKey)]); const l=r.rows[0]; if(!l)return reply.code(404).send({valid:false,status:'NOT_FOUND'}); if(l.status==='REVOKED'||new Date(l.expires_at)<new Date())return reply.code(403).send({valid:false,status:new Date(l.expires_at)<new Date()?'EXPIRED':'REVOKED'}); const active=await query('SELECT * FROM devices WHERE license_id=$1 AND device_identifier_hash=$2 AND status=\'ACTIVE\'',[l.id,hashSecret(b.deviceId)]); let device=active.rows[0]; if(!device){const count=await query('SELECT count(*) count FROM devices WHERE license_id=$1 AND status=\'ACTIVE\'',[l.id]); if(count.rows[0].count>=l.max_devices)return reply.code(409).send({valid:false,status:'DEVICE_LIMIT_REACHED'}); device=(await query('INSERT INTO devices(license_id,device_identifier_hash,device_label,app_version,platform_version) VALUES($1,$2,$3,$4,$5) RETURNING id',[l.id,hashSecret(b.deviceId),b.deviceLabel,b.appVersion,b.platformVersion])).rows[0]; await query("UPDATE licenses SET status='ACTIVE',activated_at=COALESCE(activated_at,datetime('now')) WHERE id=$1",[l.id]); } return {valid:true,status:'ACTIVE',expiresAt:l.expires_at,deviceId:device.id,nextValidationRequiredAt:new Date(Date.now()+7*86400000)}; });
app.post('/api/v1/licenses/validate', async (request, reply) => { const b=z.object({licenseKey:z.string(),deviceId:z.string()}).parse(request.body); const l=(await query<any>('SELECT * FROM licenses WHERE license_key_hash=$1',[hashSecret(b.licenseKey)])).rows[0]; const status=!l?'NOT_FOUND':l.status==='REVOKED'?'REVOKED':new Date(l.expires_at)<new Date()?'EXPIRED':'ACTIVE'; const d=l&&(await query('SELECT id FROM devices WHERE license_id=$1 AND device_identifier_hash=$2 AND status=\'ACTIVE\'',[l.id,hashSecret(b.deviceId)])).rows[0]; const valid=status==='ACTIVE'&&!!d; if(l)await query('INSERT INTO license_validations(license_id,device_id,valid,status) VALUES($1,$2,$3,$4)',[l.id,d?.id||null,valid,status]); return {valid,status,expiresAt:l?.expires_at??null}; });

async function initializeSchema() { const schema = await readFile(new URL('../sql/001_turso_schema.sql', import.meta.url), 'utf8'); for (const statement of schema.split(';').map(x => x.trim()).filter(Boolean)) await db.execute(statement); }

async function bootstrapAdmin() { const email = process.env.ADMIN_EMAIL; const password = process.env.ADMIN_PASSWORD; if (!email || !password) return; const exists = await query('SELECT id FROM admins WHERE email=$1', [email]); const passwordHash = await argon2.hash(password, { type: argon2.argon2id }); if (!exists.rows[0]) await query('INSERT INTO admins(email,password_hash,role,status) VALUES($1,$2,$3,$4)', [email, passwordHash, process.env.ADMIN_ROLE || 'SUPER_ADMIN', 'ACTIVE']); else if (process.env.ADMIN_SYNC_PASSWORD === 'true') await query("UPDATE admins SET password_hash=$2, role=$3, status='ACTIVE', updated_at=datetime('now') WHERE email=$1", [email, passwordHash, process.env.ADMIN_ROLE || 'SUPER_ADMIN']); }

await initializeSchema();
await bootstrapAdmin();
await app.listen({ port:Number(process.env.PORT||3000), host:'0.0.0.0' });
process.on('SIGTERM', async()=>{ await app.close(); });
