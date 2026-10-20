import { createHash, randomBytes } from 'node:crypto';

export function makeLicenseSecret() { return `BUBO-${randomBytes(12).toString('base64url').toUpperCase().match(/.{1,4}/g)!.join('-')}`; }
export function hashSecret(secret: string) { return createHash('sha256').update(secret).digest('hex'); }
