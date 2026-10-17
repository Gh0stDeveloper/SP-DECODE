import { createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { limits } from "./c3-config.mjs";
import { checkIntegrityVerdict, verifyPlayToken } from "./c3-integrity.mjs";
import { consumeChallenge, ipKey, rememberSession, reserveChallenge, sessionExists, throttle } from "./c3-store.mjs";
const json = object => Buffer.from(JSON.stringify(object)).toString("base64url");
const mac = (data, key) => createHmac("sha256", key).update(data).digest();
function sign(claims, key) {
  const payload = json(claims);
  return payload + "." + mac(payload, key).toString("base64url");
}
export function verifySignature(token, key, now = Math.floor(Date.now()/1000)) {
  if (typeof token !== "string" || token.length > 2048 || !/^[\w-]+\.[\w-]+$/.test(token)) return null;
  const [body, tag] = token.split(".");
  const a = Buffer.from(tag, "base64url");
  const b = mac(body, key);
  if (a.length !== b.length || !timingSafeEqual(a,b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
    if (p.iss !== "spdecode-cloud" || p.aud !== "spdecode-android-v1" || p.scope !== "decode" ||
        typeof p.jti !== "string" || !/^[0-9a-f-]{36}$/.test(p.jti) ||
        !Number.isInteger(p.iat) || !Number.isInteger(p.exp) ||
        p.exp <= now || p.iat > now + 5 || p.exp - p.iat > limits.sessionTtlSeconds) return null;
    return p;
  } catch { return null; }
}
export async function createChallenge(redis, request) {
  const ip = ipKey(request);
  const permitted = await throttle(redis, "spc3:challenge-limit:"+ip, 15, 900);
  if (!permitted) return { error:"RATE_LIMITED", status:429 };
  const challengeId = randomUUID();
  const nonce = randomBytes(32).toString("base64url");
  if (!await reserveChallenge(redis, challengeId, nonce, ip)) return { error:"SERVICE_UNAVAILABLE", status:503 };
  return { challengeId, nonce, expiresIn:limits.challengeTtlSeconds };
}
export async function issueSession(redis, request, body, cfg, verifier = verifyPlayToken) {
  const ip = ipKey(request);
  const limited = await throttle(redis,"spc3:admission-limit:"+ip,20,900);
  if (!limited) return { error:"RATE_LIMITED", status:429 };
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      typeof body.challengeId !== "string" || !/^[0-9a-f-]{36}$/.test(body.challengeId) ||
      typeof body.integrityToken !== "string" || body.integrityToken.length > 16384) return { error:"INVALID_REQUEST",status:400 };
  // GETDEL is atomic and consumes challenge even if token is forged/replayed.
  const challenge = await consumeChallenge(redis, body.challengeId, ip);
  if (!challenge) return { error:"EXPIRED_CHALLENGE",status:401 };
  if (!await verifier(body.integrityToken,challenge.nonce,cfg)) return { error:"INTEGRITY_REJECTED",status:403 };
  const now = Math.floor(Date.now()/1000);
  const claims = {iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+limits.sessionTtlSeconds,jti:randomUUID()};
  if (!await rememberSession(redis,claims.jti,claims.exp)) return {error:"SERVICE_UNAVAILABLE",status:503};
  return {accessToken:sign(claims,cfg.signingKey),tokenType:"Bearer",expiresIn:limits.sessionTtlSeconds};
}
export async function requireSession(redis, request, cfg) {
  const bearer = request.headers.get("authorization") || "";
  if (!bearer.startsWith("Bearer ")) return null;
  const claims = verifySignature(bearer.slice(7), cfg.signingKey);
  if (!claims || !await sessionExists(redis,claims.jti)) return null;
  const ip = ipKey(request);
  const sessionRate = await throttle(redis,"spc3:request-limit:"+claims.jti,limits.requestsPerSessionMinute,60);
  const networkRate = await throttle(redis,"spc3:network-limit:"+ip,limits.requestsPerIpWindow,60);
  return sessionRate && networkRate ? claims : {rateLimited:true};
}
