import { adminSettings } from "./c6-admin-auth.mjs";
let cache;
export async function opsStore() {
  if(!adminSettings().enabled)throw Error("ADMIN_DISABLED");
  if(!cache){
    cache=import("redis").then(async({createClient})=>{
      const client=createClient({
        url:process.env.CLOUD_REDIS_URL,
        socket:{connectTimeout:3000,reconnectStrategy:false},
      });
      client.on("error",()=>{}); // No URLs, credentials or payloads in logs.
      await client.connect();
      return client;
    }).catch(e=>{cache=undefined;throw e;});
  }
  return cache;
}
export const MAINTENANCE_KEY="spc6:maintenance";
export async function maintenanceEnabled(redis,env=process.env) {
  if(env.CLOUD_FORCE_MAINTENANCE==="true")return true;
  return await redis.get(MAINTENANCE_KEY)==="1";
}
export async function setMaintenance(redis,enabled,env=process.env) {
  if(!enabled && env.CLOUD_FORCE_MAINTENANCE==="true")throw Error("MAINTENANCE_LOCKED");
  if(enabled)await redis.set(MAINTENANCE_KEY,"1");
  else await redis.del(MAINTENANCE_KEY);
}
export async function recordWorkerResult(redis,outcome) {
  // No filenames, payloads, IPs, tokens, or decoded data are retained.
  if(!["success","failed"].includes(outcome))return;
  const day=new Date().toISOString().slice(0,10);
  const key="spc6:metrics:"+day+":"+outcome;
  const pipeline=redis.multi();
  pipeline.incr(key);
  pipeline.expire(key,8*86400);
  await pipeline.exec();
}
export async function aggregateMetrics(redis) {
  const day=new Date().toISOString().slice(0,10);
  const [success,failed]=await redis.mGet([
    "spc6:metrics:"+day+":success",
    "spc6:metrics:"+day+":failed",
  ]);
  return {window:"utc_today",successfulDecodes:Number(success)||0,failedDecodes:Number(failed)||0};
}
