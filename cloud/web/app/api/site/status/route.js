import { settings } from "../../../../lib/c3-config.mjs";
import { store } from "../../../../lib/c3-store.mjs";
import { maintenanceEnabled } from "../../../../lib/c6-ops-store.mjs";
import { jsonReply } from "../../../../lib/responses.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export async function GET(){
  // Public telemetry is intentionally binary: never disclose inner topology,
  // vendor configuration, Redis metrics, user data or worker credentials.
  if(!settings().configured)
    return jsonReply({status:"not_ready",phase:"prelaunch"},200);
  try {
    const redis=await store();
    if(await maintenanceEnabled(redis))
      return jsonReply({status:"maintenance",phase:"prelaunch"},200);
    if(await redis.ping()!=="PONG")throw Error("unavailable");
    // C6 does not claim availability until C7 end-to-end validation.
    return jsonReply({status:"testing",phase:"prelaunch"},200);
  }catch {
    return jsonReply({status:"not_ready",phase:"prelaunch"},200);
  }
}
