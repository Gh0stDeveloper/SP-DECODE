import { jsonReply, unavailable } from "./responses.mjs";

/** Liveness is not readiness: the Cloud API intentionally cannot decode in C1. */
export function live() {
  return jsonReply({
    apiVersion: "v1",
    service: "spdecode-cloud",
    status: "alive",
    phase: "C1",
  });
}

export function ready() {
  return jsonReply({
    apiVersion: "v1",
    status: "not_ready",
    reason: "DECODER_WORKERS_DISABLED",
  }, 503, { "Retry-After": "60" });
}

export function capabilities() {
  return jsonReply({
    apiVersion: "v1",
    status: "not_ready",
    phase: "C1",
    decodingEnabled: false,
    enabledFormats: [],
    fileDecoderCatalog: { catalogRoutes: 239, additionalSolidRoute: 1, exporterVersionsCertified: 0 },
    textDecodingEnabled: false,
    cloudImportsEnabled: false,
    nurCatalogEnabled: false,
    note: "Las rutas son un inventario, no una certificación ni una habilitación.",
  });
}

export function clientConfig() {
  return jsonReply({
    apiVersion: "v1",
    status: "not_ready",
    transport: "https",
    androidNativeLibrary: "libspdecode.so",
    minimumClientVersion: null,
    features: { decodeFiles: false, decodeTexts: false, importCloud: false, importCatalog: false },
  });
}

/** All privileged flows deny requests before even reading the request body. */
export function disabledEndpoint() {
  return unavailable();
}
