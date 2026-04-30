import { Container, getContainer } from "@cloudflare/containers";

export class ScannerContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "10m";
  enableInternet = true;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const container = getContainer(env.SCANNER, "singleton");

    // Forward all requests to the container's axum server
    // Routes: /scan, /sanitize, /scan-batch, /health, /gui
    return container.fetch(request);
  },
};

interface Env {
  SCANNER: DurableObjectNamespace<ScannerContainer>;
}
