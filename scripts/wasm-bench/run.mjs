import { spawn } from "node:child_process";
import process from "node:process";

if (!process.env.PLAYWRIGHT_BROWSERS_PATH) {
  process.env.PLAYWRIGHT_BROWSERS_PATH = "/tmp/sis-playwright";
}

const PORT = process.env.SIS_WASM_BENCH_PORT || "8088";
const HOST = "127.0.0.1";
const ROOT = ".";
const BENCH_URL = `http://${HOST}:${PORT}/crates/sis-pdf-gui/wasm-bench.html`;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForServer(url, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(url, { method: "GET" });
      if (res.ok) {
        return;
      }
    } catch (_) {
      // server not ready
    }
    await sleep(200);
  }
  throw new Error(`Timed out waiting for server: ${url}`);
}

async function run() {
  const { chromium } = await import("playwright");
  const server = spawn("python3", ["-m", "http.server", PORT, "--bind", HOST, "--directory", ROOT], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const hardTimeout = setTimeout(() => {
    console.error("WASM benchmark hard timeout exceeded (300000 ms)");
    server.kill("SIGKILL");
    process.exit(1);
  }, 300_000);
  server.stdout.on("data", (buf) => process.stdout.write(buf));
  server.stderr.on("data", (buf) => process.stderr.write(buf));

  let browser = null;
  try {
    await waitForServer(BENCH_URL, 15_000);
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    page.on("console", (msg) => {
      console.log(`[browser:${msg.type()}] ${msg.text()}`);
    });
    await page.goto(BENCH_URL, { waitUntil: "load", timeout: 60_000 });
    await page.waitForFunction(() => Boolean(window.__SIS_WASM_BENCH_RESULT__), { timeout: 240_000 });

    const result = await page.evaluate(() => window.__SIS_WASM_BENCH_RESULT__);
    console.log(JSON.stringify(result, null, 2));
    if (!result || result.ok !== true) {
      throw new Error("WASM benchmark reported failure");
    }
  } finally {
    clearTimeout(hardTimeout);
    if (browser) {
      await browser.close();
    }
    server.kill("SIGTERM");
  }
}

run().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
