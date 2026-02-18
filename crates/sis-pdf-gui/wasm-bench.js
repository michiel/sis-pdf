const CASE_BUDGETS = {
  small: {
    max_wall_ms: 2500,
    max_worker_ms: 2200,
    max_result_bytes: 2_000_000,
  },
  medium: {
    max_wall_ms: 7000,
    max_worker_ms: 6500,
    max_result_bytes: 4_000_000,
  },
  large: {
    max_wall_ms: 15000,
    max_worker_ms: 14000,
    max_result_bytes: 8_000_000,
  },
  adversarial: {
    max_wall_ms: 12000,
    max_worker_ms: 11000,
    max_result_bytes: 3_000_000,
  },
};

function buildAdversarialPdf(streamCount, streamLen) {
  const encoder = new TextEncoder();
  const chunks = [];
  const offsets = [0];
  let size = 0;

  const pushText = (text) => {
    const data = encoder.encode(text);
    chunks.push(data);
    size += data.byteLength;
  };
  const pushBytes = (bytes) => {
    chunks.push(bytes);
    size += bytes.byteLength;
  };

  pushText("%PDF-1.4\n");
  offsets.push(size);
  pushText("1 0 obj\n<< /Type /Catalog >>\nendobj\n");

  const payload = new Uint8Array(streamLen);
  payload.fill(0x41);
  for (let i = 0; i < streamCount; i += 1) {
    const objNum = i + 2;
    offsets.push(size);
    pushText(`${objNum} 0 obj\n<< /Length ${streamLen} >>\nstream\n`);
    pushBytes(payload);
    pushText("\nendstream\nendobj\n");
  }

  const xrefOffset = size;
  pushText(`xref\n0 ${offsets.length}\n`);
  pushText("0000000000 65535 f \n");
  for (let i = 1; i < offsets.length; i += 1) {
    const off = offsets[i].toString().padStart(10, "0");
    pushText(`${off} 00000 n \n`);
  }
  pushText(`trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`);

  const out = new Uint8Array(size);
  let cursor = 0;
  for (const chunk of chunks) {
    out.set(chunk, cursor);
    cursor += chunk.byteLength;
  }
  return out;
}

async function loadFixtureBytes(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch fixture ${url}: HTTP ${res.status}`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

async function runWorkerAnalysis(fileName, bytes) {
  const worker = new Worker("./dist/analysis_worker.js");
  const requestBytes = bytes.byteLength;
  const started = performance.now();
  const msgPromise = new Promise((resolve, reject) => {
    worker.onmessage = (event) => resolve(event.data);
    worker.onerror = (event) => reject(new Error(`Worker error: ${event.message}`));
  });
  const timeoutMs = 45_000;
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`Worker timeout after ${timeoutMs} ms for ${fileName}`)), timeoutMs);
  });
  worker.postMessage({ file_name: fileName, bytes: bytes.buffer }, [bytes.buffer]);
  let payload;
  try {
    payload = await Promise.race([msgPromise, timeoutPromise]);
  } finally {
    worker.terminate();
  }
  const ended = performance.now();

  if (!payload || payload.ok !== true) {
    const message = payload && typeof payload.error === "string" ? payload.error : "unknown error";
    throw new Error(`Worker analysis failed for ${fileName}: ${message}`);
  }
  const meta = payload.meta ?? {};
  return {
    request_bytes: requestBytes,
    wall_ms: Math.max(0, ended - started),
    worker_ms: typeof meta.worker_ms === "number" ? meta.worker_ms : null,
    result_bytes:
      typeof meta.result_json_bytes === "number"
        ? meta.result_json_bytes
        : JSON.stringify(payload.result).length,
    heap_bytes: performance.memory ? performance.memory.usedJSHeapSize : null,
    finding_count: payload.result?.report?.findings?.length ?? 0,
  };
}

function evaluateBudgets(name, metrics, budgets) {
  const failures = [];
  if (metrics.wall_ms > budgets.max_wall_ms) {
    failures.push(`wall_ms ${metrics.wall_ms.toFixed(1)} > ${budgets.max_wall_ms}`);
  }
  if (metrics.worker_ms != null && metrics.worker_ms > budgets.max_worker_ms) {
    failures.push(`worker_ms ${metrics.worker_ms.toFixed(1)} > ${budgets.max_worker_ms}`);
  }
  if (metrics.result_bytes > budgets.max_result_bytes) {
    failures.push(`result_bytes ${metrics.result_bytes} > ${budgets.max_result_bytes}`);
  }
  return {
    name,
    metrics,
    budgets,
    ok: failures.length === 0,
    failures,
  };
}

async function runBenchmarks() {
  const small = new Uint8Array(
    new TextEncoder().encode(
      "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n58\n%%EOF",
    ),
  );
  const medium = await loadFixtureBytes("../sis-pdf-core/tests/fixtures/launch_action.pdf");
  const large = await loadFixtureBytes(
    "../sis-pdf-core/tests/fixtures/actions/launch_cve_2010_1240.pdf",
  );
  const adversarial = buildAdversarialPdf(180, 4096);

  const cases = [
    { name: "small", fileName: "small.pdf", bytes: small, budgets: CASE_BUDGETS.small },
    { name: "medium", fileName: "launch_action.pdf", bytes: medium, budgets: CASE_BUDGETS.medium },
    {
      name: "large",
      fileName: "launch_cve_2010_1240.pdf",
      bytes: large,
      budgets: CASE_BUDGETS.large,
    },
    {
      name: "adversarial",
      fileName: "adversarial_streams.pdf",
      bytes: adversarial,
      budgets: CASE_BUDGETS.adversarial,
    },
  ];

  const started = performance.now();
  const results = [];
  for (const testCase of cases) {
    const metrics = await runWorkerAnalysis(testCase.fileName, testCase.bytes);
    results.push(evaluateBudgets(testCase.name, metrics, testCase.budgets));
  }
  const totalMs = Math.max(0, performance.now() - started);
  const failed = results.filter((entry) => !entry.ok);
  return {
    ok: failed.length === 0,
    total_ms: totalMs,
    failed_cases: failed.map((entry) => ({ name: entry.name, failures: entry.failures })),
    results,
  };
}

async function main() {
  const output = document.getElementById("output");
  try {
    const summary = await runBenchmarks();
    window.__SIS_WASM_BENCH_RESULT__ = summary;
    output.textContent = JSON.stringify(summary, null, 2);
    output.style.color = summary.ok ? "#1f7a1f" : "#a40000";
  } catch (err) {
    const message = err && typeof err.message === "string" ? err.message : String(err);
    const summary = { ok: false, error: message };
    window.__SIS_WASM_BENCH_RESULT__ = summary;
    output.textContent = JSON.stringify(summary, null, 2);
    output.style.color = "#a40000";
  }
}

main();
