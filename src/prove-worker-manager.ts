/**
 * prove-worker-manager.ts — Worker pool for parallel proving (browser + Node.js)
 *
 * Manages a pool of Web Workers (browser) or worker_threads (Node.js) that each
 * load the Go WASM binary and expose SigbashWASM_ProveOnly for CPU-intensive
 * proof generation.  Falls back silently to main-thread proving when Workers
 * are unavailable.
 *
 * The manager is a singleton — multiple calls to init() return the same promise.
 */

import { detectEnvironment, type Environment } from './environment';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface ProveRequest {
  circuitType: 'unified' | 'output_chunk' | 'output_chunk_final';
  witnessBytes: Uint8Array;
  paramsJSON: string;
  policyRoot: string;
  sessionBind: string;
  publicInputsJSON: string;
}

export interface WitnessAndProveRequest {
  circuitType: 'output_chunk' | 'output_chunk_final';
  witnessInputsJSON: string;
  paramsJSON: string;
  policyRoot: string;
  sessionBind: string;
  publicInputsJSON: string;
}

export interface ProveWorkerManagerStatus {
  ready: boolean;
  workerCount: number;
  pendingTasks: number;
}

export interface ProveWorkerManager {
  init(): Promise<void>;
  proveAsync(request: ProveRequest): Promise<Uint8Array>;
  witnessAndProveAsync(request: WitnessAndProveRequest): Promise<Uint8Array>;
  warmCircuits(): void;
  destroy(): void;
  getStatus(): ProveWorkerManagerStatus;
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

interface PendingTask {
  id: number;
  resolve: (result: Uint8Array) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface WorkerWrapper {
  worker: Worker | /* node worker_threads.Worker */ any;
  busy: boolean;
  isWarmed: boolean;
}

// Timeout for a single proof task (ms).
const PROVE_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// Singleton state
// ---------------------------------------------------------------------------

let _instance: ProveWorkerManagerImpl | null = null;

/**
 * Return the singleton ProveWorkerManager.
 * Safe to call before init() — callers should call init() to warm up workers.
 */
export function getProveWorkerManager(): ProveWorkerManager {
  if (!_instance) {
    _instance = new ProveWorkerManagerImpl();
  }
  return _instance;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

class ProveWorkerManagerImpl implements ProveWorkerManager {
  private _initPromise: Promise<void> | null = null;
  private _ready = false;
  private _workers: WorkerWrapper[] = [];
  private _pending = new Map<number, PendingTask>();
  private _queue: Array<{ id: number; request: ProveRequest }> = [];
  private _wapQueue: Array<{ id: number; request: WitnessAndProveRequest }> = [];
  private _nextId = 1;
  private _env: Environment = 'unknown';
  private _fallbackMode = false;

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Initialize the worker pool.  Repeated calls return the same promise.
   */
  init(): Promise<void> {
    if (this._initPromise) return this._initPromise;
    this._initPromise = this._doInit();
    return this._initPromise;
  }

  /**
   * Submit a prove request.  Resolves with serialized proof bytes.
   * Falls back to main-thread proving if workers are unavailable.
   */
  async proveAsync(request: ProveRequest): Promise<Uint8Array> {
    // Ensure init has been called (idempotent).
    await this.init();

    if (this._fallbackMode) {
      return this._proveMainThread(request);
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      const id = this._nextId++;

      const timer = setTimeout(() => {
        const task = this._pending.get(id);
        if (task) {
          this._pending.delete(id);
          task.reject(new Error(`Prove task ${id} timed out after ${PROVE_TIMEOUT_MS}ms`));
        }
      }, PROVE_TIMEOUT_MS);

      this._pending.set(id, { id, resolve, reject, timer });
      this._queue.push({ id, request });
      this._dispatch();
    });
  }

  /**
   * Submit a witness+prove request (output chunks).  The worker builds the
   * witness from raw inputs and proves in one step, avoiding witness
   * serialization round-trip.  Falls back to main-thread if unavailable.
   */
  async witnessAndProveAsync(request: WitnessAndProveRequest): Promise<Uint8Array> {
    await this.init();

    if (this._fallbackMode) {
      return this._witnessAndProveMainThread(request);
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      const id = this._nextId++;

      const timer = setTimeout(() => {
        const task = this._pending.get(id);
        if (task) {
          this._pending.delete(id);
          task.reject(new Error(`WitnessAndProve task ${id} timed out after ${PROVE_TIMEOUT_MS}ms`));
        }
      }, PROVE_TIMEOUT_MS);

      this._pending.set(id, { id, resolve, reject, timer });
      this._wapQueue.push({ id, request });
      this._dispatch();
    });
  }

  /**
   * Tell all workers to prefetch and cache circuit binaries.  Fire-and-forget —
   * workers that aren't ready yet will ignore the message.  Must be called
   * after sigbashBaseUrl is set on globalThis so the circuit fetch resolves.
   */
  warmCircuits(): void {
    const g = globalThis as Record<string, unknown>;
    const baseUrl = (g['sigbashBaseUrl'] as string) || '';
    for (const w of this._workers) {
      if (w.isWarmed) continue; // Item 2: skip workers that already have circuits cached.
      try {
        w.worker.postMessage({ type: 'warm_circuits', sigbashBaseUrl: baseUrl });
      } catch {
        // Ignore — worker may not be ready.
      }
    }
  }

  /**
   * Terminate all workers and release resources.
   */
  destroy(): void {
    for (const w of this._workers) {
      try {
        w.worker.terminate();
      } catch {
        // Ignore termination errors.
      }
    }
    this._workers = [];

    for (const task of this._pending.values()) {
      clearTimeout(task.timer);
      task.reject(new Error('ProveWorkerManager destroyed'));
    }
    this._pending.clear();
    this._queue = [];
    this._ready = false;
    this._initPromise = null;
    _instance = null;
  }

  /**
   * Current status snapshot.
   */
  getStatus(): ProveWorkerManagerStatus {
    return {
      ready: this._ready,
      workerCount: this._workers.length,
      pendingTasks: this._pending.size,
    };
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private async _doInit(): Promise<void> {
    this._env = detectEnvironment();

    const poolSize = this._computePoolSize();
    if (poolSize === 0) {
      this._fallbackMode = true;
      this._ready = true;
      return;
    }

    try {
      const workers = await this._spawnWorkers(poolSize);
      if (workers.length === 0) {
        this._fallbackMode = true;
      } else {
        this._workers = workers;
        // Item 2: attach a persistent listener for warm_complete on each worker.
        for (const w of this._workers) {
          this._attachWarmCompleteListener(w);
        }
      }
    } catch {
      // Workers unavailable — fall back silently.
      this._fallbackMode = true;
    }

    this._ready = true;
  }

  /**
   * Attach a persistent message listener that sets isWarmed = true when a
   * worker sends back a warm_complete message.  This is a one-shot listener
   * per worker; re-warm is never needed once warm_complete fires.
   */
  private _attachWarmCompleteListener(wrapper: WorkerWrapper): void {
    const handler = (ev: MessageEvent | { type: string }) => {
      const msg = 'data' in ev ? (ev as MessageEvent).data : ev;
      if (msg && msg.type === 'warm_complete') {
        wrapper.isWarmed = true;
        // Remove listener — warm_complete fires exactly once per worker.
        if (typeof wrapper.worker.removeEventListener === 'function') {
          wrapper.worker.removeEventListener('message', handler);
        } else if (typeof wrapper.worker.off === 'function') {
          wrapper.worker.off('message', handler);
        }
      }
    };
    if (typeof wrapper.worker.addEventListener === 'function') {
      wrapper.worker.addEventListener('message', handler);
    } else if (typeof wrapper.worker.on === 'function') {
      wrapper.worker.on('message', handler);
    }
  }

  /**
   * Determine pool size.  Leave 2 cores free for the main thread and OS;
   * floor at 2 so single-core-detected environments still get parallelism.
   * Each worker loads a full WASM instance (~50MB peak during prove).
   */
  private _computePoolSize(): number {
    try {
      if (this._env === 'browser' || this._env === 'electron') {
        if (typeof Worker === 'undefined') return 0;
        const cores = typeof navigator !== 'undefined'
          ? (navigator.hardwareConcurrency || 4)
          : 4;
        return Math.max(2, cores - 2);
      }

      if (this._env === 'node') {
        try {
          // eslint-disable-next-line @typescript-eslint/no-var-requires
          const os = require('os');
          const cpus: unknown[] = os.cpus();
          return Math.max(2, (cpus.length || 4) - 2);
        } catch {
          return 2;
        }
      }
    } catch {
      // Safety net.
    }
    return 0;
  }

  /**
   * Spawn worker threads appropriate for the current environment.
   */
  private async _spawnWorkers(count: number): Promise<WorkerWrapper[]> {
    const wrappers: WorkerWrapper[] = [];

    for (let i = 0; i < count; i++) {
      try {
        const w = await this._spawnOne();
        if (w) wrappers.push(w);
      } catch {
        // If one worker fails to spawn, continue with fewer.
      }
    }

    return wrappers;
  }

  private async _spawnOne(): Promise<WorkerWrapper | null> {
    if (this._env === 'browser' || this._env === 'electron') {
      return this._spawnBrowserWorker();
    }
    if (this._env === 'node') {
      return this._spawnNodeWorker();
    }
    return null;
  }

  // -- Browser worker -----------------------------------------------------

  private _spawnBrowserWorker(): Promise<WorkerWrapper | null> {
    return new Promise<WorkerWrapper | null>((resolve) => {
      try {
        // Build an inline worker script that loads wasm_exec.js and sigbash.wasm,
        // then listens for prove requests.  The WASM URL and wasm_exec.js URL are
        // inferred from the same location the main thread loaded them.
        const workerCode = `
"use strict";
// Browser prove-worker inline script.
let wasmReady = false;
const pending = [];

self.onmessage = function(e) {
  const msg = e.data;
  if (msg.type === 'init') {
    initWasm(msg.wasmExecUrl, msg.wasmUrl).then(function() {
      wasmReady = true;
      self.postMessage({ type: 'ready' });
      // Drain any queued tasks.
      while (pending.length > 0) {
        handleProve(pending.shift());
      }
    }).catch(function(err) {
      self.postMessage({ type: 'init_error', error: err.message || String(err) });
    });
    return;
  }
  if (msg.type === 'warm_circuits') {
    if (msg.sigbashBaseUrl) { self.sigbashBaseUrl = msg.sigbashBaseUrl; }
    if (wasmReady && typeof self.SigbashWASM_WarmCircuits === 'function') {
      self.SigbashWASM_WarmCircuits().then(function() {
        self.postMessage({ type: 'warm_complete' });
      }).catch(function() {});
    }
    return;
  }
  if (msg.type === 'prove' || msg.type === 'witness_and_prove') {
    if (!wasmReady) {
      pending.push(msg);
      return;
    }
    if (msg.type === 'witness_and_prove') {
      handleWitnessAndProve(msg);
    } else {
      handleProve(msg);
    }
  }
};

async function initWasm(wasmExecUrl, wasmUrl) {
  importScripts(wasmExecUrl);
  var go = new Go();
  var response = await fetch(wasmUrl);
  var result = await WebAssembly.instantiateStreaming(response, go.importObject);
  go.run(result.instance);
  // Warm up WebCrypto thread pool before first prove.
  if (typeof crypto !== "undefined" && crypto.subtle) {
    await crypto.subtle.digest("SHA-256", new Uint8Array(0));
  }
}

async function handleProve(msg) {
  try {
    var fn = self.SigbashWASM_ProveOnly;
    if (typeof fn !== 'function') {
      self.postMessage({ type: 'prove_error', id: msg.id, error: 'SigbashWASM_ProveOnly not available' });
      return;
    }
    var result = await fn(
      msg.circuitType,
      msg.witnessBytes,
      msg.paramsJSON,
      msg.policyRoot,
      msg.sessionBind,
      msg.publicInputsJSON
    );
    // Transfer the underlying buffer for zero-copy.
    var bytes = new Uint8Array(result);
    self.postMessage({ type: 'prove_result', id: msg.id, proof: bytes }, [bytes.buffer]);
  } catch (err) {
    self.postMessage({ type: 'prove_error', id: msg.id, error: err.message || String(err) });
  }
}

async function handleWitnessAndProve(msg) {
  try {
    var fn = self.SigbashWASM_WitnessAndProveOutputChunk;
    if (typeof fn !== 'function') {
      self.postMessage({ type: 'prove_error', id: msg.id, error: 'SigbashWASM_WitnessAndProveOutputChunk not available' });
      return;
    }
    var result = await fn(
      msg.circuitType,
      msg.witnessInputsJSON,
      msg.paramsJSON,
      msg.policyRoot,
      msg.sessionBind,
      msg.publicInputsJSON
    );
    var bytes = new Uint8Array(result);
    self.postMessage({ type: 'prove_result', id: msg.id, proof: bytes }, [bytes.buffer]);
  } catch (err) {
    self.postMessage({ type: 'prove_error', id: msg.id, error: err.message || String(err) });
  }
}
`;
        const blob = new Blob([workerCode], { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        const worker = new Worker(url);

        // Settled guard prevents the timeout from terminating a worker that
        // already resolved successfully (or vice versa).
        let settled = false;

        // Wait for 'ready' or 'init_error'.
        const onReady = (ev: MessageEvent) => {
          if (settled) return;
          if (ev.data.type === 'ready') {
            settled = true;
            cleanup();
            URL.revokeObjectURL(url); // Release Blob URL to avoid memory leak
            resolve({ worker, busy: false, isWarmed: false });
          } else if (ev.data.type === 'init_error') {
            settled = true;
            cleanup();
            URL.revokeObjectURL(url);
            try { worker.terminate(); } catch { /* ignore */ }
            resolve(null);
          }
        };
        const onError = () => {
          if (settled) return;
          settled = true;
          cleanup();
          URL.revokeObjectURL(url);
          try { worker.terminate(); } catch { /* ignore */ }
          resolve(null);
        };
        const cleanup = () => {
          worker.removeEventListener('message', onReady);
          worker.removeEventListener('error', onError);
        };

        worker.addEventListener('message', onReady);
        worker.addEventListener('error', onError);

        // Infer the wasm_exec.js and sigbash.wasm URLs.
        // The main thread should have set these on globalThis during loadWasm().
        const g = globalThis as Record<string, unknown>;
        const wasmExecUrl = (g['_sigbashWasmExecUrl'] as string) || '/wasm_exec.js';
        const wasmUrl = (g['_sigbashWasmUrl'] as string) || '/sigbash.wasm';

        worker.postMessage({ type: 'init', wasmExecUrl, wasmUrl });

        // Timeout for init — 30s is generous for WASM download + compile.
        setTimeout(() => {
          if (settled) return;
          settled = true;
          cleanup();
          URL.revokeObjectURL(url);
          try { worker.terminate(); } catch { /* ignore */ }
          resolve(null);
        }, 30_000);

      } catch {
        resolve(null);
      }
    });
  }

  // -- Node.js worker -----------------------------------------------------

  private async _spawnNodeWorker(): Promise<WorkerWrapper | null> {
    try {
      const { Worker: NodeWorker } = await import('worker_threads');

      // The Node worker script loads wasm_exec.js + sigbash.wasm, then
      // listens on the parentPort for prove messages.
      const workerCode = `
"use strict";
const { parentPort, workerData } = require("worker_threads");

let wasmReady = false;
const pending = [];

parentPort.on("message", function(msg) {
  if (msg.type === "warm_circuits") {
    if (msg.sigbashBaseUrl && !global.sigbashBaseUrl) {
      global.sigbashBaseUrl = msg.sigbashBaseUrl;
    }
    if (wasmReady && typeof global.SigbashWASM_WarmCircuits === "function") {
      global.SigbashWASM_WarmCircuits().then(function() {
        parentPort.postMessage({ type: "warm_complete" });
      }).catch(function() {});
    }
    return;
  }
  if (msg.type === "prove" || msg.type === "witness_and_prove") {
    if (!wasmReady) { pending.push(msg); return; }
    if (msg.type === "witness_and_prove") {
      handleWitnessAndProve(msg);
    } else {
      handleProve(msg);
    }
  }
});

(async function init() {
  try {
    // Propagate sigbashBaseUrl so Go WASM can resolve relative URLs (e.g. /poet_circuit.bin).
    if (workerData.sigbashBaseUrl) {
      global.sigbashBaseUrl = workerData.sigbashBaseUrl;
    }
    // Load wasm_exec.js — sets global.Go.
    require(workerData.wasmExecPath);
    const go = new Go();
    const fs = require("fs");
    const path = require("path");

    let wasmBuffer;
    const wasmPath = workerData.wasmPath;
    if (wasmPath.startsWith("http://") || wasmPath.startsWith("https://")) {
      const resp = await fetch(wasmPath);
      wasmBuffer = await resp.arrayBuffer();
    } else {
      wasmBuffer = fs.readFileSync(path.resolve(wasmPath)).buffer;
    }

    const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
    go.run(result.instance);
    // Warm up WebCrypto/OpenSSL thread pool before first prove.
    // Without this, the first Ligero batch SHA-256 pays ~2s cold-start.
    if (typeof crypto !== "undefined" && crypto.subtle) {
      await crypto.subtle.digest("SHA-256", new Uint8Array(0));
    }
    wasmReady = true;
    parentPort.postMessage({ type: "ready" });
    while (pending.length > 0) {
      var p = pending.shift();
      if (p.type === "witness_and_prove") handleWitnessAndProve(p);
      else handleProve(p);
    }
  } catch (err) {
    parentPort.postMessage({ type: "init_error", error: err.message || String(err) });
  }
})();

async function handleProve(msg) {
  try {
    // Lazily propagate sigbashBaseUrl from the prove message so Go WASM
    // can resolve relative URLs (e.g. /poet_circuit.bin).  The main
    // thread sets this during signPSBT — after workers are spawned.
    if (msg.sigbashBaseUrl && !global.sigbashBaseUrl) {
      global.sigbashBaseUrl = msg.sigbashBaseUrl;
    }
    var fn = global.SigbashWASM_ProveOnly;
    if (typeof fn !== "function") {
      parentPort.postMessage({ type: "prove_error", id: msg.id, error: "SigbashWASM_ProveOnly not available" });
      return;
    }
    var result = await fn(
      msg.circuitType,
      msg.witnessBytes,
      msg.paramsJSON,
      msg.policyRoot,
      msg.sessionBind,
      msg.publicInputsJSON
    );
    var bytes = new Uint8Array(result);
    parentPort.postMessage({ type: "prove_result", id: msg.id, proof: bytes }, [bytes.buffer]);
  } catch (err) {
    parentPort.postMessage({ type: "prove_error", id: msg.id, error: err.message || String(err) });
  }
}

async function handleWitnessAndProve(msg) {
  try {
    if (msg.sigbashBaseUrl && !global.sigbashBaseUrl) {
      global.sigbashBaseUrl = msg.sigbashBaseUrl;
    }
    var fn = global.SigbashWASM_WitnessAndProveOutputChunk;
    if (typeof fn !== "function") {
      parentPort.postMessage({ type: "prove_error", id: msg.id, error: "SigbashWASM_WitnessAndProveOutputChunk not available" });
      return;
    }
    var result = await fn(
      msg.circuitType,
      msg.witnessInputsJSON,
      msg.paramsJSON,
      msg.policyRoot,
      msg.sessionBind,
      msg.publicInputsJSON
    );
    var bytes = new Uint8Array(result);
    parentPort.postMessage({ type: "prove_result", id: msg.id, proof: bytes }, [bytes.buffer]);
  } catch (err) {
    parentPort.postMessage({ type: "prove_error", id: msg.id, error: err.message || String(err) });
  }
}
`;

      // Resolve wasm_exec.js path.
      let wasmExecPath: string;
      try {
        wasmExecPath = require.resolve('@sigbash/sdk/wasm/wasm_exec.js');
      } catch {
        const path = require('path');
        wasmExecPath = path.resolve(__dirname, '../wasm/wasm_exec.js');
      }

      const g = globalThis as Record<string, unknown>;
      const wasmPath = (g['_sigbashWasmUrl'] as string) || '';
      if (!wasmPath) {
        // No WASM path available — can't init worker.
        return null;
      }

      const sigbashBaseUrl = (g['sigbashBaseUrl'] as string) || '';

      return new Promise<WorkerWrapper | null>((resolve) => {
        const worker = new NodeWorker(workerCode, {
          eval: true,
          workerData: { wasmExecPath, wasmPath, sigbashBaseUrl },
        });

        let settled = false;

        const onMessage = (msg: { type: string; error?: string }) => {
          if (settled) return;
          if (msg.type === 'ready') {
            settled = true;
            cleanup();
            resolve({ worker, busy: false, isWarmed: false });
          } else if (msg.type === 'init_error') {
            settled = true;
            cleanup();
            try { worker.terminate(); } catch { /* ignore */ }
            resolve(null);
          }
        };
        const onError = () => {
          if (settled) return;
          settled = true;
          cleanup();
          try { worker.terminate(); } catch { /* ignore */ }
          resolve(null);
        };
        const cleanup = () => {
          worker.off('message', onMessage);
          worker.off('error', onError);
        };

        worker.on('message', onMessage);
        worker.on('error', onError);

        // 30s init timeout.
        setTimeout(() => {
          if (settled) return;
          settled = true;
          cleanup();
          try { worker.terminate(); } catch { /* ignore */ }
          resolve(null);
        }, 30_000);
      });
    } catch {
      return null;
    }
  }

  // -- Task dispatch -------------------------------------------------------

  /**
   * Try to assign queued tasks to idle workers.
   */
  private _dispatch(): void {
    while (this._queue.length > 0 || this._wapQueue.length > 0) {
      const idleWorker = this._workers.find(w => !w.busy);
      if (!idleWorker) break;

      // Drain prove tasks first, then witness+prove tasks.
      if (this._queue.length > 0) {
        const item = this._queue.shift()!;
        const task = this._pending.get(item.id);
        if (!task) continue; // Already timed out.
        idleWorker.busy = true;
        this._sendToWorker(idleWorker, item.id, item.request);
      } else if (this._wapQueue.length > 0) {
        const item = this._wapQueue.shift()!;
        const task = this._pending.get(item.id);
        if (!task) continue;
        idleWorker.busy = true;
        this._sendWitnessAndProveToWorker(idleWorker, item.id, item.request);
      }
    }
  }

  private _sendToWorker(wrapper: WorkerWrapper, id: number, request: ProveRequest): void {
    const handler = (ev: MessageEvent | { type: string; id: number; proof?: Uint8Array; error?: string }) => {
      // Normalize browser MessageEvent vs Node message.
      const msg = 'data' in ev ? (ev as MessageEvent).data : ev;

      if (msg.id !== id) return; // Not our task.

      // Remove listener.
      if (typeof wrapper.worker.removeEventListener === 'function') {
        wrapper.worker.removeEventListener('message', handler);
      } else if (typeof wrapper.worker.off === 'function') {
        wrapper.worker.off('message', handler);
      }

      wrapper.busy = false;

      const task = this._pending.get(id);
      if (!task) return; // Already resolved/timed out.
      this._pending.delete(id);
      clearTimeout(task.timer);

      if (msg.type === 'prove_result') {
        task.resolve(new Uint8Array(msg.proof));
      } else if (msg.type === 'prove_error') {
        task.reject(new Error(msg.error || 'Worker prove failed'));
      }

      // Try to dispatch more work.
      this._dispatch();
    };

    // Attach listener.
    if (typeof wrapper.worker.addEventListener === 'function') {
      wrapper.worker.addEventListener('message', handler);
    } else if (typeof wrapper.worker.on === 'function') {
      wrapper.worker.on('message', handler);
    }

    // Send the task.  Transfer the witnessBytes buffer for zero-copy (browser).
    const transferable = (this._env === 'browser' || this._env === 'electron')
      ? [request.witnessBytes.buffer]
      : undefined;

    const g = globalThis as Record<string, unknown>;
    wrapper.worker.postMessage({
      type: 'prove',
      id,
      circuitType: request.circuitType,
      witnessBytes: request.witnessBytes,
      paramsJSON: request.paramsJSON,
      policyRoot: request.policyRoot,
      sessionBind: request.sessionBind,
      publicInputsJSON: request.publicInputsJSON,
      sigbashBaseUrl: (g['sigbashBaseUrl'] as string) || '',
    }, transferable);
  }

  private _sendWitnessAndProveToWorker(wrapper: WorkerWrapper, id: number, request: WitnessAndProveRequest): void {
    const handler = (ev: MessageEvent | { type: string; id: number; proof?: Uint8Array; error?: string }) => {
      const msg = 'data' in ev ? (ev as MessageEvent).data : ev;
      if (msg.id !== id) return;

      if (typeof wrapper.worker.removeEventListener === 'function') {
        wrapper.worker.removeEventListener('message', handler);
      } else if (typeof wrapper.worker.off === 'function') {
        wrapper.worker.off('message', handler);
      }

      wrapper.busy = false;

      const task = this._pending.get(id);
      if (!task) return;
      this._pending.delete(id);
      clearTimeout(task.timer);

      if (msg.type === 'prove_result') {
        task.resolve(new Uint8Array(msg.proof));
      } else if (msg.type === 'prove_error') {
        task.reject(new Error(msg.error || 'Worker witness+prove failed'));
      }

      this._dispatch();
    };

    if (typeof wrapper.worker.addEventListener === 'function') {
      wrapper.worker.addEventListener('message', handler);
    } else if (typeof wrapper.worker.on === 'function') {
      wrapper.worker.on('message', handler);
    }

    const g = globalThis as Record<string, unknown>;
    wrapper.worker.postMessage({
      type: 'witness_and_prove',
      id,
      circuitType: request.circuitType,
      witnessInputsJSON: request.witnessInputsJSON,
      paramsJSON: request.paramsJSON,
      policyRoot: request.policyRoot,
      sessionBind: request.sessionBind,
      publicInputsJSON: request.publicInputsJSON,
      sigbashBaseUrl: (g['sigbashBaseUrl'] as string) || '',
    });
  }

  // -- Main-thread fallback ------------------------------------------------

  /**
   * Fall back to calling SigbashWASM_ProveOnly on the main thread.
   */
  private async _proveMainThread(request: ProveRequest): Promise<Uint8Array> {
    const fn = (globalThis as Record<string, unknown>)['SigbashWASM_ProveOnly'] as
      | ((
          circuitType: string,
          witnessBytes: Uint8Array,
          paramsJSON: string,
          policyRoot: string,
          sessionBind: string,
          publicInputsJSON: string,
        ) => Promise<Uint8Array>)
      | undefined;

    if (typeof fn !== 'function') {
      throw new Error(
        'SigbashWASM_ProveOnly not available. ' +
        'Ensure the WASM binary has been loaded via loadWasm().'
      );
    }

    return fn(
      request.circuitType,
      request.witnessBytes,
      request.paramsJSON,
      request.policyRoot,
      request.sessionBind,
      request.publicInputsJSON,
    );
  }

  /**
   * Fall back to calling SigbashWASM_WitnessAndProveOutputChunk on the main thread.
   */
  private async _witnessAndProveMainThread(request: WitnessAndProveRequest): Promise<Uint8Array> {
    const fn = (globalThis as Record<string, unknown>)['SigbashWASM_WitnessAndProveOutputChunk'] as
      | ((
          circuitType: string,
          witnessInputsJSON: string,
          paramsJSON: string,
          policyRoot: string,
          sessionBind: string,
          publicInputsJSON: string,
        ) => Promise<Uint8Array>)
      | undefined;

    if (typeof fn !== 'function') {
      throw new Error(
        'SigbashWASM_WitnessAndProveOutputChunk not available. ' +
        'Ensure the WASM binary has been loaded via loadWasm().'
      );
    }

    return fn(
      request.circuitType,
      request.witnessInputsJSON,
      request.paramsJSON,
      request.policyRoot,
      request.sessionBind,
      request.publicInputsJSON,
    );
  }
}
