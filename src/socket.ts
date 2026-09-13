/**
 * Socket.IO abstraction for Sigbash SDK.
 *
 * Provides a Promise-based interface over the raw socket.io-client,
 * targeting the `/api/v2/sdk` namespace.
 */

import { io, Socket } from 'socket.io-client';
import { ServerError, TimeoutError } from './errors';

/** Default request timeout in milliseconds. */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Parsed server error response shape. */
interface ServerErrorData {
  error?: boolean;
  code?: string;
  message?: string;
  [key: string]: unknown;
}

/** One outstanding request, held in the per-event pending registry. */
interface PendingRequest {
  /** Correlation ID sent in the request payload and expected in the response. */
  id: string;
  /** Resolve and clean up this request. */
  complete: (payload: unknown) => void;
  /** Reject and clean up this request. */
  fail: (err: Error) => void;
}

/**
 * Generate a request-unique correlation ID. Prefers the platform UUID
 * implementation; falls back to a version-4-shaped hex string from any
 * available CSPRNG so older runtimes still produce collision-resistant IDs.
 */
function _newCorrelationId(): string {
  const cryptoObj = (globalThis as Record<string, unknown>)['crypto'] as
    | { randomUUID?: () => string; getRandomValues?: (b: Uint8Array) => Uint8Array }
    | undefined;
  if (cryptoObj && typeof cryptoObj.randomUUID === 'function') {
    return cryptoObj.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
    cryptoObj.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Read the correlation ID a server echoed back, or '' when untagged. */
function _echoedRequestId(payload: unknown): string {
  const rid = (payload as { request_id?: unknown } | null | undefined)?.request_id;
  return typeof rid === 'string' ? rid : '';
}

/** Normalise a server error payload into a typed ServerError. */
function _toServerError(payload: ServerErrorData, event: string): ServerError {
  const msg = payload?.message ?? `Server returned error for '${event}'`;
  const code = payload?.code ?? 'SERVER_ERROR';
  return new ServerError(msg, undefined, { code, ...payload });
}

/**
 * Optional handshake-time auth payload for SocketIO `auth` parameter.
 * Provided as a function so we can await async credentials (e.g. authHash
 * Promise) at handshake time and re-evaluate on automatic reconnect.
 *
 * The backend's connect handler at api/app.py reads `auth.auth_hash` and
 * sets `session['credential_id']` deterministically at handshake — this
 * eliminates the cross-namespace session-propagation race that was causing
 * intermittent "WebAuthn session not authenticated" rejections on multi-sign
 * tests (cbc03-B/C).
 */
export type SigbashSocketAuthPayload =
  | { token?: string; auth_hash?: string; apikey_hash?: string }
  | undefined;

export type SigbashSocketAuthProvider = (
  cb: (payload: SigbashSocketAuthPayload) => void
) => void;

/**
 * Wraps a socket.io Socket connected to a Sigbash namespace.
 *
 * Usage:
 *   const sock = new SigbashSocket('https://api.example.com');
 *   const resp = await sock.request('register_key_with_hash', payload);
 *   sock.disconnect();
 *
 *   // With handshake-time auth (recommended for the musig2 namespace):
 *   const sock = new SigbashSocket(serverUrl, '/api/v2/musig2', (cb) => {
 *     authHashPromise.then(h => cb({ auth_hash: h }));
 *   });
 */
export class SigbashSocket {
  private readonly _socket: Socket;

  /**
   * Outstanding requests per base event name, in emission order. Exactly one
   * dispatcher pair (see `_dispatchers`) serves all requests of an event, so
   * each incoming response is consumed at most once.
   */
  private _pending = new Map<string, PendingRequest[]>();

  /** Lazily created response/error dispatcher pair per base event name. */
  private _dispatchers = new Map<
    string,
    { onResponse: (payload: unknown) => void; onError: (payload: ServerErrorData) => void }
  >();

  /**
   * @param serverUrl    - Base server URL (e.g. 'https://api.example.com')
   * @param namespace    - Socket.IO namespace path (default: '/api/v2/sdk')
   * @param authProvider - Optional async handshake-auth callback. Called by
   *                       socket.io-client before each connection attempt;
   *                       must invoke its argument with the auth payload
   *                       (or `undefined` to fall through to legacy auth).
   */
  constructor(
    serverUrl: string,
    namespace: string = '/api/v2/sdk',
    authProvider?: SigbashSocketAuthProvider
  ) {
    const base = serverUrl.replace(/\/$/, '');
    this._socket = io(`${base}${namespace}`, {
      autoConnect: true,
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: DEFAULT_TIMEOUT_MS,
      transports: ['websocket', 'polling'],
      ...(authProvider ? { auth: authProvider } : {}),
    });
  }

  /**
   * Emit a Socket.IO event and await the corresponding response or error event.
   *
   * Convention used by the backend:
   *   request event:  `<event>`
   *   success event:  `<event>_response`
   *   error event:    `<event>_error`
   *
   * Every object payload is stamped with a request-unique `request_id`. When
   * the server echoes it, the response resolves exactly the matching request
   * and any response carrying an unknown ID (late, duplicate, or stale) is
   * dropped. When the server does not echo it, responses resolve the oldest
   * pending request FIFO, preserving the historical pairing behavior.
   *
   * Error events route by ID the same way; an untagged error is treated as
   * connection-wide (auth expiry, internal error) and rejects every pending
   * request for the event.
   *
   * @param event - Base event name (without `_response`/`_error` suffix)
   * @param data  - Payload to emit
   * @param timeoutMs - Optional timeout override
   * @returns Resolved server response
   * @throws ServerError on server-side error, TimeoutError on timeout
   */
  request<T = Record<string, unknown>>(
    event: string,
    data: unknown,
    timeoutMs: number = DEFAULT_TIMEOUT_MS
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const entry: PendingRequest = {
        id: _newCorrelationId(),
        complete: (payload: unknown): void => {
          removeFromPending(event, entry);
          resolve(payload as T);
        },
        fail: (err: Error): void => {
          removeFromPending(event, entry);
          reject(err);
        },
      };

      const removeFromPending = (evt: string, pending: PendingRequest): void => {
        const list = this._pending.get(evt);
        if (!list) return;
        const i = list.indexOf(pending);
        if (i >= 0) list.splice(i, 1);
        if (list.length === 0) {
          this._pending.delete(evt);
          this._detach(evt);
        }
      };

      this._attach(event);
      this._pendingFor(event).push(entry);

      setTimeout(() => {
        entry.fail(new TimeoutError(event, timeoutMs));
      }, timeoutMs);

      const payload = (data !== null && typeof data === 'object' && !Array.isArray(data))
        ? { ...(data as Record<string, unknown>), request_id: entry.id }
        : data;
      this._socket.emit(event, payload);
    });
  }

  /** Registry list for an event, created on demand (insertion order kept). */
  private _pendingFor(event: string): PendingRequest[] {
    let list = this._pending.get(event);
    if (!list) {
      list = [];
      this._pending.set(event, list);
    }
    return list;
  }

  /**
   * Install the response/error dispatcher pair for an event on first use.
   * The dispatcher resolves at most one pending request per incoming
   * response: the one whose correlation ID matches, or — when the server
   * does not echo IDs — the oldest pending request.
   */
  private _attach(event: string): void {
    if (this._dispatchers.has(event)) return;

    const onResponse = (payload: unknown): void => {
      const list = this._pending.get(event);
      if (!list || list.length === 0) return;
      const rid = _echoedRequestId(payload);
      if (rid !== '') {
        const entry = list.find(p => p.id === rid);
        // Unknown ID: the response belongs to a request that already
        // resolved, timed out, or was never issued — drop it.
        if (!entry) return;
        entry.complete(payload);
        return;
      }
      list[0].complete(payload);
    };

    const onError = (payload: ServerErrorData): void => {
      const list = this._pending.get(event);
      if (!list || list.length === 0) return;
      const rid = _echoedRequestId(payload);
      if (rid !== '') {
        const entry = list.find(p => p.id === rid);
        if (!entry) return;
        entry.fail(_toServerError(payload, event));
        return;
      }
      // Untagged error: connection-wide — reject every pending request for
      // this event. Iterate a snapshot; each fail() mutates the list.
      for (const p of [...list]) p.fail(_toServerError(payload, event));
    };

    this._dispatchers.set(event, { onResponse, onError });
    this._socket.on(`${event}_response`, onResponse);
    this._socket.on(`${event}_error`, onError);
  }

  /** Remove the dispatcher pair once no request is pending for the event. */
  private _detach(event: string): void {
    const bound = this._dispatchers.get(event);
    if (!bound) return;
    this._socket.off(`${event}_response`, bound.onResponse);
    this._socket.off(`${event}_error`, bound.onError);
    this._dispatchers.delete(event);
  }

  /** Disconnect the underlying socket. */
  disconnect(): void {
    this._socket.disconnect();
  }

  /** Whether the underlying socket is currently connected. */
  get connected(): boolean {
    return this._socket.connected;
  }

  /**
   * Expose the raw socket.io-client Socket instance.
   *
   * Used by SigbashClient to register the musig2 socket on globalThis so
   * the Go WASM binary can locate it via js.Global().Get("sharedMusigSocket").
   */
  get rawSocket(): Socket {
    return this._socket;
  }
}
