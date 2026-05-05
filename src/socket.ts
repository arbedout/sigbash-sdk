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
      const responseEvent = `${event}_response`;
      const errorEvent = `${event}_error`;

      const cleanup = (): void => {
        this._socket.off(responseEvent, onResponse);
        this._socket.off(errorEvent, onError);
        clearTimeout(timer);
      };

      const onResponse = (payload: T): void => {
        cleanup();
        resolve(payload);
      };

      const onError = (payload: ServerErrorData): void => {
        cleanup();
        const msg = payload?.message ?? `Server returned error for '${event}'`;
        const code = payload?.code ?? 'SERVER_ERROR';
        reject(new ServerError(msg, undefined, { code, ...payload }));
      };

      const timer = setTimeout(() => {
        cleanup();
        reject(new TimeoutError(event, timeoutMs));
      }, timeoutMs);

      this._socket.once(responseEvent, onResponse);
      this._socket.once(errorEvent, onError);
      this._socket.emit(event, data);
    });
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
