/**
 * Tests for SigbashSocket request/response correlation and the
 * get_encrypted_kmc key-identity validation in SigbashClient.
 *
 * The socket.io-client module is mocked with a controllable fake socket so
 * tests can play the server: emit responses in arbitrary order, replay stale
 * responses, and emit untagged payloads the way older servers do.
 */

jest.mock('socket.io-client', () => {
  type Handler = (...args: unknown[]) => void;
  const handlers = new Map<string, Set<Handler>>();
  const mockSocket = {
    connected: true,
    disconnected: false,
    emit: jest.fn(),
    on: jest.fn((event: string, cb: Handler) => {
      if (!handlers.has(event)) handlers.set(event, new Set());
      handlers.get(event)!.add(cb);
      return mockSocket;
    }),
    off: jest.fn((event: string, cb?: Handler) => {
      if (cb) handlers.get(event)?.delete(cb);
      else handlers.delete(event);
      return mockSocket;
    }),
    once: jest.fn(),
    disconnect: jest.fn(),
  };
  const io = jest.fn(() => mockSocket);
  return { io, __sigbashMockHandlers: handlers, __sigbashMockSocket: mockSocket };
});

import { io } from 'socket.io-client';
import { SigbashSocket } from './socket';
import { ServerError, SigbashSDKError, TimeoutError } from './errors';
import { SigbashClient } from './SigbashClient';

type Handler = (...args: unknown[]) => void;

interface MockSocket {
  emit: jest.Mock;
  on: jest.Mock;
  off: jest.Mock;
  disconnect: jest.Mock;
}

const ioMock = io as unknown as jest.Mock;
const mockModule = jest.requireMock('socket.io-client') as {
  __sigbashMockHandlers: Map<string, Set<Handler>>;
  __sigbashMockSocket: MockSocket;
};
const handlers = mockModule.__sigbashMockHandlers;

/** The fake Socket the client side holds (created per SigbashSocket). */
function clientSocket(): MockSocket {
  return ioMock.mock.results[ioMock.mock.results.length - 1].value as MockSocket;
}

/** Deliver an event from the fake server to every registered handler. */
function serverEmit(event: string, payload: unknown): void {
  for (const cb of [...(handlers.get(event) ?? [])]) cb(payload);
}

/** Payloads the client emitted for a given event, in order. */
function emittedPayloads(event: string): Array<Record<string, unknown>> {
  return clientSocket()
    .emit.mock.calls.filter((c: unknown[]) => c[0] === event)
    .map((c: unknown[]) => c[1] as Record<string, unknown>);
}

/** Wait out the async emit wrapper / promise machinery. */
function flush(): Promise<void> {
  return new Promise(resolve => setImmediate(resolve));
}

beforeEach(() => {
  ioMock.mockClear();
  mockModule.__sigbashMockSocket.emit.mockClear();
  handlers.clear();
});

describe('SigbashSocket request correlation', () => {
  it('stamps every object payload with a unique request_id', () => {
    const sock = new SigbashSocket('https://test.example');
    sock.request('stamp', { a: 1 }, 250).catch(() => undefined);
    sock.request('stamp', { a: 2 }, 250).catch(() => undefined);
    const payloads = emittedPayloads('stamp');
    expect(payloads).toHaveLength(2);
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    expect(payloads[0]['request_id']).toMatch(uuid);
    expect(payloads[1]['request_id']).toMatch(uuid);
    expect(payloads[0]['request_id']).not.toBe(payloads[1]['request_id']);
  });

  it('resolves each concurrent request with its own response when responses are reordered', async () => {
    const sock = new SigbashSocket('https://test.example');
    const p1 = sock.request<Record<string, unknown>>('kmc_reorder', { key_id: '1' }, 1000);
    const p2 = sock.request<Record<string, unknown>>('kmc_reorder', { key_id: '2' }, 1000);
    const p3 = sock.request<Record<string, unknown>>('kmc_reorder', { key_id: '3' }, 1000);

    const ids = emittedPayloads('kmc_reorder').map(p => p['request_id'] as string);
    expect(ids).toHaveLength(3);

    // Server answers out of order; each response resolves only its own request.
    serverEmit('kmc_reorder_response', { request_id: ids[2], key_index: 3 });
    serverEmit('kmc_reorder_response', { request_id: ids[1], key_index: 2 });
    serverEmit('kmc_reorder_response', { request_id: ids[0], key_index: 1 });

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
    expect(r1).toEqual({ request_id: ids[0], key_index: 1 });
    expect(r2).toEqual({ request_id: ids[1], key_index: 2 });
    expect(r3).toEqual({ request_id: ids[2], key_index: 3 });
  });

  it('drops a late response for an already-resolved request', async () => {
    const sock = new SigbashSocket('https://test.example');
    const p1 = sock.request<Record<string, unknown>>('kmc_late', { key_id: '1' }, 1000);
    const id1 = emittedPayloads('kmc_late')[0]['request_id'] as string;
    serverEmit('kmc_late_response', { request_id: id1, key_index: 1 });
    await expect(p1).resolves.toEqual({ request_id: id1, key_index: 1 });

    const p2 = sock.request<Record<string, unknown>>('kmc_late', { key_id: '2' }, 1000);
    const id2 = emittedPayloads('kmc_late')[1]['request_id'] as string;

    // A duplicate of the first response arrives while the second is pending.
    serverEmit('kmc_late_response', { request_id: id1, key_index: 1 });
    await flush();

    let resolved = false;
    void p2.then(() => { resolved = true; });
    await flush();
    expect(resolved).toBe(false);

    serverEmit('kmc_late_response', { request_id: id2, key_index: 2 });
    await expect(p2).resolves.toEqual({ request_id: id2, key_index: 2 });
  });

  it('pairs untagged responses with pending requests FIFO (old server)', async () => {
    const sock = new SigbashSocket('https://test.example');
    const p1 = sock.request<Record<string, unknown>>('fifo', { n: 1 }, 1000);
    const p2 = sock.request<Record<string, unknown>>('fifo', { n: 2 }, 1000);

    serverEmit('fifo_response', { seq: 'a' });
    await expect(p1).resolves.toEqual({ seq: 'a' });

    serverEmit('fifo_response', { seq: 'b' });
    await expect(p2).resolves.toEqual({ seq: 'b' });
  });

  it('routes a tagged error to exactly its request', async () => {
    const sock = new SigbashSocket('https://test.example');
    const p1 = sock.request<Record<string, unknown>>('kmc_err', { key_id: '1' }, 1000);
    const p2 = sock.request<Record<string, unknown>>('kmc_err', { key_id: '2' }, 1000);
    const ids = emittedPayloads('kmc_err').map(p => p['request_id'] as string);

    serverEmit('kmc_err_error', {
      request_id: ids[1], error: true, code: 'NOT_FOUND', message: 'Key not found',
    });
    await expect(p2).rejects.toThrow(ServerError);

    // The other request stays pending and still resolves afterwards.
    serverEmit('kmc_err_response', { request_id: ids[0], key_index: 1 });
    await expect(p1).resolves.toEqual({ request_id: ids[0], key_index: 1 });
  });

  it('rejects every pending request on an untagged error (connection-wide)', async () => {
    const sock = new SigbashSocket('https://test.example');
    const p1 = sock.request<Record<string, unknown>>('bcast', {}, 1000);
    const p2 = sock.request<Record<string, unknown>>('bcast', {}, 1000);

    serverEmit('bcast_error', { error: true, code: 'UNAUTHORIZED', message: 'Unauthorized' });
    await expect(p1).rejects.toThrow(/Unauthorized/);
    await expect(p2).rejects.toThrow(/Unauthorized/);
  });

  it('times out, cleans up its listeners, and ignores a later response', async () => {
    const sock = new SigbashSocket('https://test.example');
    const p = sock.request<Record<string, unknown>>('slow', {}, 50);
    const id = emittedPayloads('slow')[0]['request_id'];

    await expect(p).rejects.toThrow(TimeoutError);

    // Both listeners were removed on timeout, so a late response is a no-op.
    const offs = clientSocket().off.mock.calls.map((c: unknown[]) => c[0]);
    expect(offs).toContain('slow_response');
    expect(offs).toContain('slow_error');
    serverEmit('slow_response', { request_id: id, late: true });
    await flush();
  });

  it('passes non-object payloads through without stamping', () => {
    const sock = new SigbashSocket('https://test.example');
    sock.request('raw', 'raw-string', 250).catch(() => undefined);
    expect(emittedPayloads('raw')[0]).toBe('raw-string');
  });
});

describe('get_encrypted_kmc key-identity validation', () => {
  const makeClient = (): SigbashClient =>
    new SigbashClient({
      apiKey: 'org-api-key',
      userKey: 'user-key',
      userSecretKey: '0123456789abcdef0123456789abcdef',
      serverUrl: 'https://test.example',
    });

  type Validator = (keyId: string, optsKeyIndex: number | undefined, response: { key_index?: number }) => void;
  const validate = (client: SigbashClient): Validator =>
    (client as unknown as { _validateKmcResponseIdentity: Validator })._validateKmcResponseIdentity.bind(client);

  it('accepts a response whose key_index matches the requested key_id', () => {
    expect(() => validate(makeClient())('5', undefined, { key_index: 5 })).not.toThrow();
  });

  it('rejects a mismatched key_index with KEY_IDENTITY_MISMATCH', () => {
    expect.assertions(3);
    try {
      validate(makeClient())('5', undefined, { key_index: 7 });
    } catch (err) {
      expect(err).toBeInstanceOf(SigbashSDKError);
      expect((err as SigbashSDKError).code).toBe('KEY_IDENTITY_MISMATCH');
      expect((err as SigbashSDKError).message).toContain('Key identity mismatch');
    }
  });

  it('tolerates a response without a numeric key_index (older server)', () => {
    expect(() => validate(makeClient())('5', undefined, {})).not.toThrow();
    expect(() => validate(makeClient())('5', undefined, { key_index: undefined })).not.toThrow();
  });

  it('falls back to the requested key_index when key_id is non-numeric', () => {
    const v = validate(makeClient());
    expect(() => v('not-a-number', 3, { key_index: 3 })).not.toThrow();
    expect(() => v('not-a-number', 3, { key_index: 4 })).toThrow();
    // No expectation supplied and a non-numeric key_id: advisory only.
    expect(() => v('not-a-number', undefined, { key_index: 9 })).not.toThrow();
  });
});
