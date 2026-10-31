import { beforeEach, expect, it, vi } from 'vitest';
import { isWails, wailsBridge } from '../src/renderer/wails';
const runtime = vi.hoisted(() => ({ ByName: vi.fn(), On: vi.fn() }));
vi.mock('@wailsio/runtime', () => ({ Call: { ByName: runtime.ByName }, Events: { On: runtime.On } }));
beforeEach(() => { vi.clearAllMocks(); vi.stubGlobal('window', {}); });
it('only selects Wails for a native runtime or native message handler', () => {
  expect(isWails()).toBe(false);
  for (const window of [{ _wails: {} }, { chrome: { webview: { postMessage() {} } } }, { webkit: { messageHandlers: { external: { postMessage() {} } } } }]) {
    vi.stubGlobal('window', window); expect(isWails()).toBe(true);
  }
  vi.stubGlobal('window', { chrome: {}, webkit: {} }); expect(isWails()).toBe(false);
});
it('passes a structured command through the sole registered bridge method', async () => {
  const result = { ok: true, state: {} }; runtime.ByName.mockResolvedValue(result);
  const command = { type: 'login' as const, email: 'a@example.invalid', password: 'password' };
  expect(await wailsBridge().command(command)).toBe(result);
  expect(runtime.ByName).toHaveBeenCalledWith('main.Bridge.Command', command);
});
it('forwards the event data and unsubscribes without retaining listeners', async () => {
  const off = vi.fn(); runtime.On.mockReturnValue(off);
  const listener = vi.fn(), bridge = wailsBridge(), unsubscribe = bridge.subscribe(listener);
  await bridge.command({ type: 'state' });
  const [name, callback] = runtime.On.mock.calls[0]!;
  expect(name).toBe('starrail:state'); const view = { brand: 'test' }; callback({ data: view });
  expect(listener).toHaveBeenCalledWith(view); unsubscribe(); expect(off).toHaveBeenCalledOnce();
});
it('does not register an event listener after an early unmount', async () => {
  const bridge = wailsBridge(); bridge.subscribe(vi.fn())();
  await bridge.command({ type: 'state' }); expect(runtime.On).not.toHaveBeenCalled();
});
