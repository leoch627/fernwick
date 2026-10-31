import type { AppView, ClientBridge, CommandResult } from '../shared/view';

// Importing the runtime initializes native handlers. Keep browser previews free
// of those handlers and let the native environment injected by Wails select it.
export function isWails(): boolean {
  const native = window as unknown as {
    chrome?: { webview?: { postMessage?: unknown } };
    webkit?: { messageHandlers?: { external?: { postMessage?: unknown } } };
  };
  return '_wails' in window || typeof native.chrome?.webview?.postMessage === 'function' || typeof native.webkit?.messageHandlers?.external?.postMessage === 'function';
}

export function wailsBridge(): ClientBridge {
  const runtime = import('@wailsio/runtime');
  return {
    async command(command) {
      const { Call } = await runtime;
      return await Call.ByName('main.Bridge.Command', command) as CommandResult;
    },
    subscribe(listener) {
      let cancelled = false;
      let unsubscribe: (() => void) | undefined;
      void runtime.then(({ Events }) => {
        if (!cancelled) unsubscribe = Events.On('starrail:state', event => listener(event.data as AppView));
      });
      return () => { cancelled = true; unsubscribe?.(); };
    },
  };
}
