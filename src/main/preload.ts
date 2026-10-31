import { contextBridge, ipcRenderer } from 'electron';
import type { AppView, ClientBridge } from '../shared/view';
import type { Command } from '../shared/schema';
const bridge: ClientBridge = Object.freeze({
  command: (command: Command) => ipcRenderer.invoke('starrail:intent', command),
  subscribe: (listener: (state: AppView) => void) => { const handler = (_event: unknown, state: AppView) => listener(state); ipcRenderer.on('starrail:state', handler); return () => { ipcRenderer.removeListener('starrail:state', handler); }; },
});
contextBridge.exposeInMainWorld('starrail', bridge);
