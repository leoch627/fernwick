import type { Command, Preferences } from './schema';
import type { ErrorCode } from './errors';
import type { ConnectionState } from '../platform/network';
import type { DownloadView } from '../services/download';
export interface NodeView { id: string; name: string; group: string; region: string | null; protocol: string; compatible: boolean; reason: string | null; latency: number | null; probe: 'untested' | 'testing' | 'timeout' | 'healthy'; }
export interface AppView {
  brand: string; version: string; environment: 'test' | 'production'; demo: boolean;
  loggedIn: boolean; account: { email: string; planName: string; expiryKind: string; expiresAt: string | null; quotaKind: string; usedBytes: string | null; quotaBytes: string | null; observedAt: string; status: string } | null;
  connection: ConnectionState; selectedNode: string | null; actualNode: string | null;
  sync: 'Idle' | 'Syncing' | 'Fresh' | 'UsingValidCache' | 'NeedsLogin' | 'Denied' | 'Unavailable';
  lastSync: number | null; usableUntil: number | null; error: ErrorCode | null;
  nodes: NodeView[]; preferences: Preferences; storage: 'encrypted' | 'memory' | 'locked';
  /** Loopback HTTP/SOCKS port while connected in system proxy mode, else 0. */
  helperReady: boolean; proxyPort: number; policy: string; announcement: string | null; update: string; updateError?: ErrorCode | null; manualUpdate: boolean;
  /** The user asked to update: downloading (if needed), installing, then restarting. */
  installing: boolean; pendingRenewal: boolean;
  download: DownloadView; rules: string; showTrafficSummary: boolean;
  links: { website: boolean; renew: boolean; help: boolean; support: boolean };
  /** Problem report: the code is what the user gives to support. */
  report: { status: 'idle' | 'sending' | 'sent' | 'failed'; code: string | null }; reportAvailable: boolean;
  /** What the panel asks of a new account; null until the sign-up form asks, or when unreachable. */
  signup: SignupView | null; invite: InviteView | null; now: number;
}
export interface SignupView { emailCode: boolean; inviteRequired: boolean; emailSuffixes: string[]; inApp: boolean; }
/** message: the panel's own explanation of a refusal, e.g. 邀请码无效. */
export interface CommandResult { ok: boolean; state: AppView; error?: ErrorCode; message?: string; }
/** The account's invite code and how many people signed up with it. */
export interface InviteView { code: string; invited: number }
/** The connection's speed, already formatted ("1.2 KB/s"); sent once a second while connected. */
export interface TrafficView { up: string; down: string }
export interface ClientBridge { command(command: Command): Promise<CommandResult>; subscribe(listener: (state: AppView) => void): () => void; traffic?(listener: (traffic: TrafficView | null) => void): () => void; }
