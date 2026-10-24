import { NativeModule, requireOptionalNativeModule } from 'expo';
import type {
  ProtectionEvents,
  ProtectionStatus,
  ProtectionWarning,
  SampleAnalysis,
  ThreatListInfo,
  DnsEvent,
  VpnStatus,
} from './AuthentikProtection.types';

declare class AuthentikProtectionModule extends NativeModule<ProtectionEvents> {
  getStatus(): Omit<ProtectionStatus, 'supported'> & { supported: true };
  /** Returns false if no settings screen could be opened. */
  openNotificationAccessSettings(): boolean;
  requestRebind(): void;
  setEnabled(enabled: boolean): void;
  getWarnings(): ProtectionWarning[];
  dismissWarning(id: string): void;
  clearWarnings(): void;
  analyzeSample(title: string, text: string): SampleAnalysis;
  getThreatListInfo(): ThreatListInfo;
  /** Takes a `ThreatListUpdate` as JSON. Throws code `ERR_THREAT_DELTA` if a delta doesn't fit the stored list. */
  applyThreatUpdate(json: string): ThreatListInfo;
  /** Text shared to Authentik from another app, returned once, or null. */
  consumeSharedText(): string | null;
  /** Shows Android's VPN consent dialog when needed. True when Authentik may run the VPN. */
  requestVpnPermission(): Promise<boolean>;
  /** Throws `ERR_VPN_PERMISSION` without consent. */
  startVpn(): void;
  stopVpn(): void;
  getVpnStatus(): VpnStatus;
  getDnsEvents(): DnsEvent[];
  clearDnsEvents(): void;
  /** Android's VPN settings, for always-on. False if they couldn't be opened. */
  openVpnSettings(): boolean;
}

/** Null where the native module doesn't exist: iOS, web and Expo Go. */
export default requireOptionalNativeModule<AuthentikProtectionModule>('AuthentikProtection');
