import type { ProtectionStatus } from './src/AuthentikProtection.types';
import Native from './src/AuthentikProtectionModule';

export * from './src/AuthentikProtection.types';
export { Native as AuthentikProtection };

const UNSUPPORTED: ProtectionStatus = {
  supported: false,
  notificationAccess: false,
  listenerConnected: false,
  enabled: false,
  warningsAllowed: false,
};

export function getProtectionStatus(): ProtectionStatus {
  return Native?.getStatus() ?? UNSUPPORTED;
}
