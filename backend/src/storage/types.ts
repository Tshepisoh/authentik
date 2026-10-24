import type {
  AlertDoc,
  DeviceDoc,
  ProfileDoc,
  ReportDoc,
  SandboxSessionDoc,
  SettingsDoc,
} from './models.js';

/**
 * Every stored document belongs to exactly one user. Ownership is enforced
 * here as well as in the routes: there is no "list everything" operation.
 */
export interface Doc {
  id: string;
  uid: string;
  createdAt: string;
  /** ISO timestamp after which the document is treated as gone and purged. */
  expiresAt?: string;
}

export interface ListOptions<T> {
  limit?: number;
  /** Single-field equality filter. */
  where?: { field: keyof T & string; equals: string | number | boolean | null };
}

export interface Collection<T extends Doc> {
  get(id: string): Promise<T | null>;
  put(doc: T): Promise<void>;
  update(id: string, patch: Partial<Omit<T, 'id' | 'uid'>>): Promise<void>;
  delete(id: string): Promise<void>;
  /** Newest first. Expired documents are never returned. */
  listByUser(uid: string, options?: ListOptions<T>): Promise<T[]>;
  deleteByUser(uid: string): Promise<number>;
  /** Physically deletes documents whose `expiresAt` has passed. Returns how many were removed. */
  purgeExpired(now: Date): Promise<number>;
}

export interface Store {
  profiles: Collection<ProfileDoc>;
  settings: Collection<SettingsDoc>;
  devices: Collection<DeviceDoc>;
  reports: Collection<ReportDoc>;
  alerts: Collection<AlertDoc>;
  sandboxSessions: Collection<SandboxSessionDoc>;
}
