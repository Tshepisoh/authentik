/**
 * `@firebase/auth` lists its generic `types` condition before `react-native`
 * in its export map, so TypeScript never sees the React Native typings, even
 * though Metro loads the React Native build (which exports this) at runtime.
 * Remove once Firebase reorders its export conditions.
 */
import type { Persistence } from '@firebase/auth';

declare module '@firebase/auth' {
  export function getReactNativePersistence(storage: {
    getItem(key: string): Promise<string | null>;
    setItem(key: string, value: string): Promise<void>;
    removeItem(key: string): Promise<void>;
  }): Persistence;
}
