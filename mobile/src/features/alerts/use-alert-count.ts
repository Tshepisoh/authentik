import { useCallback, useState } from 'react';
import { useFocusEffect } from 'expo-router';
import { api } from '@/shared/api/client';

/** Unreviewed alert count, refreshed whenever the tab bar's screen regains focus. */
export function useUnreviewedAlertCount() {
  const [count, setCount] = useState(0);
  useFocusEffect(
    useCallback(() => {
      let live = true;
      api.alerts(true).then((a) => live && setCount(a.length), () => undefined);
      return () => {
        live = false;
      };
    }, []),
  );
  return count;
}
