import { useCallback } from 'react';
import { FlatList, RefreshControl } from 'react-native';
import { useFocusEffect, useRouter } from 'expo-router';
import { api } from '@/shared/api/client';
import { useAsync } from '@/shared/lib/use-async';
import { Button, EmptyState, Loading, Notice } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { ReportRow } from '@/features/reports/report-row';

export default function History() {
  const t = useTheme();
  const router = useRouter();
  const { data, error, loading, refreshing, refresh } = useAsync(() => api.reports());
  useFocusEffect(useCallback(() => void refresh(), [])); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading && !data) return <Loading label="Loading history" />;
  return (
    <FlatList
      style={{ backgroundColor: t.colors.bg }}
      contentContainerStyle={{ padding: t.space.lg, gap: t.space.md, flexGrow: 1 }}
      data={data ?? []}
      keyExtractor={(r) => r.id}
      renderItem={({ item }) => <ReportRow report={item} />}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={refresh} />}
      ListHeaderComponent={error ? <Notice tone="warning">{error}</Notice> : undefined}
      ListEmptyComponent={
        <EmptyState
          title="No reports yet"
          body="Website scans, Sandbox sessions and payment checks you run will be listed here until they expire."
          action={<Button title="Check a website" onPress={() => router.push('/scan')} />}
        />
      }
    />
  );
}
