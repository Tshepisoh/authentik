import { useCallback } from 'react';
import { FlatList, RefreshControl, View } from 'react-native';
import { useFocusEffect, useRouter } from 'expo-router';
import type { Alert } from '@authentik/shared';
import { api } from '@/shared/api/client';
import { useAsync } from '@/shared/lib/use-async';
import { Card, EmptyState, Loading, Notice, Text } from '@/shared/ui';
import { useTheme } from '@/shared/ui/theme';
import { relativeTime } from '@/shared/lib/format';

export default function Alerts() {
  const t = useTheme();
  const router = useRouter();
  const { data, setData, error, loading, refreshing, refresh } = useAsync(() => api.alerts());
  useFocusEffect(useCallback(() => void refresh(), [])); // eslint-disable-line react-hooks/exhaustive-deps

  const open = async (a: Alert) => {
    if (!a.reviewedAt) {
      api.reviewAlert(a.id).then((updated) => setData((list) => list?.map((x) => (x.id === a.id ? updated : x)) ?? null), () => undefined);
    }
    router.push({ pathname: '/report/[id]', params: { id: a.reportId } });
  };

  if (loading && !data) return <Loading label="Loading alerts" />;
  return (
    <FlatList
      style={{ backgroundColor: t.colors.bg }}
      contentContainerStyle={{ padding: t.space.lg, gap: t.space.md, flexGrow: 1 }}
      data={data ?? []}
      keyExtractor={(a) => a.id}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={refresh} />}
      ListHeaderComponent={error ? <Notice tone="warning">{error}</Notice> : undefined}
      renderItem={({ item }) => (
        <Card onPress={() => void open(item)} accessibilityLabel={`${item.reviewedAt ? '' : 'New. '}${item.title}`}
          style={!item.reviewedAt ? { borderColor: t.colors.danger, borderWidth: 1 } : undefined}>
          <View style={{ flexDirection: 'row', justifyContent: 'space-between', gap: t.space.sm }}>
            <Text variant="subheading" style={{ flex: 1 }}>{item.title}</Text>
            {!item.reviewedAt ? <Text variant="caption" color={t.colors.danger}>NEW</Text> : null}
          </View>
          <Text variant="small">{item.summary}</Text>
          <Text variant="caption" muted>{item.hostname} · {relativeTime(item.createdAt)}</Text>
        </Card>
      )}
      ListEmptyComponent={
        <EmptyState title="No alerts" body="We alert you only for serious findings — a known threat, a blocked attack, or a payment that doesn’t match. Minor warnings stay in their reports." />
      }
    />
  );
}
