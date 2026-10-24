import { useCallback, useEffect, useRef, useState } from 'react';
import { Image, StyleSheet, View } from 'react-native';

/**
 * Double-buffered display for the Sandbox screencast.
 *
 * Swapping an <Image>'s `source` makes Android clear the old bitmap before the
 * new one has decoded, which shows up as flicker. Instead, two stacked layers
 * are kept: new frames load into the hidden layer and only become visible once
 * decoded. Frames that arrive while one is still decoding replace each other,
 * so only the latest is shown and decoding can never fall behind the stream.
 */
export function FrameView({ frame }: { frame: string | null }) {
  const [layers, setLayers] = useState<[string | null, string | null]>([null, null]);
  const [front, setFront] = useState<0 | 1>(0);
  const loading = useRef(false);
  const pending = useRef<string | null>(null);
  const frontRef = useRef<0 | 1>(0);

  const loadIntoBack = useCallback((data: string) => {
    loading.current = true;
    const back = frontRef.current === 0 ? 1 : 0;
    setLayers((prev) => {
      const next: [string | null, string | null] = [prev[0], prev[1]];
      next[back] = data;
      return next;
    });
  }, []);

  useEffect(() => {
    if (!frame) return;
    if (loading.current) pending.current = frame;
    else loadIntoBack(frame);
  }, [frame, loadIntoBack]);

  const onLoaded = (layer: 0 | 1) => {
    if (layer === frontRef.current) return; // the visible layer re-rendering, not a new frame
    frontRef.current = layer;
    setFront(layer);
    loading.current = false;
    const next = pending.current;
    pending.current = null;
    if (next) loadIntoBack(next);
  };

  return (
    <View style={StyleSheet.absoluteFill}>
      {([0, 1] as const).map((i) =>
        layers[i] ? (
          <Image
            key={i}
            source={{ uri: `data:image/jpeg;base64,${layers[i]}` }}
            style={[StyleSheet.absoluteFill, { opacity: front === i ? 1 : 0, zIndex: front === i ? 1 : 0 }]}
            resizeMode="contain"
            fadeDuration={0}
            onLoad={() => onLoaded(i)}
            onError={() => {
              loading.current = false;
            }}
          />
        ) : null,
      )}
    </View>
  );
}
