import { useState, useEffect, useRef } from 'react';

export function useCountUp(target: number, duration = 1200, start = false, decimals = 0) {
  const [value, setValue] = useState(0);
  const frameRef = useRef<number>(0);

  useEffect(() => {
    if (!start) {
      setValue(0);
      return;
    }

    const startTime = performance.now();

    function tick(now: number) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = eased * target;
      setValue(Number(current.toFixed(decimals)));

      if (progress < 1) {
        frameRef.current = requestAnimationFrame(tick);
      }
    }

    frameRef.current = requestAnimationFrame(tick);

    return () => {
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    };
  }, [target, duration, start, decimals]);

  return value;
}
