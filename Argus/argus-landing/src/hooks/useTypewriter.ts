import { useState, useEffect, useRef } from 'react';

export function useTypewriter(lines: string[], speed = 30, startDelay = 0) {
  const [displayed, setDisplayed] = useState<string[]>([]);
  const [currentLine, setCurrentLine] = useState(0);
  const [currentChar, setCurrentChar] = useState(0);
  const [done, setDone] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (lines.length === 0) return;

    const timeout = setTimeout(() => {
      started.current = true;
    }, startDelay);

    return () => clearTimeout(timeout);
  }, [lines, startDelay]);

  useEffect(() => {
    if (!started.current || lines.length === 0) return;
    if (currentLine >= lines.length) {
      setDone(true);
      return;
    }

    const line = lines[currentLine];

    if (currentChar < line.length) {
      const timer = setTimeout(() => {
        setDisplayed((prev) => {
          const copy = [...prev];
          copy[currentLine] = (copy[currentLine] || '') + line[currentChar];
          return copy;
        });
        setCurrentChar((c) => c + 1);
      }, speed);
      return () => clearTimeout(timer);
    } else {
      // Line complete — move to next after a small pause
      const timer = setTimeout(() => {
        setCurrentLine((l) => l + 1);
        setCurrentChar(0);
      }, 200);
      return () => clearTimeout(timer);
    }
  }, [currentLine, currentChar, lines, speed, started.current]);

  // Kick off after startDelay
  useEffect(() => {
    const interval = setInterval(() => {
      if (started.current && displayed.length === 0 && lines.length > 0) {
        setDisplayed(['']);
        clearInterval(interval);
      }
    }, 50);
    return () => clearInterval(interval);
  }, [lines, displayed.length]);

  return { displayed, done, currentLine };
}
