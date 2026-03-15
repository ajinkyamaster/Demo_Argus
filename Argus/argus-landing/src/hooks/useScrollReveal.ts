import { useEffect } from 'react';

export function useScrollReveal() {
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const el = entry.target as HTMLElement;
            const delay = el.dataset.delay || '0';
            el.style.transitionDelay = delay + 'ms';
            el.classList.add('revealed');
            observer.unobserve(el);
          }
        });
      },
      { threshold: 0.1 }
    );

    function observeAll() {
      document.querySelectorAll('.reveal:not(.revealed)').forEach((el) => {
        observer.observe(el);
      });
    }

    // Initial observe
    observeAll();

    // Re-observe after DOM updates (for dynamically added elements)
    const mutationObserver = new MutationObserver(() => {
      observeAll();
    });
    mutationObserver.observe(document.body, { childList: true, subtree: true });

    return () => {
      observer.disconnect();
      mutationObserver.disconnect();
    };
  }, []);
}
