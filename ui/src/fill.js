import { useLayoutEffect, useState } from 'react';
import * as UI from '@hostwerk/ui';

/*
 * Füllhöhe: Listen nehmen den Rest des Fensters ein und scrollen in ihrer eigenen Fläche, die Seite bleibt stehen.
 * Neuere Hostwerk-Versionen bringen dafür useFillHeight mit – sonst gilt diese kleine Kopie (gleiches Verhalten), damit
 * die Erweiterung auch mit älteren Hostwerk-Versionen läuft.
 */
function useFillHeightLocal({ gap = 16, min = 320 } = {}) {
  const [el, setEl] = useState(null);
  useLayoutEffect(() => {
    if (!el) return undefined;
    const scroller = el.closest('.main');
    let raf = 0;
    const fit = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const top = el.getBoundingClientRect().top + (scroller ? scroller.scrollTop - scroller.getBoundingClientRect().top : 0);
        const avail = (scroller ? scroller.clientHeight : window.innerHeight) - top;
        const page = el.closest('.page');
        const bottom = page ? parseFloat(getComputedStyle(page).paddingBottom) || gap : gap;
        el.style.height = `${Math.max(min, Math.floor(avail - bottom))}px`;
      });
    };
    fit();
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(fit) : null;
    if (ro) { ro.observe(document.documentElement); if (scroller) ro.observe(scroller); }
    window.addEventListener('resize', fit);
    return () => { cancelAnimationFrame(raf); if (ro) ro.disconnect(); window.removeEventListener('resize', fit); el.style.height = ''; };
  }, [el, gap, min]);
  return setEl;
}

export const useFill = typeof UI.useFillHeight === 'function' ? UI.useFillHeight : useFillHeightLocal;
