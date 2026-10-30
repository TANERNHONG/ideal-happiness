// A portable print snapshot, made from the paper currently visible to the analyst.
// Text stays text; PDF uses an inert sanitised clone. Export never re-queries evidence.
import { h } from './dom';
import { icon } from './icons';

export function paperCopy(paper: HTMLElement): HTMLElement {
  const clone = paper.cloneNode(true) as HTMLElement;
  const originals = [...paper.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('input,textarea')];
  clone.querySelectorAll('input,textarea').forEach((el, i) => el.replaceWith(h('span', { class: `${el.className} rp-print-value` }, originals[i].value)));
  const canvases = [...paper.querySelectorAll('canvas')];
  clone.querySelectorAll('canvas').forEach((el, i) => el.replaceWith(h('img', { src: canvases[i].toDataURL('image/png'), alt: 'Cluster map', class: 'rp-map-image' })));
  clone.querySelectorAll('.rp-ui,.rp-grip,.rp-tools,.rp-fn-btn,.rp-tile-x,.rp-empty,.icon-btn,button.btn,.rp-tb-corner,select').forEach(el => el.remove());
  clone.querySelectorAll('[contenteditable]').forEach(el => el.removeAttribute('contenteditable'));
  clone.querySelectorAll('button').forEach(el => el.replaceWith(h('span', { class: el.className }, ...el.childNodes)));     // keeps a tick box's box
  return clone;
}

export function printSnapshot(paper: HTMLElement): any[] {
  const root = paperCopy(paper), out: any[] = [];
  const heading = '.rp-doc-title,.rp-sec-head,.rp-mast-title,.rp-mast-sub,.rp-foot-head';
  const blocks = 'div,section,header,footer,aside,p,dl,ol,ul,li,table,figure,img';
  function walk(el: Element): void {
    if (el.matches('img')) {
      const src = el.getAttribute('src') ?? '';
      if (src.startsWith('data:image/png;base64,')) out.push({ type: 'image', src });
      return;
    }
    if (el.matches('table')) {
      out.push({ type: 'table', rows: [...el.querySelectorAll('tr')].map(tr => [...tr.children].map(c => {
        const rgb = (c as HTMLElement).style.backgroundColor.match(/\d+/g);
        return { text: c.textContent ?? '', fill: rgb?.length === 3 ? rgb.map(v => Number(v).toString(16).padStart(2, '0')).join('') : '' };
      })).filter(r => r.length) });
      return;
    }
    if (el.matches(heading)) { out.push({ type: 'heading', text: el.textContent?.trim(), level: el.matches('.rp-doc-title') ? 0 : 1 }); return; }
    if (!el.querySelector(blocks) || el.matches('.rp-sign,.rp-field,.rp-tile,.rp-ll-line,.rp-cm,.rp-map-caption')) {
      const text = el.textContent?.trim();
      if (text) out.push({ type: 'p', text });
      return;
    }
    let inline = '';
    const flush = () => { if (inline.trim()) out.push({ type: 'p', text: inline.trim() }); inline = ''; };
    for (const node of el.childNodes) {
      if (node instanceof Element && (node.matches(blocks) || node.matches(heading))) { flush(); walk(node); }
      else inline += node.textContent ?? '';
    }
    flush();
  }
  walk(root);
  return out;
}

export function previewPaper(paper: HTMLElement): void {
  const modal = h('dialog', { class: 'rp-preview', 'aria-label': 'Report preview' });
  modal.append(h('button', { class: 'icon-btn rp-preview-close', title: 'Close', 'aria-label': 'Close preview', onclick: () => modal.close() }, icon('close', 16)), paperCopy(paper));
  modal.addEventListener('close', () => modal.remove());
  document.body.append(modal);
  modal.showModal();
}

export function downloadReport(result: { filename: string; mime: string; content: string }): void {
  const bytes = Uint8Array.from(atob(result.content), c => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], { type: result.mime }));
  const a = h('a', { href: url, download: result.filename });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
