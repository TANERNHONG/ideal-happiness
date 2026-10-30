import { api, qs } from './api';
import { clear, errorBox, h } from './dom';
import { icon } from './icons';

export const reviewFilters: Record<string, string[]> = { host: [], username: [], program: [], address: [] };
export const filterQuery = () => JSON.stringify(reviewFilters);
export const filtersActive = () => Object.values(reviewFilters).some(v => v.length);
const fields = [['host', 'Server'], ['username', 'Account'], ['program', 'Program'], ['address', 'Address']];
let serial = 0;

export function filterBar(source: string, changed: () => void, facts?: Record<string, string>[]): HTMLElement {
  const root = h('div', { class: 'card review-filters', role: 'group', 'aria-label': 'Review filters' });
  for (const [field, label] of fields) {
    const id = `review-filter-${++serial}`;
    const input = h('input', { type: 'search', list: id, placeholder: label, 'aria-label': `Filter by ${label.toLowerCase()}` });
    const choices = h('datalist', { id }), status = h('span', { class: 'rf-status' });
    let request = 0, timer = 0;
    const suggest = async () => {
      const token = ++request;
      try {
        const values: string[] = facts ? [...new Set(facts.map(f => f[field]).filter(Boolean))].filter(v => v.toLowerCase().includes(input.value.toLowerCase())).slice(0, 100)
          : (await api(`/api/review/options${qs({ source, field, search: input.value })}`)).values;
        if (request === token) { clear(choices, values.map(v => h('option', { value: v }))); clear(status); }
      } catch (e) { if (request === token) { clear(status, errorBox(e)); } }
    };
    input.addEventListener('focus', suggest);
    input.addEventListener('input', () => { clearTimeout(timer); timer = window.setTimeout(suggest, 250); });
    const add = () => { const value = input.value.trim(); if (value && !reviewFilters[field].includes(value)) { reviewFilters[field].push(value); changed(); } };
    input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); add(); } });
    root.append(h('div', { class: 'rf-field' }, input, choices,
      h('button', { class: 'icon-btn', onclick: add, title: `Add ${label.toLowerCase()} filter`, 'aria-label': `Add ${label.toLowerCase()} filter` }, icon('plus', 14)), status));
  }
  const chips = h('div', { class: 'rf-chips' }, icon('filter', 14));
  for (const [field, label] of fields) for (const value of reviewFilters[field]) chips.append(h('button', { class: 'rf-chip', title: `Remove ${label.toLowerCase()} filter`, 'aria-label': `${label}: ${value}`,
    onclick: () => { reviewFilters[field] = reviewFilters[field].filter(v => v !== value); changed(); } }, h('span', {}, label), value, icon('close', 12)));
  if (filtersActive()) {
    chips.append(h('button', { class: 'btn small', 'aria-label': 'Clear filters', onclick: () => { Object.keys(reviewFilters).forEach(k => reviewFilters[k] = []); changed(); } }, icon('close', 12), 'Clear'));
    root.append(chips);
  }
  return root;
}

export function matchesFacts(facts: Record<string, string>[]): boolean {
  return !filtersActive() || facts.some(f => Object.entries(reviewFilters).every(([k, values]) => !values.length || values.includes(f[k] ?? '')));
}

export function linkedReports(finding: string): HTMLElement {
  const box = h('div', { class: 'report-links small' });
  api(`/api/reports${qs({ finding })}`).then(r => clear(box,
    r.reports.map((p: any) => h('a', { href: `#/reports/${p.id}`, class: 'btn small', title: p.title || 'Untitled report' }, icon('reports', 14), `${p.number} · v${p.current_version}`))
  )).catch(e => clear(box, errorBox(e)));
  return box;
}
