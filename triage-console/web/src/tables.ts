// Reading a chosen log file in the browser: text as it is; an Excel workbook (.xlsx) sent to the local service
// (service/tabular.py) and read back as CSV text of its first sheet. Nothing leaves the laptop.

import { api } from "./api";

export const LOG_FILES = ".txt,.log,.csv,.tsv,.xlsx,text/plain,text/csv";
const MAX_TEXT = 60 * 1024 * 1024;
const MAX_EXCEL = 40 * 1024 * 1024;           // sent as base64 under the service's 64 MB request limit

export const isExcel = (name: string) => /\.xlsx?$/i.test(name);

/** Rows as CSV text: every cell quoted. A cell a spreadsheet would run as a formula (starting with = + - @, a tab or a
 * carriage return, unless it is a plain number) gets a leading apostrophe, so log text such as "=cmd|..." stays text. */
export function csvText(columns: string[], rows: unknown[][]): string {
  const cell = (v: unknown) => {
    let text = String(v ?? "");
    if (/^[=+\-@\t\r]/.test(text) && !/^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  return [columns.map(cell).join(","), ...rows.map((row) => row.map(cell).join(","))].join("\n");
}

/** The file's text; a too-large file or an old .xls workbook is refused with what to do instead. */
export async function readLogFile(file: File): Promise<string> {
  if (/\.xls$/i.test(file.name)) throw new Error("An older .xls workbook: save it as .xlsx or .csv.");
  const limit = isExcel(file.name) ? MAX_EXCEL : MAX_TEXT;
  if (file.size > limit) throw new Error(`${(file.size / 1e6).toFixed(0)} MB is over ${limit / 1e6} MB: use "File on this laptop" in Advanced.`);
  if (!isExcel(file.name)) return file.text();
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const { text } = await api("/api/tables/excel", { body: { data: btoa(binary), name: file.name } });
  return text;
}
