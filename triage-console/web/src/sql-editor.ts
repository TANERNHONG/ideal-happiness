// SQL editor for the Data tab: CodeMirror 6 with SQLite highlighting in the
// app's palette, completion of the real table and column names, and
// Ctrl/Cmd+Enter to run.

import { autocompletion, closeBrackets, closeBracketsKeymap, completionKeymap } from "@codemirror/autocomplete";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { sql, SQLite, type SQLNamespace } from "@codemirror/lang-sql";
import { bracketMatching, HighlightStyle, indentOnInput, syntaxHighlighting } from "@codemirror/language";
import { EditorState, Prec } from "@codemirror/state";
import { drawSelection, EditorView, highlightActiveLine, keymap, lineNumbers, placeholder } from "@codemirror/view";
import { tags as t } from "@lezer/highlight";

// Colours come from CSS variables (styles.css), so light and dark themes both work.
const highlight = HighlightStyle.define([
  { tag: t.keyword, color: "var(--sql-keyword)", fontWeight: "700" },
  { tag: [t.standard(t.name), t.function(t.variableName)], color: "var(--sql-function)", fontWeight: "600" },
  { tag: [t.string, t.special(t.string)], color: "var(--sql-string)" },
  { tag: [t.number, t.bool, t.null], color: "var(--sql-number)" },
  { tag: [t.lineComment, t.blockComment, t.comment], color: "var(--sql-comment)", fontStyle: "italic" },
  { tag: t.typeName, color: "var(--sql-type)" },
  { tag: t.special(t.name), color: "var(--sql-quoted)" },
  { tag: t.operator, color: "var(--sql-operator)" },
  { tag: [t.punctuation, t.paren, t.bracket, t.separator], color: "var(--sql-operator)" },
]);

const look = EditorView.theme({
  "&": { fontSize: "0.85rem", backgroundColor: "var(--surface-2)", borderRadius: "var(--r)", border: "1px solid transparent" },
  "&.cm-focused": { outline: "none", borderColor: "var(--brand)" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", lineHeight: "1.55", minHeight: "190px", maxHeight: "420px" },
  ".cm-content": { padding: "10px 0", caretColor: "var(--brand)" },
  ".cm-gutters": { backgroundColor: "transparent", border: "none", color: "var(--muted)", paddingLeft: "6px" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "rgb(127 127 127 / 7%)" },
  ".cm-cursor": { borderLeftColor: "var(--brand)", borderLeftWidth: "2px" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection": { backgroundColor: "var(--brand-soft) !important" },
  ".cm-tooltip": { border: "1px solid var(--border)", borderRadius: "var(--r)", boxShadow: "none", backgroundColor: "var(--surface)", overflow: "hidden" },
  ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--brand)", color: "var(--brand-text)" },
  ".cm-placeholder": { color: "var(--muted)" },
});

/** {"auth.events": [...columns]} -> {auth: {events: [...columns]}} for schema-aware completion. */
function namespace(tables: Record<string, string[]>): SQLNamespace {
  const out: Record<string, Record<string, string[]>> = {};
  for (const [qualified, columns] of Object.entries(tables)) {
    const [schema, table] = qualified.split(".");
    (out[schema] ??= {})[table] = columns;
  }
  return out;
}

// Early warning while typing; the service (sql_guard.py) is the authority and checks again.
const FORBIDDEN = /\b(INSERT|UPDATE|DELETE|UPSERT|MERGE|INTO|TRUNCATE|CREATE|DROP|ALTER|RENAME|REINDEX|VACUUM|ANALYZE|ATTACH|DETACH|PRAGMA|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|TRANSACTION|GRANT|REVOKE|EXEC|EXECUTE|CALL)\b/i;

/** Why this query cannot run here, or null if it only reads. */
export function readOnlyProblem(text: string): string | null {
  const bare = text
    .replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/'(?:[^']|'')*'/g, "''").replace(/"(?:[^"]|"")*"|`[^`]*`|\[[^\]]*\]/g, '"q"');
  const statements = bare.split(";").filter((s) => s.trim());
  if (!statements.length) return null;
  if (statements.length > 1) return "One statement at a time.";
  if (!/^\s*(SELECT|WITH)\b/i.test(statements[0])) return "Only reading queries run here: start with SELECT or WITH.";
  const word = FORBIDDEN.exec(statements[0])?.[1] ?? (/\bREPLACE\b(?!\s*\()/i.test(statements[0]) ? "REPLACE" : null);
  return word ? `“${word.toUpperCase()}” is not allowed: this console only reads data.` : null;
}

export interface SqlEditor { readonly value: string; setValue(text: string): void; focus(): void }

export function sqlEditor(parent: HTMLElement, options: {
  value: string; tables: Record<string, string[]>; onChange(text: string): void; onRun(): void;
}): SqlEditor {
  const view = new EditorView({
    parent,
    state: EditorState.create({
      doc: options.value,
      extensions: [
        lineNumbers(), history(), drawSelection(), indentOnInput(), bracketMatching(), closeBrackets(), highlightActiveLine(),
        autocompletion({ activateOnTyping: true }),
        sql({ dialect: SQLite, schema: namespace(options.tables), upperCaseKeywords: true }),
        syntaxHighlighting(highlight), look, EditorView.lineWrapping,
        placeholder("SELECT … FROM auth.events WHERE …"),
        Prec.highest(keymap.of([{ key: "Mod-Enter", run: () => { options.onRun(); return true; } }])),
        keymap.of([...closeBracketsKeymap, ...defaultKeymap, ...historyKeymap, ...completionKeymap, indentWithTab]),
        EditorView.updateListener.of((update) => { if (update.docChanged) options.onChange(update.state.doc.toString()); }),
        EditorView.contentAttributes.of({ "aria-label": "SQL query" }),
      ],
    }),
  });
  return {
    get value() { return view.state.doc.toString(); },
    setValue(text: string) { view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text } }); view.focus(); },
    focus() { view.focus(); },
  };
}
