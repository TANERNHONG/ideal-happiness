// Shared native Typst style for the core whitepaper and companion appendices.
// Keep this file beside both entry-point documents and the figures/ directory.
#let ink = rgb("183348")
#let accent = rgb("236578")
#let pale = rgb("edf3f6")
#let reviewred = rgb("b42318")

#let whitepaper(body, appendix: false) = {
  set document(
    title: if appendix { "Project DAD Console — Technical Whitepaper Appendices" }
      else { "Project DAD Console — Technical Whitepaper" },
    author: "Project DAD",
  )
  set page(
    paper: "a4",
    margin: (x: 24mm, y: 24mm),
    header: text(size: 9pt, fill: ink)[Project DAD Console #h(1fr)
      #if appendix [Technical whitepaper: appendices] else [Technical whitepaper]],
    footer: context align(center, text(size: 9pt, counter(page).display("1"))),
  )
  set text(font: "Libertinus Serif", size: 11pt, lang: "en", fill: ink)
  set par(justify: true, leading: 0.65em, spacing: 0.6em)
  set heading(numbering: if appendix { "A.1.1." } else { "1.1.1." })
  show heading.where(level: 1): set text(size: 17pt, weight: "bold", fill: ink)
  show heading.where(level: 2): set text(size: 13pt, weight: "bold", fill: ink)
  show heading.where(level: 3): set text(size: 11pt, weight: "bold", fill: accent)
  show link: set text(fill: accent)
  show raw.where(block: false): it => text(
    font: "DejaVu Sans Mono", size: 0.85em,
    it.text.replace("_", "_\u{200b}").replace("/", "/\u{200b}")
      .replace("\\", "\\\u{200b}").replace("-", "-\u{200b}"),
  )
  set math.equation(numbering: "(1)")
  set table(inset: 5pt, stroke: 0.35pt + rgb("c8d5dc"))
  show table.cell.where(y: 0): set text(weight: "bold")
  set figure(gap: 8pt)
  show figure.caption: set text(size: 9pt)
  body
}

#let cover(appendix: false) = {
  set page(header: none, footer: none)
  set par(justify: false)
  set text(hyphenate: false)
  v(18mm)
  text(size: 10pt, fill: accent, weight: "bold")[
    #if appendix [TECHNICAL WHITEPAPER: APPENDICES] else [TECHNICAL WHITEPAPER]
  ]
  v(18mm)
  text(size: 34pt, weight: "bold", fill: ink)[Project DAD]
  v(4mm)
  text(size: 19pt, weight: "bold", fill: ink)[(Data Anomaly Detection) Console]
  v(12mm)
  text(size: 23pt, weight: "bold", fill: ink)[
    #if appendix [Appendices to\ ]
    Building an In-House Capability for Log-Based Cybersecurity Monitoring and Detection Engineering
  ]
  v(12mm)
  text(size: 12pt)[12 October 2026]
  v(18mm)
  if appendix [
    This companion preserves detailed methods, evidence, user instructions and historical results.
    Appendices A–F contain the evidence register and catalogues; G–L contain detail migrated from the extended paper.
    Cross-references resolve within this companion unless explicitly identified as references to the core paper.
  ] else [
    *Implementation baseline:* application release 0.2.0 plus the current workspace inspected on 12 October 2026,
    including sequential pattern mining, pattern discovery, user whitelisting and frozen-runtime operation.
    Whitelisting is implemented in the current source; it is not a new numbered release.
  ]
  v(1fr)
  text(size: 9pt)[Repository paths identify supporting evidence. The companion screenshots are in #raw("figures/").]
  pagebreak()
}

#let tok(value) = raw(value)
#let projectref(title, path) = [#title #text(size: 8.5pt)[(#raw(path))]]
#let screenshot(filename, width, caption) = figure(
  image("figures/" + filename, width: width),
  caption: caption,
)

#let stepbox(body) = block(
  width: 100%, inset: 7pt, fill: pale, stroke: accent, radius: 3pt,
  align(center, body),
)
