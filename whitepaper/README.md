# Technical whitepaper

| File | What it is |
|---|---|
| [TECHNICAL_WHITEPAPER.typ](TECHNICAL_WHITEPAPER.typ) | The primary editable Typst core, with chapter breaks, tables and a native workflow diagram. |
| [TECHNICAL_WHITEPAPER_APPENDICES.typ](TECHNICAL_WHITEPAPER_APPENDICES.typ) | The independently compiled Typst companion, preserving detailed tables, formulas, screenshots and catalogues. |
| [typst-style.typ](typst-style.typ) | Shared page layout, typography and figure helpers; keep beside both documents. |
| [TECHNICAL_WHITEPAPER.pdf](TECHNICAL_WHITEPAPER.pdf) and [appendix PDF](TECHNICAL_WHITEPAPER_APPENDICES.pdf) | Compiled PDFs from the Typst editions. |
| [TECHNICAL_WHITEPAPER.tex](TECHNICAL_WHITEPAPER.tex) and [LaTeX appendices](TECHNICAL_WHITEPAPER_APPENDICES.tex) | Preserved LaTeX sources from before conversion. |
| [TECHNICAL_WHITEPAPER.md](TECHNICAL_WHITEPAPER.md) | A Markdown edition for reading in the repository. |
| [WHITEPAPER_CONTENT_REVIEW.md](WHITEPAPER_CONTENT_REVIEW.md) | Review notes on the content. |
| [figures/](figures/) | The user-guide screenshots the appendices include. |
| [colab/](colab/) | Compile both PDFs directly from a runtime or mounted Drive directory: the notebook and [instructions](colab/README.md). |

**In this workspace (26 October 2026)** only the LaTeX sources, `typst-style.typ` and `figures/` are present, and the
LaTeX sources are the newest edition: they describe Sigma, the redesigned Dashboard, the SQL password, the security of
the local service and the event-log parser in progress. Not yet in the paper (work of 27–30 October 2026): Phase 4g's activity alerts and incidents, Explain, Phase 4h and Profiles, names no longer used as features, and the pipeline's console output standard (`pipeline/STYLE_GUIDE.md`). Regenerate the Typst editions and PDFs from them before
relying on those.

After editing the `.typ` files, style or figures, sync them to the directory selected in Colab and rerun compilation. The notebook installs the `typst` Python package; no separate compiler application is required.

To compile locally using Python, run from the project folder:

```powershell
python -m pip install typst==0.15.0
python scripts/compile_whitepaper_typst.py
```

The documents use native Typst and the supplied figures, without external Typst packages. You can also open the two entry points in the Typst web editor with the style file and `figures/` directory beside them.

To regenerate the notebook after changing its generator, run this from the project folder:

```powershell
.\.venv\Scripts\python.exe scripts\create_colab_whitepaper_notebook.py
```
