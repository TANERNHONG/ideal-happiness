"""Create a directory-based Typst whitepaper notebook using Python's standard library.

Writes the notebook to whitepaper/colab/. In Colab, SOURCE_DIRECTORY points directly to
the existing .typ files, typst-style.typ and figures/ in the runtime or Google Drive.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAPER = ROOT / 'whitepaper'
DEST = PAPER / 'colab'


def markdown(text):
    return {'cell_type': 'markdown', 'metadata': {}, 'source': textwrap.dedent(text).strip() + '\n'}


def code(text):
    return {'cell_type': 'code', 'execution_count': None, 'metadata': {}, 'outputs': [],
            'source': textwrap.dedent(text).strip() + '\n'}


cells = [
    markdown('''
    # Compile the Project DAD Typst whitepaper in Google Colab

    This notebook installs **the Typst Python package inside the temporary Colab runtime**, compiles the core whitepaper and its companion appendix, and downloads the PDFs with their build logs. It uses `pip` only; your laptop does not need a typesetting application.

    1. Import this `.ipynb` through **Colab > File > Upload notebook**.
    2. Use a standard **CPU runtime**. Set `SOURCE_DIRECTORY` to the folder containing your two `.typ` files, `typst-style.typ`, and `figures/`.
    3. Run the cells in order. If the folder is in Google Drive, keep `MOUNT_GOOGLE_DRIVE = True` and authorise the mount when prompted.
    4. The last cell downloads a results ZIP with both PDFs and diagnostics.

    The notebook reads the existing files directly; source edits are picked up by the next compile. Hosted Colab can access its `/content/` folders and mounted Drive folders, but it cannot directly open a laptop path such as `C:\\Users\\...`. Put the whitepaper folder in Drive or the runtime filesystem first.

    The initial package installation needs internet access. Compilation uses the installed package without downloading LaTeX support files. Colab runtime files are temporary: download the results before the session ends. Each compilation uses fresh output folders while leaving the source directory unchanged.
    '''),
    markdown('''
    ## 1. Runtime and settings

    Edit `SOURCE_DIRECTORY` below to match your folder. The example uses Google Drive; for a runtime folder such as `/content/whitepaper`, set `MOUNT_GOOGLE_DRIVE = False`. To compile the core only, set `COMPILE_APPENDIX = False`.
    '''),
    code('''
    import json
    import re
    import subprocess
    import sys
    import time
    import traceback
    import uuid
    import zipfile
    from importlib import metadata
    from pathlib import Path, PureWindowsPath

    try:
        from google.colab import files
    except ImportError as exc:
        raise RuntimeError("Open this notebook in Google Colab and connect a hosted runtime.") from exc

    TYPST_VERSION = "0.15.0"
    SOURCE_DIRECTORY = "/content/drive/MyDrive/Project-Huh/whitepaper"
    MOUNT_GOOGLE_DRIVE = True
    COMPILE_APPENDIX = True
    WORK_ROOT = Path("/content/project_dad_whitepaper")
    DOCUMENTS = ["TECHNICAL_WHITEPAPER.typ"]
    if COMPILE_APPENDIX:
        DOCUMENTS.append("TECHNICAL_WHITEPAPER_APPENDICES.typ")
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    PROJECT_DIR = None
    OUTPUT_DIR = None
    BUILD_RESULTS = []
    print("Documents:", ", ".join(DOCUMENTS))
    print("Source directory:", SOURCE_DIRECTORY)
    print("Working folder:", WORK_ROOT)
    '''),
    markdown('''
    ## 2. Install the Typst Python package in Colab

    This cell installs the pinned `typst==0.15.0` package from PyPI using the runtime's Python interpreter. The package includes the compiler, so there is no separate executable or LaTeX installation. An already installed matching package is reused.
    '''),
    code('''
    def install_typst():
        try:
            installed_version = metadata.version("typst")
        except metadata.PackageNotFoundError:
            installed_version = None
        if installed_version != TYPST_VERSION:
            print(f"Installing typst=={TYPST_VERSION} in the Colab runtime...", flush=True)
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--quiet", f"typst=={TYPST_VERSION}"],
                    check=True, timeout=600,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                raise RuntimeError("Could not install Typst. Check Colab internet access and rerun this cell.") from exc
        installed_version = metadata.version("typst")
        if installed_version != TYPST_VERSION:
            raise RuntimeError(f"Unexpected Typst package version {installed_version}; expected {TYPST_VERSION}.")
        import typst
        (WORK_ROOT / "compiler_install.json").write_text(json.dumps({
            "package": "typst", "version": installed_version,
            "installer": "python -m pip", "source": "https://pypi.org/project/typst/",
        }, indent=2), encoding="utf-8")
        print("Ready: Typst Python package", installed_version)
        return typst


    typst = install_typst()
    '''),
    markdown('''
    ## 3. Read the source directory

    `SOURCE_DIRECTORY` must point to the folder with this layout:

    ```text
    TECHNICAL_WHITEPAPER.typ
    TECHNICAL_WHITEPAPER_APPENDICES.typ
    typst-style.typ
    figures/
        analyze.jpg
        ... the other referenced figures ...
    ```

    This cell optionally mounts Google Drive, checks the selected documents, shared style file and referenced figures, and sets the compiler's source directory. It does not copy or unpack the sources. File checks are repeated before every compilation, so edits do not require rebuilding a package.
    '''),
    code(r'''
    def validate_source_directory(source_dir, documents):
        if PureWindowsPath(str(source_dir)).drive:
            raise ValueError("Hosted Colab cannot read a laptop Windows path. Use a /content/ or mounted Drive folder.")
        project = Path(source_dir).expanduser().resolve()
        if not project.is_dir():
            raise FileNotFoundError(f"Source directory not found: {project}. Check SOURCE_DIRECTORY and the Drive mount.")
        source_files = list(documents) + ["typst-style.typ"]
        missing_sources = [name for name in source_files if not (project / name).is_file()]
        if missing_sources:
            raise FileNotFoundError("Missing source files: " + ", ".join(missing_sources)
                                    + ". Point SOURCE_DIRECTORY to the folder containing the .typ files.")
        missing = []
        for name in source_files:
            text = (project / name).read_text(encoding="utf-8")
            # Direct image paths and screenshot helper filenames use literal strings.
            image_paths = re.findall(r'\bimage\s*\(\s*"([^"]+)"\s*(?=[,)])', text)
            screenshot_names = re.findall(r'\bscreenshot\s*\(\s*"([^"]+)"\s*(?=[,)])', text)
            references = image_paths + ["figures/" + filename for filename in screenshot_names]
            for reference in references:
                path = (project / reference).resolve()
                if not path.is_relative_to(project):
                    raise ValueError(f"Figure path must remain inside SOURCE_DIRECTORY: {reference}")
                if not path.is_file():
                    missing.append(reference)
        if missing:
            raise ValueError("Missing figures: " + ", ".join(sorted(set(missing))))
        return project


    PROJECT_DIR = None
    OUTPUT_DIR = None
    BUILD_RESULTS = []
    if MOUNT_GOOGLE_DRIVE:
        from google.colab import drive
        drive.mount("/content/drive")
    PROJECT_DIR = validate_source_directory(SOURCE_DIRECTORY, DOCUMENTS)
    JOB_DIR = WORK_ROOT / "jobs" / uuid.uuid4().hex[:12]
    JOB_DIR.mkdir(parents=True)
    print("Reading directly from:", PROJECT_DIR)
    print("Source files validated:", ", ".join(DOCUMENTS), "and typst-style.typ")
    print("Job folder:", JOB_DIR)
    '''),
    markdown('''
    ## 4. Compile both documents

    Typst compiles each document through its Python API, resolving figures and imports inside `SOURCE_DIRECTORY`. Each document has its own fresh output folder. A failed document does not stop the other one from building.

    The results retain one log per document with the compilation status or exception diagnostics. A successful build confirms PDF generation; review the downloaded PDF to assess page layout and typography.
    '''),
    code(r'''
    if PROJECT_DIR is None or not PROJECT_DIR.is_dir():
        raise RuntimeError("Run the source-directory cell successfully before compiling.")
    PROJECT_DIR = validate_source_directory(SOURCE_DIRECTORY, DOCUMENTS)
    BUILD_RESULTS = []

    def compile_document(source_name):
        stem = Path(source_name).stem
        output = OUTPUT_DIR / stem
        output.mkdir(parents=True, exist_ok=True)
        pdf = output / f"{stem}.pdf"
        started = time.monotonic()
        error = None
        success = False
        log_lines = [f"Document: {source_name}", f"Typst Python package: {TYPST_VERSION}",
                     f"Source directory: {PROJECT_DIR}"]
        print(f"Compiling {source_name}...", flush=True)
        try:
            typst.compile(str(PROJECT_DIR / source_name), output=str(pdf), root=str(PROJECT_DIR))
            valid_pdf = False
            if pdf.is_file() and pdf.stat().st_size > 5:
                with pdf.open("rb") as stream:
                    valid_pdf = stream.read(5) == b"%PDF-"
            if not valid_pdf:
                raise RuntimeError("Compiler returned without producing a valid PDF.")
            success = True
            log_lines.append(f"PDF generated successfully: {pdf.name} ({pdf.stat().st_size} bytes)")
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            log_lines.append("Compilation failed:\n" + traceback.format_exc())
            # Typst's source locations and contextual details are separate exception attributes.
            for attribute, heading in (("diagnostic", "Typst diagnostic"),
                                       ("hints", "Typst hints"), ("trace", "Typst trace")):
                details = getattr(exc, attribute, None)
                if details:
                    rendered = "\n".join(str(item) for item in details) if isinstance(details, (list, tuple)) else str(details)
                    log_lines.append(f"{heading}:\n{rendered}")
            if pdf.exists():
                pdf.unlink()
        duration = round(time.monotonic() - started, 2)
        log_lines.append(f"Elapsed seconds: {duration}")
        (output / f"{stem}.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        result = {"document": source_name, "success": success, "error": error,
                  "pdf": str(pdf.relative_to(OUTPUT_DIR)) if success else None,
                  "pdf_bytes": pdf.stat().st_size if success else None,
                  "elapsed_seconds": duration}
        if success:
            print(f"  PDF ready ({pdf.stat().st_size / 1024:.0f} KB, {duration:.2f} seconds).")
        else:
            print("  Build failed. The results ZIP will retain the diagnostics.")
            print(error)
        return result


    # Every compile-cell run gets fresh PDFs and logs; earlier outputs cannot be reused.
    OUTPUT_DIR = JOB_DIR / ("build_" + uuid.uuid4().hex[:8])
    OUTPUT_DIR.mkdir()
    BUILD_RESULTS = [compile_document(name) for name in DOCUMENTS]
    summary = {"typst_version": TYPST_VERSION, "source_directory": str(PROJECT_DIR),
               "documents": BUILD_RESULTS}
    (OUTPUT_DIR / "build_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Finished: {sum(r['success'] for r in BUILD_RESULTS)}/{len(BUILD_RESULTS)} PDFs compiled.")
    '''),
    markdown('''
    ## 5. Download the results

    The ZIP contains successfully compiled PDFs, per-document logs and a build summary. If a document failed, its diagnostics are still included. Extract the downloaded ZIP to open the individual PDFs.
    '''),
    code('''
    if not BUILD_RESULTS or OUTPUT_DIR is None:
        raise RuntimeError("Run the compile cell before downloading results.")

    RESULT_ZIP = JOB_DIR / "Project_DAD_Whitepaper_Results.zip"
    with zipfile.ZipFile(RESULT_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in sorted(OUTPUT_DIR.rglob("*")):
            if item.is_file():
                archive.write(item, item.relative_to(OUTPUT_DIR).as_posix())
        install_record = WORK_ROOT / "compiler_install.json"
        if install_record.is_file():
            archive.write(install_record, "compiler_install.json")
    for result in BUILD_RESULTS:
        if result["success"]:
            print("Included PDF:", result["pdf"])
    print("Downloading PDFs and diagnostics:", RESULT_ZIP.name)
    files.download(str(RESULT_ZIP))
    '''),
    markdown('''
    ## Troubleshooting and future updates

    - **Package installation fails:** check that the Colab runtime has internet access and rerun the installation cell. No laptop installation is required.
    - **Missing figure or style file:** include `typst-style.typ` and the named image under `figures/` next to the documents.
    - **Directory not found:** check `SOURCE_DIRECTORY` and confirm that Google Drive is mounted if your path starts with `/content/drive/`. Hosted Colab cannot read a laptop's `C:` drive directly.
    - **Typst error:** inspect the relevant `.log` in the results ZIP. Edit the source in the selected directory and rerun compilation. If you change the directory, rerun the settings and source-directory cells first.
    - **Updated local files:** sync the edited whitepaper folder to Drive or refresh the runtime files. The next compilation reads those files directly.
    - **Download prompt does not appear:** find the results ZIP in Colab's left-side Files panel, then use its download menu.

    References: [Typst Python package](https://pypi.org/project/typst/0.15.0/), [Python API and examples](https://github.com/messense/typst-py), [Typst documentation](https://typst.app/docs/), [Colab file access examples](https://colab.research.google.com/notebooks/io.ipynb).

    The notebook was generated and its Python cells checked locally. Run installation and compilation in your Colab session; this notebook has not been executed against your Google account.
    '''),
]


def build_artifacts():
    DEST.mkdir(parents=True, exist_ok=True)
    notebook = {'nbformat': 4, 'nbformat_minor': 5,
                'metadata': {'colab': {'name': 'Project_DAD_Whitepaper_Colab.ipynb', 'provenance': []},
                             'kernelspec': {'display_name': 'Python 3', 'language': 'python', 'name': 'python3'},
                             'language_info': {'name': 'python', 'version': '3.12'}},
                'cells': cells}
    for index, cell in enumerate(notebook['cells']):
        cell['id'] = f'dad-{index:02d}'
        if cell['cell_type'] == 'code':
            compile(cell['source'], f'cell-{index}', 'exec')
    notebook_path = DEST / 'Project_DAD_Whitepaper_Colab.ipynb'
    notebook_path.write_text(json.dumps(notebook, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

    print(f'Created {notebook_path.relative_to(ROOT)} ({len(cells)} cells)')


if __name__ == '__main__':
    build_artifacts()
