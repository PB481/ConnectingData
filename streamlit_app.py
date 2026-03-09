import streamlit as st
import zipfile
import io
from pathlib import Path

# ─────────────────────────────────────────────
# CONFIG & CONSTANTS
# ─────────────────────────────────────────────

PROJECTS_DIR = Path("projects")
APP_TITLE = "📂 Project Viewer"
APP_PASSWORD = st.secrets.get("password", "helloworld")

LANG_MAP = {
    ".py": "python", ".js": "javascript", ".jsx": "jsx", ".ts": "typescript",
    ".tsx": "tsx", ".html": "html", ".css": "css", ".json": "json",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".sh": "bash",
    ".sql": "sql", ".rs": "rust", ".go": "go", ".java": "java",
    ".c": "c", ".cpp": "cpp", ".md": "markdown", ".txt": "text"
}

IGNORE = {".git", "__pycache__", ".DS_Store", "node_modules", ".venv", "venv", ".streamlit"}

# ─────────────────────────────────────────────
# PAGE SETUP
# ─────────────────────────────────────────────

st.set_page_config(page_title="Project Viewer", page_icon="📂", layout="wide")

st.markdown("""
    <style>
        .block-container { padding-top: 2rem; }
        .stTabs [data-baseweb="tab"] { font-family: monospace; font-size: 0.85rem; }
    </style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def check_password():
    """Returns True if the user had the correct password."""
    if st.session_state.get("authenticated"):
        return True

    st.title("🔒 Access Restricted")
    pwd = st.text_input("Enter Password", type="password")
    if st.button("Login"):
        if pwd == APP_PASSWORD:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("Invalid password")
    return False

def get_project_files(project_path: Path):
    """Yields valid files for display using pathlib."""
    for path in sorted(project_path.rglob("*")):
        if any(part in IGNORE or part.startswith(".") for part in path.parts):
            if path.name != ".env.example": continue
        
        if path.is_file() and (path.suffix in LANG_MAP or path.name in ["Dockerfile", "Makefile"]):
            yield path

def create_zip(project_path: Path):
    """Generates an in-memory ZIP file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in project_path.rglob("*"):
            if not any(part in IGNORE for part in file.parts):
                zf.write(file, file.relative_to(project_path.parent))
    return buf.getvalue()

# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────

def main():
    if not check_password():
        return

    # Ensure directory exists
    PROJECTS_DIR.mkdir(exist_ok=True)
    
    projects = [p for p in PROJECTS_DIR.iterdir() if p.is_dir() and p.name not in IGNORE]

    with st.sidebar:
        st.title(APP_TITLE)
        if not projects:
            st.info(f"Empty directory: `{PROJECTS_DIR}/`")
            return

        selected_project_path = st.radio("Select Project", projects, format_func=lambda x: x.name)
        
        st.divider()
        st.download_button(
            "⬇️ Download ZIP", 
            data=create_zip(selected_project_path),
            file_name=f"{selected_project_path.name}.zip",
            use_container_width=True
        )
        
        if st.button("Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.rerun()

    # Main Content Area
    st.header(f"📁 Project: {selected_project_path.name}")
    
    # Render README if exists
    readme = selected_project_path / "README.md"
    if readme.exists():
        with st.expander("📖 README.md", expanded=True):
            st.markdown(readme.read_text(errors="ignore"))

    # File Viewer
    files = list(get_project_files(selected_project_path))
    if files:
        # Filter out README from tabs to avoid duplication
        display_files = [f for f in files if f.name.lower() != "readme.md"]
        tabs = st.tabs([f.name for f in display_files])
        
        for tab, file_path in zip(tabs, display_files):
            with tab:
                content = file_path.read_text(errors="replace")
                st.caption(f"Path: `{file_path.relative_to(selected_project_path)}`")
                lang = LANG_MAP.get(file_path.suffix, "python" if "Dockerfile" in file_path.name else "text")
                st.code(content, language=lang, line_numbers=True)
    else:
        st.write("No source files found.")

if __name__ == "__main__":
    main()