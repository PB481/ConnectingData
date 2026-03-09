# 📂 Project Viewer — Streamlit App

A password-protected Streamlit app that lets you browse, read, and copy your project code from any browser — no git access needed.

## 🚀 Quick Start

### 1. Clone & add your projects

```
my-work-tools/
├── app.py                ← Streamlit viewer (don't touch)
├── requirements.txt
├── projects/
│   ├── my_project_a/
│   │   ├── README.md
│   │   ├── app.py
│   │   └── utils.py
│   └── my_project_b/
│       ├── README.md
│       └── main.py
└── .streamlit/
    └── secrets.toml      ← (optional) for secure password
```

### 2. Set your password

Open `app.py` and change:

```python
APP_PASSWORD = "changeme"  # ← set your own password
```

**Or better**, use Streamlit secrets (see Security section below).

### 3. Deploy to Streamlit Community Cloud

1. Push this repo to a **public** GitHub repo
1. Go to [share.streamlit.io](https://share.streamlit.io)
1. Click **New app** → select your repo → set `app.py` as the main file
1. Deploy!

### 4. Use at work

Open the Streamlit URL in your work browser, enter your password, browse your projects, and copy code using the built-in copy buttons.

## 📋 Workflow

```
Home                          Work
─────                         ────
Write code                    Open Streamlit app URL
  ↓                             ↓
Push to GitHub              Enter password
  ↓                             ↓
Auto-deploys to Streamlit   Browse projects
                                ↓
                            Copy/paste or download ZIP
```

## 🔐 Security

The repo is public, but the app is password-gated. For better security:

### Option A: Streamlit Secrets (Recommended)

1. Create `.streamlit/secrets.toml` locally (don’t commit it):
   
   ```toml
   password = "your-secure-password"
   ```
1. In Streamlit Cloud, go to **App Settings → Secrets** and add:
   
   ```toml
   password = "your-secure-password"
   ```
1. Update `app.py` to use:
   
   ```python
   APP_PASSWORD = st.secrets["password"]
   ```

### Option B: Environment Variable

Set `APP_PASSWORD` as an environment variable in Streamlit Cloud settings.

## ⚠️ Important Notes

- The GitHub repo **must be public** for Streamlit Community Cloud (free tier)
- Don’t put truly sensitive code (API keys, credentials) in the repo
- The password gate prevents casual browsing but the repo itself is public
- Use `.gitignore` to exclude sensitive files

## 🛠 Adding a New Project

1. Create a folder in `projects/`
1. Add a `README.md` and your code files
1. Commit & push
1. The app auto-discovers it — no config changes needed

## 📁 Supported File Types

Python, JavaScript, TypeScript, HTML, CSS, JSON, YAML, TOML, SQL, Shell scripts, Go, Rust, Java, C/C++, R, Dockerfiles, Makefiles, and more.