# 🚀 APIForge — Automatic OpenAPI Generation from Code

A full-stack developer tool that converts **source code or GitHub repositories** into **OpenAPI specifications, interactive documentation, and mock APIs** using static code analysis across multiple languages.

---

## 🌐 Live Demo

https://apiforge-vmin.onrender.com  

---

## ✨ Features

### ⚡ Code → OpenAPI Generation
- Paste source code and generate API specifications instantly  
- Detects:
  - Functions and methods  
  - Classes and controllers  
  - REST endpoints  
  - Parameters (path, query, body, headers)  
  - Response structures  

---

### 🌐 GitHub Repository Analysis
- Accepts public GitHub repository URLs  
- Recursively scans source files  
- Filters relevant code files  
- Generates a consolidated OpenAPI specification  

---

### 📄 Specification Output
- OpenAPI 3.0 compliant  
- YAML and JSON formats  
- Includes:
  - Paths and operations  
  - Parameters and request bodies  
  - Response schemas  
  - Security schemes  

---

### 📚 Interactive Documentation
- Swagger UI integration  
- Visual API exploration  
- Endpoint-level inspection  

---

### 🧪 Mock API Playground
- Simulate API responses  
- Test endpoints with authentication tokens  

---

### 📊 Analytics
- Tracks:
  - Generation count  
  - Language distribution  
  - Endpoint statistics  

---

## 🧠 Supported Languages

- 🐍 Python (Flask, FastAPI, Django)  
- ☕ Java (Spring Boot, Spring MVC)  
- 🟨 JavaScript (Node.js, Express)  
- 🔷 TypeScript  
- 🐹 Go (Gin, Echo, net/http)  
- 🟪 C# (ASP.NET Web API)  
- 🐘 PHP  
- 💎 Ruby  

---

## 🧭 System Flow


<img width="2897" height="326" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/88d51fb1-a0fd-4d56-9bd0-0a9995ded621" />

---

## 🛠️ Tech Stack

### 🔧 Backend
- Python (Flask)  
- Static Analysis Engine (AST + pattern-based parsing)  
- PyYAML (OpenAPI generation)  
- GitHub REST API  

### 🎨 Frontend
- HTML  
- Tailwind CSS  
- JavaScript  
- Swagger UI  

---

## 📥 API Usage

### 🔹 Generate from Code  
`POST /generate`

```json
{
  "code": "your_source_code_here"
}
```

---

### 🔹 Generate from GitHub Repository  
`POST /generate-repo`

```json
{
  "repo_url": "https://github.com/user/repo"
}
```

---

### 🔹 Fetch Repository Contents  
`POST /fetch-github`

---

### 🔹 Analytics  
`GET /analytics`

---

## 📂 Project Structure

```
APIForge/
│
├── app.py              # Backend (Flask + parsing engine)
├── index.html          # Frontend UI
├── requirements.txt    # Dependencies
├── Procfile            # Deployment config
└── .gitignore
```

---

## ⚙️ Installation

1. Clone Repository  
```bash
git clone https://github.com/Anusha-Sundar-2912/APIForge.git
cd APIForge
```

2. Create Virtual Environment  
```bash
python -m venv venv
venv\Scripts\activate
```

3. Install Dependencies  
```bash
pip install -r requirements.txt
```

4. Configure Environment Variables  

Create a `.env` file:

```
GITHUB_TOKEN=your_github_token
```

👉 Required for GitHub API access and higher rate limits  

5. Run Application  
```bash
python app.py
```

---

## 🚀 Future Advancements

- Improved Spring Boot and multi-layer Java parsing  
- Enhanced schema inference from complex code structures  
- Better handling of large repositories  
- AI-assisted endpoint detection  
- Postman export support  
- CI/CD integration  

---

## ✔️ Highlights

- Multi-language static code analysis  
- GitHub repository-level API extraction  
- OpenAPI + Swagger integration  
- Mock API testing support  
- Real-world applicable developer tool  

---
