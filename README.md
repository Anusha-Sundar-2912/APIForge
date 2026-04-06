🚀 APIForge — Automatic OpenAPI Generation from Code

Generate OpenAPI specifications, interactive documentation, and mock APIs directly from source code or GitHub repositories.

🌐 Live Demo: https://apiforge-vmin.onrender.com

✨ Overview

APIForge is an AI-powered developer tool that performs static code analysis to convert source code into structured API specifications. It extracts endpoints, parameters, and response structures across multiple languages and generates OpenAPI 3.0–compliant documentation automatically.

The system supports both single-file analysis and repository-level analysis, enabling developers to quickly understand and document APIs without manual effort.

🔥 Features
⚡ Code → OpenAPI Generation
Paste source code and generate API specifications instantly
Detects:
Functions and methods
Classes and controllers
REST endpoints
Parameters (path, query, body, headers)
Response structures

🌐 GitHub Repository Analysis
Accepts public GitHub repository URLs
Recursively scans source files
Filters relevant code files
Generates a consolidated OpenAPI specification

🧠 Supported Languages
🐍 Python (Flask, FastAPI, Django)
☕ Java (Spring Boot, Spring MVC)
🟨 JavaScript (Node.js, Express)
🔷 TypeScript
🐹 Go (Gin, Echo, net/http)
🟪 C# (ASP.NET Web API)
🐘 PHP
💎 Ruby

📄 Specification Output
OpenAPI 3.0 compliant
YAML and JSON formats
Includes:
Paths and operations
Parameters and request bodies
Response schemas
Security schemes

📚 Interactive Documentation
Swagger UI integration
Visual API exploration
Endpoint-level inspection

🧪 Mock API Playground
Simulate API responses
Test endpoints with authentication tokens

📊 Analytics
Tracks:
Generation count
Language distribution
Endpoint statistics

🧠 How It Works
<img width="2897" height="326" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/fe077b4d-3bbd-42fb-927e-c188eb39a590" />

🏗️ Tech Stack
Backend
Flask (Python)
Static Analysis Engine (AST + pattern-based parsing)
PyYAML (OpenAPI generation)
GitHub REST API
Frontend
HTML + TailwindCSS
JavaScript
Swagger UI

📂 Project Structure
APIForge/
├── app.py             # Backend (Flask + parsing engine)
├── index.html         # Frontend UI
├── requirements.txt   # Dependencies
├── Procfile           # Deployment config
└── .gitignore


⚙️ Installation
1. Clone Repository
git clone https://github.com/Anusha-Sundar-2912/APIForge.git
cd APIForge
2. Create Virtual Environment
python -m venv venv
venv\Scripts\activate
3. Install Dependencies
pip install -r requirements.txt
4. Configure Environment Variables
Create a .env file:
GITHUB_TOKEN=your_github_token
👉 Required for GitHub API access and higher rate limits
5. Run Application
python app.py

🔑 API Endpoints
Endpoint	Method	Description
/generate	POST	Generate OpenAPI from code
/generate-repo	POST	Generate from GitHub repository
/fetch-github	POST	Fetch repository contents
/summarize-repo	POST	Repository summary
/generate-otp	GET	Generate OTP
/validate-otp	POST	Validate OTP
/analytics	GET	Retrieve usage analytics

🧪 Example Workflow
Paste code or enter a GitHub repository URL
Generate specification
View OpenAPI output
Explore via Swagger documentation
Test using the mock API playground

🚀 Future Advancements
Improved Spring Boot and multi-layer Java parsing for deeper endpoint coverage
Enhanced request/response schema inference from complex code structures
Better handling of large repositories with optimized recursive analysis
Integration of AI-assisted parsing to improve endpoint detection accuracy
Export support for Postman collections and API clients
CI/CD integration for automated API documentation workflows
