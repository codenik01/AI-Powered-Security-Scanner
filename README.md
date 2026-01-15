The AI-Powered Security Scanner is a security engineering tool designed to assist penetration testers and security teams in identifying high-impact, real-world vulnerabilities in modern web applications and APIs.

Instead of relying on noisy signature-based scans, this project focuses on:

Authorization flaws

Business logic weaknesses

Misconfigurations

Insecure API behavior

AI is used only where it adds value — to analyze responses, explain vulnerabilities, assess impact, and recommend fixes — while the core scanning logic remains deterministic and transparent.

This project is built as a learning-by-building security lab and as a portfolio-grade system suitable for advanced cybersecurity roles.

🏃‍♂️ Run Instructions
Install dependencies:
pip install -r requirements.txt
playwright install chromium



Set OpenAI key (optional for AI features):
export OPENAI_API_KEY="your-key-here"

Run the scanner:
uvicorn app:app --reload --host 0.0.0.0 --port 8000

Test the API:
curl -X POST "http://localhost:8000/api/scan/url" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://httpbin.org",
    "scan_type": "full",
    "max_depth": 2
  }'
