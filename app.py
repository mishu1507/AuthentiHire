"""
app.py - Flask Backend for JobSentinel (AI-Powered)
=====================================================
Provides a REST API that accepts job/internship posting text OR file uploads,
runs them through both the rule-based detector AND Gemini AI detector,
and returns a combined risk assessment.

Routes
------
GET  /          → Serves the frontend (index.html)
POST /analyze   → Accepts JSON {"text": "..."} or multipart file upload
GET  /api/status → Health check endpoint
"""

import os
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime

# Import detection modules
from detector import analyze_text
from ai_detector import analyze_with_ai, analyze_image_with_ai, compute_combined_score

# ---------------------------------------------------------------------------
# 1. APP INITIALISATION
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Set the Gemini API key from environment or hardcode for development
# In production, always use environment variables!
if not os.environ.get("GEMINI_API_KEY"):
    os.environ["GEMINI_API_KEY"] = "AIzaSyCLOEIDDhN8rizZSwIx4LEF95L5GlgwBGU"

# Configure upload settings
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB max upload
ALLOWED_EXTENSIONS = {".txt", ".docx", ".pdf", ".eml", ".doc"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}
IMAGE_MIME_MAP = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


# ---------------------------------------------------------------------------
# 2. FILE PARSING UTILITIES
# ---------------------------------------------------------------------------

def extract_text_from_file(file_storage) -> str:
    """
    Extract text content from an uploaded file.

    Supports: .txt, .eml, .docx, .pdf
    """
    filename = file_storage.filename.lower()
    ext = os.path.splitext(filename)[1]

    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {ext}. Supported: {', '.join(ALLOWED_EXTENSIONS)}")

    if ext in (".txt", ".eml"):
        # Plain text or email file — read directly
        try:
            content = file_storage.read().decode("utf-8")
        except UnicodeDecodeError:
            content = file_storage.read().decode("latin-1")
        return content

    elif ext in (".docx", ".doc"):
        # Word document — use python-docx
        try:
            import docx
            doc = docx.Document(file_storage)
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            return "\n".join(paragraphs)
        except Exception as e:
            raise ValueError(f"Failed to read .docx file: {str(e)}")

    elif ext == ".pdf":
        # PDF document — use PyPDF2
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(file_storage)
            text_parts = []
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            return "\n".join(text_parts)
        except Exception as e:
            raise ValueError(f"Failed to read PDF file: {str(e)}")

    raise ValueError(f"Unsupported file type: {ext}")


# ---------------------------------------------------------------------------
# 3. ROUTES
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Serve the main frontend page."""
    print(f"[{datetime.now()}] GET / — serving index.html")
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyse a job posting for scam indicators using both rule-based
    and AI detection.

    Accepts:
    - JSON body: { "text": "<job posting text>" }
    - Multipart form: file upload + optional "text" field

    Returns:
    - Combined analysis with rule-based, AI, and final scores.
    """

    print(f"\n{'=' * 60}")
    print(f"[{datetime.now()}] POST /analyze — analysis request received")

    text = ""
    is_image = False
    image_bytes = None
    image_mime = None

    # --- Determine input type (JSON vs file upload) ---
    content_type = request.content_type or ""

    if "multipart/form-data" in content_type:
        # File upload
        uploaded_file = request.files.get("file")
        form_text = request.form.get("text", "").strip()

        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename.lower()
            ext = os.path.splitext(filename)[1]

            if ext in IMAGE_EXTENSIONS:
                # IMAGE UPLOAD — use Gemini Vision
                is_image = True
                image_bytes = uploaded_file.read()
                image_mime = IMAGE_MIME_MAP.get(ext, "image/png")
                print(f"[INFO] Image upload: {uploaded_file.filename} ({image_mime}, {len(image_bytes)} bytes)")
            elif ext in ALLOWED_EXTENSIONS:
                # DOCUMENT UPLOAD — extract text
                try:
                    print(f"[INFO] File upload: {uploaded_file.filename}")
                    text = extract_text_from_file(uploaded_file)
                    print(f"[INFO] Extracted {len(text)} chars from file")
                except ValueError as e:
                    print(f"[ERROR] File parsing failed: {e}")
                    return jsonify({"error": str(e)}), 400
            else:
                return jsonify({"error": f"Unsupported file type: {ext}. Supported: .docx, .pdf, .txt, .eml, .png, .jpg, .jpeg"}), 400
        elif form_text:
            text = form_text
        else:
            return jsonify({"error": "No file or text provided."}), 400

    else:
        # JSON body
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "Invalid JSON in request body."}), 400
        text = data.get("text", "").strip()

    if not text and not is_image:
        return jsonify({"error": "'text' field is required and cannot be empty."}), 400

    # --- IMAGE ANALYSIS PATH ---
    if is_image:
        print(f"[INFO] Running AI Vision analysis on image...")
        ai_result = analyze_image_with_ai(image_bytes, image_mime)

        if ai_result.get("ai_available"):
            print(f"[AI-VISION] Score: {ai_result['ai_score']} | Risk: {ai_result['ai_risk_level']}")
            print(f"[AI-VISION] Confidence: {ai_result['ai_confidence']}%")

            # Run the extracted text through rule-based detector too
            extracted_text = ai_result.get("extracted_text", "")
            if extracted_text:
                rule_result = analyze_text(extracted_text)
                print(f"[RULES-FROM-IMAGE] Score: {rule_result['score']} | Flags: {len(rule_result['flags'])}")
            else:
                rule_result = {"score": 0, "risk_level": "LOW", "flags": [], "highlighted_phrases": [], "recommendation": "", "total_checked": 0}

            combined = compute_combined_score(rule_result["score"], ai_result)
        else:
            print(f"[AI-VISION] Unavailable: {ai_result['ai_reasoning']}")
            return jsonify({
                "error": "AI Vision is required for image analysis but is unavailable. " + ai_result.get("ai_reasoning", "Please check your API key.")
            }), 503

        final_score = combined["final_score"]
        if final_score <= 30:
            recommendation = "This offer appears relatively safe. Always verify the company on LinkedIn and their official website before proceeding."
        elif final_score <= 60:
            recommendation = "Proceed with caution. Multiple suspicious patterns detected. Research this company thoroughly and never pay any fees to get a job."
        else:
            recommendation = "HIGH SCAM RISK DETECTED. Do NOT share personal information, do NOT send any money, do NOT click any links. Report this to cybercrime.gov.in or your institution's placement cell."

        response = {
            "score": combined["final_score"],
            "risk_level": combined["final_risk_level"],
            "recommendation": recommendation,
            "rule_score": rule_result["score"],
            "rule_risk_level": rule_result["risk_level"],
            "flags": rule_result["flags"],
            "highlighted_phrases": rule_result["highlighted_phrases"],
            "ai_available": True,
            "ai_score": ai_result.get("ai_score"),
            "ai_risk_level": ai_result.get("ai_risk_level"),
            "ai_confidence": ai_result.get("ai_confidence", 0),
            "ai_flags": ai_result.get("ai_flags", []),
            "ai_positive_signals": ai_result.get("ai_positive_signals", []),
            "ai_reasoning": ai_result.get("ai_reasoning", ""),
            "scam_type": ai_result.get("scam_type", "unknown"),
            "scoring_source": combined["scoring_source"],
            "is_image_analysis": True,
            "extracted_text": ai_result.get("extracted_text", ""),
        }
        print(f"{'=' * 60}\n")
        return jsonify(response), 200

    # --- TEXT ANALYSIS PATH (existing) ---

    # --- Run rule-based detector ---
    print(f"[INFO] Text length: {len(text)} characters")
    rule_result = analyze_text(text)
    print(f"[RULES] Score: {rule_result['score']} | Risk: {rule_result['risk_level']}")
    print(f"[RULES] Flags: {len(rule_result['flags'])}")

    # --- Run AI detector ---
    print(f"[INFO] Running AI analysis...")
    ai_result = analyze_with_ai(text)

    if ai_result.get("ai_available"):
        print(f"[AI] Score: {ai_result['ai_score']} | Risk: {ai_result['ai_risk_level']}")
        print(f"[AI] Confidence: {ai_result['ai_confidence']}%")
        print(f"[AI] Scam Type: {ai_result['scam_type']}")
        print(f"[AI] Flags: {len(ai_result['ai_flags'])}")
    else:
        print(f"[AI] Unavailable: {ai_result['ai_reasoning']}")

    # --- Compute combined score ---
    combined = compute_combined_score(rule_result["score"], ai_result)
    print(f"[COMBINED] Final Score: {combined['final_score']} | Risk: {combined['final_risk_level']}")
    print(f"[COMBINED] Source: {combined['scoring_source']}")

    # --- Generate final recommendation ---
    final_score = combined["final_score"]
    if final_score <= 30:
        recommendation = (
            "This offer appears relatively safe. Always verify the company "
            "on LinkedIn and their official website before proceeding."
        )
    elif final_score <= 60:
        recommendation = (
            "Proceed with caution. Multiple suspicious patterns detected. "
            "Research this company thoroughly, check reviews on Glassdoor, "
            "and never pay any fees to get a job."
        )
    else:
        recommendation = (
            "HIGH SCAM RISK DETECTED. Do NOT share personal information, "
            "do NOT send any money, do NOT click any links. Report this to "
            "cybercrime.gov.in or your institution's placement cell."
        )

    print(f"{'=' * 60}\n")

    # --- Build response ---
    response = {
        # Combined / final results
        "score": combined["final_score"],
        "risk_level": combined["final_risk_level"],
        "recommendation": recommendation,

        # Rule-based details
        "rule_score": rule_result["score"],
        "rule_risk_level": rule_result["risk_level"],
        "flags": rule_result["flags"],
        "highlighted_phrases": rule_result["highlighted_phrases"],

        # AI details
        "ai_available": ai_result.get("ai_available", False),
        "ai_score": ai_result.get("ai_score"),
        "ai_risk_level": ai_result.get("ai_risk_level"),
        "ai_confidence": ai_result.get("ai_confidence", 0),
        "ai_flags": ai_result.get("ai_flags", []),
        "ai_positive_signals": ai_result.get("ai_positive_signals", []),
        "ai_reasoning": ai_result.get("ai_reasoning", ""),
        "scam_type": ai_result.get("scam_type", "unknown"),

        # Meta
        "scoring_source": combined["scoring_source"],
    }

    return jsonify(response), 200


@app.route("/api/status", methods=["GET"])
def status():
    """Health check endpoint."""
    has_api_key = bool(os.environ.get("GEMINI_API_KEY"))
    return jsonify({
        "status": "ok",
        "ai_enabled": has_api_key,
        "version": "2.0.0",
        "engine": "hybrid_ai_rules",
    }), 200


# ---------------------------------------------------------------------------
# 4. ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  AuthentiHire v2.0 — AI-Powered Verification")
    print("  http://127.0.0.1:5000")
    ai_status = "ENABLED" if os.environ.get("GEMINI_API_KEY") else "DISABLED (no API key)"
    print(f"  AI Engine: {ai_status}")
    print("=" * 60)

    app.run(host="0.0.0.0", port=5000, debug=True)
