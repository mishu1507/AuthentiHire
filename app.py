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
from ai_detector import analyze_with_ai, compute_combined_score

# ---------------------------------------------------------------------------
# 1. APP INITIALISATION
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# Set the NVIDIA API key from environment or hardcode for development
# In production, always use environment variables!
if not os.environ.get("NVIDIA_API_KEY"):
    os.environ["NVIDIA_API_KEY"] = "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"


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
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON in request body."}), 400
    text = data.get("text", "").strip()

    if not text:
        return jsonify({"error": "'text' field is required and cannot be empty."}), 400

    # --- TEXT ANALYSIS PATH ---

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
    has_api_key = bool(os.environ.get("NVIDIA_API_KEY"))
    return jsonify({
        "status": "ok",
        "ai_enabled": has_api_key,
        "version": "2.0.0",
        "engine": "hybrid_ai_rules_nvidia",
    }), 200


# ---------------------------------------------------------------------------
# 4. ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  AuthentiHire v2.0 — AI-Powered Verification")
    print("  http://127.0.0.1:5000")
    ai_status = "ENABLED (NVIDIA Llama 3.2)" if os.environ.get("NVIDIA_API_KEY") else "DISABLED (no API key)"
    print(f"  AI Engine: {ai_status}")
    print("=" * 60)

    app.run(host="0.0.0.0", port=5000, debug=True)
