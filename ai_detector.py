"""
ai_detector.py - AI-Powered Scam Detection using NVIDIA NIM API
===============================================================
Uses NVIDIA's Llama 3.2 11B Vision Instruct model to perform deep semantic analysis of
job/internship postings and emails. Unlike keyword matching, the AI
understands context, tone, manipulation tactics, and subtle red flags.
"""

import base64
import json
import os
import re
from typing import Dict, Any, Optional

# ---------------------------------------------------------------------------
# 1. OPENAI CLIENT SETUP (Configured for NVIDIA NIM)
# ---------------------------------------------------------------------------

_client = None
_MODEL_ID = "meta/llama-3.2-11b-vision-instruct"


def _get_client():
    """Lazy-init the OpenAI client for NVIDIA NIM."""
    global _client
    if _client is None:
        try:
            from openai import OpenAI
            api_key = os.environ.get("NVIDIA_API_KEY", "")
            if not api_key:
                return None
            _client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=api_key
            )
        except Exception as e:
            print(f"[AI_DETECTOR] Failed to initialize OpenAI client for NVIDIA: {e}")
            return None
    return _client


# ---------------------------------------------------------------------------
# 2. EXPERT ANALYSIS PROMPT
# ---------------------------------------------------------------------------

ANALYSIS_PROMPT = """You are an expert Cyber Fraud Investigator specializing in fake job scams, 
fraudulent internship offers, and employment phishing attacks. You have 15+ years of experience 
analyzing thousands of scam emails, job postings, and recruitment fraud schemes.

Analyze the text or image that was submitted as a potential job offer, internship opportunity, 
or recruitment email. Perform a thorough investigation and return your findings.

ANALYSIS FRAMEWORK — Check ALL of these dimensions:

1. **SENDER CREDIBILITY**
   - Is the sender using a professional company domain or a free/generic email service?
   - Does the domain look like an impersonation? (e.g., getujobs.com, skill.getujobs.com)
   - Is there a real company name or just vague references?
   - Does the sender's title match what a real recruiter would use?

2. **CONTENT LEGITIMACY**
   - Is there a specific job role, title, or position mentioned?
   - Are there specific company names or just vague "leading MNCs", "top companies"?
   - Is there a real job description with responsibilities?
   - Are salary/compensation details mentioned?
   - Is there a specific location or office mentioned?
   - Are there qualification requirements?

3. **MANIPULATION TACTICS**
   - Unsolicited "CONGRATULATIONS" or "You have been selected" without applying
   - Urgency pressure ("limited seats", "apply now", "don't miss")
   - Flattery ("your profile is impressive", "you match our requirements")
   - Too-good-to-be-true promises
   - Vague benefits without specifics

4. **RED FLAGS**
   - Asking to "register" on an external link instead of a company portal
   - Asking for personal documents (Aadhaar, PAN, bank details) upfront
   - Requesting payment/fees of any kind
   - Using WhatsApp for official recruitment
   - No company website or LinkedIn presence referenced
   - Mass email patterns (generic greeting, no personalization beyond name)
   - "Unsubscribe" links typical of mass marketing, not recruitment

5. **DOMAIN & LINK ANALYSIS**
   - Check any URLs or domains mentioned
   - Look for suspicious TLDs, redirects, or link shorteners
   - Check if domains impersonate legitimate companies

IMPORTANT: You MUST respond with ONLY a valid JSON object (no markdown, no code fences, no extra text). 
Use this exact structure:

{
  "extracted_text": "<if an image was provided, extract all text you can read from it here>",
  "ai_score": <integer 0-100, where 0=definitely legitimate, 100=definitely a scam>,
  "ai_risk_level": "<LOW|MEDIUM|HIGH>",
  "ai_confidence": <integer 0-100, how confident you are in your assessment>,
  "ai_flags": [
    "<specific red flag finding 1>",
    "<specific red flag finding 2>"
  ],
  "ai_positive_signals": [
    "<any legitimate signals found, or empty array>"
  ],
  "ai_reasoning": "<2-3 sentence summary explaining your overall assessment>",
  "scam_type": "<type of scam if detected: 'recruitment_phishing', 'fee_fraud', 'data_harvesting', 'pyramid_scheme', 'impersonation', 'legitimate', 'unknown'>"
}

SCORING GUIDE:
- 0-20: Clearly legitimate job posting from a real company
- 21-40: Mostly legitimate but with minor concerns
- 41-60: Suspicious — multiple yellow flags
- 61-80: Likely a scam — strong red flags present
- 81-100: Almost certainly a scam — classic fraud patterns

Be thorough, be skeptical, and err on the side of caution to protect job seekers."""

# ---------------------------------------------------------------------------
# 3. AI ANALYSIS FUNCTIONS
# ---------------------------------------------------------------------------

def _parse_ai_response(response_text: str) -> Dict[str, Any]:
    """Parse and validate the JSON response from the LLM."""
    # Clean up potential markdown code fences
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*\n?", "", cleaned)
        cleaned = re.sub(r"\n?```\s*$", "", cleaned)
        cleaned = cleaned.strip()

    result = json.loads(cleaned)

    return {
        "ai_score": max(0, min(100, int(result.get("ai_score", 50)))),
        "ai_risk_level": result.get("ai_risk_level", "MEDIUM"),
        "ai_confidence": max(0, min(100, int(result.get("ai_confidence", 50)))),
        "ai_flags": result.get("ai_flags", []),
        "ai_positive_signals": result.get("ai_positive_signals", []),
        "ai_reasoning": result.get("ai_reasoning", "Analysis complete."),
        "scam_type": result.get("scam_type", "unknown"),
        "extracted_text": result.get("extracted_text", ""),
        "ai_available": True,
    }


def analyze_with_ai(text: str) -> Dict[str, Any]:
    """
    Send text to NVIDIA NIM (Llama 3.2 Vision Instruct) for deep scam analysis.

    Parameters
    ----------
    text : str
        The job posting / email text to analyze.

    Returns
    -------
    dict
        AI analysis results, or a fallback dict if the API call fails.
    """
    client = _get_client()

    if client is None:
        return _fallback_result("AI analysis unavailable -- no API key configured")

    try:
        response = client.chat.completions.create(
            model=_MODEL_ID,
            messages=[
                {"role": "system", "content": ANALYSIS_PROMPT},
                {"role": "user", "content": f"TEXT TO ANALYZE:\n---\n{text}\n---"}
            ],
            temperature=0.2,
            max_tokens=1024,
        )
        
        return _parse_ai_response(response.choices[0].message.content)

    except json.JSONDecodeError as e:
        print(f"[AI_DETECTOR] Failed to parse API response as JSON: {e}")
        return _fallback_result("AI response parsing failed")

    except Exception as e:
        print(f"[AI_DETECTOR] NVIDIA API call failed: {e}")
        return _fallback_result(f"AI analysis failed: {str(e)}")


def analyze_image_with_ai(image_bytes: bytes, mime_type: str) -> Dict[str, Any]:
    """
    Send an image (screenshot) to NVIDIA NIM for scam analysis.

    Parameters
    ----------
    image_bytes : bytes
        Raw bytes of the uploaded image.
    mime_type : str
        MIME type of the image (e.g. 'image/png', 'image/jpeg').

    Returns
    -------
    dict
        AI analysis results including extracted_text from the image.
    """
    client = _get_client()

    if client is None:
        return _fallback_result("AI analysis unavailable -- no API key configured")

    try:
        # Encode image to base64
        base64_encoded = base64.b64encode(image_bytes).decode('utf-8')
        data_uri = f"data:{mime_type};base64,{base64_encoded}"

        response = client.chat.completions.create(
            model=_MODEL_ID,
            messages=[
                {"role": "system", "content": ANALYSIS_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Please extract all text from this screenshot and analyze it for scam indicators."},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": data_uri
                            }
                        }
                    ]
                }
            ],
            temperature=0.2,
            max_tokens=1024,
        )

        return _parse_ai_response(response.choices[0].message.content)

    except json.JSONDecodeError as e:
        print(f"[AI_DETECTOR] Failed to parse vision response as JSON: {e}")
        return _fallback_result("AI image response parsing failed")

    except Exception as e:
        print(f"[AI_DETECTOR] NVIDIA Vision API call failed: {e}")
        return _fallback_result(f"AI image analysis failed: {str(e)}")


def _fallback_result(reason: str) -> Dict[str, Any]:
    """Return a safe fallback result when AI is unavailable."""
    return {
        "ai_score": None,
        "ai_risk_level": None,
        "ai_confidence": 0,
        "ai_flags": [],
        "ai_positive_signals": [],
        "ai_reasoning": reason,
        "scam_type": "unknown",
        "ai_available": False,
    }


# ---------------------------------------------------------------------------
# 4. COMBINED SCORING — merge AI + Rule-based scores
# ---------------------------------------------------------------------------

def compute_combined_score(rule_score: int, ai_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine rule-based score with AI score using weighted average.

    Weights:
    - If AI is available and confident (>60%): AI gets 60% weight, rules get 40%
    - If AI is less confident: AI gets 40% weight, rules get 60%
    - If AI unavailable: 100% rule-based

    Parameters
    ----------
    rule_score : int
        Score from the rule-based detector (0-100).
    ai_result : dict
        Result from analyze_with_ai().

    Returns
    -------
    dict
        Combined scoring with final_score, final_risk_level, etc.
    """
    if not ai_result.get("ai_available", False) or ai_result["ai_score"] is None:
        # AI unavailable — use rule score only
        final_score = rule_score
        source = "rules_only"
    else:
        ai_score = ai_result["ai_score"]
        ai_confidence = ai_result.get("ai_confidence", 50)

        if ai_confidence >= 60:
            # High confidence — AI gets more weight
            final_score = int(ai_score * 0.60 + rule_score * 0.40)
            source = "ai_primary"
        else:
            # Lower confidence — rules get more weight
            final_score = int(ai_score * 0.40 + rule_score * 0.60)
            source = "ai_secondary"

        # If either score is very high (>75), boost the final score
        # This ensures obvious scams aren't diluted
        if ai_score >= 75 or rule_score >= 75:
            final_score = max(final_score, max(ai_score, rule_score) - 10)

    final_score = max(0, min(100, final_score))

    # Determine final risk level
    if final_score <= 30:
        final_risk = "LOW"
    elif final_score <= 60:
        final_risk = "MEDIUM"
    else:
        final_risk = "HIGH"

    return {
        "final_score": final_score,
        "final_risk_level": final_risk,
        "scoring_source": source,
        "rule_score": rule_score,
        "ai_score": ai_result.get("ai_score"),
    }


# ---------------------------------------------------------------------------
# 5. SELF-TEST
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Test with the actual scam email
    test_email = """
    Hi Aditi Borkar,

    CONGRATULATIONS!

    We're excited to inform you that your profile matches the requirements 
    of leading MNCs currently hiring.

    To proceed, kindly submit your details: [Register Here]

    Best regards,
    Garima Maurya | HR Manager

    From: info@skill.getujobs.com
    """

    print("=" * 60)
    print("AI Detector — Self-Test (NVIDIA NIM)")
    print("=" * 60)

    result = analyze_with_ai(test_email)

    if result["ai_available"]:
        print(f"AI Score     : {result['ai_score']}")
        print(f"Risk Level   : {result['ai_risk_level']}")
        print(f"Confidence   : {result['ai_confidence']}%")
        print(f"Scam Type    : {result['scam_type']}")
        print(f"Reasoning    : {result['ai_reasoning']}")
        print(f"Red Flags    :")
        for flag in result["ai_flags"]:
            print(f"  🚩 {flag}")
        print(f"Positive     :")
        for sig in result["ai_positive_signals"]:
            print(f"  ✅ {sig}")
    else:
        print(f"AI unavailable: {result['ai_reasoning']}")
