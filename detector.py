"""
detector.py - Enhanced Rule-Based Scam Detection for JobSentinel
=================================================================
Analyses job/internship posting text and email content using 80+
pattern rules across 10 categories. Integrated with AI detector
for hybrid analysis.
"""

import re
from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# 1. PATTERN DEFINITIONS
#    Each category is a list of (pattern_string, score_delta, flag_label)
#    tuples.  Positive deltas increase the scam score; negative deltas
#    decrease it (legitimate signals).
# ---------------------------------------------------------------------------

# 1a. Urgency keywords – pressure tactics common in scam postings
URGENCY_KEYWORDS: List[tuple] = [
    ("act now",               10, "Urgency tactic: 'act now'"),
    ("limited time",          10, "Urgency tactic: 'limited time'"),
    ("urgent",                10, "Urgency tactic: 'urgent'"),
    ("immediately",           10, "Urgency tactic: 'immediately'"),
    ("don't miss",            10, "Urgency tactic: 'don't miss'"),
    ("expires soon",          10, "Urgency tactic: 'expires soon'"),
    ("today only",            10, "Urgency tactic: 'today only'"),
    ("respond immediately",   10, "Urgency tactic: 'respond immediately'"),
    ("hurry",                 10, "Urgency tactic: 'hurry'"),
    ("last chance",           10, "Urgency tactic: 'last chance'"),
    ("apply before",          10, "Urgency tactic: 'apply before'"),
    ("positions filling fast", 10, "Urgency tactic: 'positions filling fast'"),
    ("limited seats",         10, "Urgency tactic: 'limited seats'"),
    ("only few spots",        10, "Urgency tactic: 'only few spots left'"),
    ("deadline approaching",  10, "Urgency tactic: 'deadline approaching'"),
]

# 1b. Payment red flags – legitimate employers never ask you to pay
PAYMENT_RED_FLAGS: List[tuple] = [
    ("pay upfront",        20, "Payment red flag: 'pay upfront'"),
    ("registration fee",   20, "Payment red flag: 'registration fee'"),
    ("processing fee",     20, "Payment red flag: 'processing fee'"),
    ("send money",         20, "Payment red flag: 'send money'"),
    ("wire transfer",      20, "Payment red flag: 'wire transfer'"),
    ("pay to apply",       20, "Payment red flag: 'pay to apply'"),
    ("refundable deposit", 20, "Payment red flag: 'refundable deposit'"),
    ("buy kit",            20, "Payment red flag: 'buy kit'"),
    ("purchase kit",       20, "Payment red flag: 'purchase kit'"),
    ("invest now",         20, "Payment red flag: 'invest now'"),
    ("security deposit",   20, "Payment red flag: 'security deposit'"),
    ("training fee",       20, "Payment red flag: 'training fee'"),
    ("equipment fee",      20, "Payment red flag: 'equipment fee'"),
    ("starter kit",        20, "Payment red flag: 'starter kit'"),
]

# 1c. Vague / suspicious job description patterns
VAGUE_PATTERNS: List[tuple] = [
    ("work from home and earn",     15, "Vague promise: 'work from home and earn'"),
    ("no experience needed",        15, "Vague promise: 'no experience needed'"),
    ("unlimited earning",           15, "Vague promise: 'unlimited earning'"),
    ("be your own boss",            15, "Vague promise: 'be your own boss'"),
    ("passive income",              15, "Vague promise: 'passive income'"),
    ("guaranteed income",           15, "Vague promise: 'guaranteed income'"),
    ("weekly payment",              15, "Vague promise: 'weekly payment'"),
    ("no interview",                15, "Vague promise: 'no interview'"),
    ("hired immediately",           15, "Vague promise: 'hired immediately'"),
    ("make money fast",             15, "Vague promise: 'make money fast'"),
    ("earn from anywhere",          15, "Vague promise: 'earn from anywhere'"),
    ("no qualifications required",  15, "Vague promise: 'no qualifications required'"),
    ("instant approval",            15, "Vague promise: 'instant approval'"),
]

# 1d. Personal-info request red flags (India-centric examples included)
PERSONAL_INFO_REQUESTS: List[tuple] = [
    ("send your aadhar",        15, "Personal info request: Aadhaar card"),
    ("send your pan card",      15, "Personal info request: PAN card"),
    ("bank account details",    15, "Personal info request: bank account details"),
    ("send your passport",      15, "Personal info request: passport"),
    ("send your photo",         15, "Personal info request: photo"),
    ("send your id proof",      15, "Personal info request: ID proof"),
]

# 1e. Positive / legitimate signals – these *reduce* the scam score
POSITIVE_SIGNALS: List[tuple] = [
    ("formal interview",           -10, "Positive: mentions formal interview process"),
    ("video call interview",       -10, "Positive: mentions video call interview"),
    ("in-person interview",        -10, "Positive: mentions in-person interview"),
    ("hr department",              -10, "Positive: references HR department"),
    ("company registration number", -10, "Positive: company registration number mentioned"),
]

# ─────────────────────────────────────────────────────────────────
# NEW CATEGORIES — Email-specific scam patterns
# ─────────────────────────────────────────────────────────────────

# 1f. Congratulatory / flattery openers — classic unsolicited scam email pattern
CONGRATULATORY_PATTERNS: List[tuple] = [
    ("congratulations",                 15, "Scam signal: unsolicited 'congratulations'"),
    ("congratulation",                  15, "Scam signal: unsolicited 'congratulation'"),
    ("you have been selected",          18, "Scam signal: 'you have been selected' without applying"),
    ("your profile has been selected",  18, "Scam signal: unsolicited profile selection claim"),
    ("your profile matches",            15, "Scam signal: vague 'your profile matches' claim"),
    ("your application is required",    15, "Scam signal: 'your application is required' bait"),
    ("your resume has been shortlisted", 18, "Scam signal: unsolicited resume shortlisting"),
    ("you are shortlisted",             18, "Scam signal: unsolicited shortlisting claim"),
    ("you've been shortlisted",         18, "Scam signal: unsolicited shortlisting claim"),
    ("we found your profile",           12, "Scam signal: 'we found your profile' — unsolicited"),
    ("we found your resume",            12, "Scam signal: 'we found your resume' — unsolicited"),
    ("your profile caught our attention", 12, "Scam signal: flattery about profile"),
    ("we are impressed",                10, "Scam signal: generic flattery"),
    ("highly impressed by your profile", 12, "Scam signal: generic flattery"),
]

# 1g. Vague company references — scams never name a specific employer
VAGUE_COMPANY_PATTERNS: List[tuple] = [
    ("leading mncs",                12, "Vague reference: 'leading MNCs' — no specific company named"),
    ("leading companies",           12, "Vague reference: 'leading companies' — no specifics"),
    ("top companies",               12, "Vague reference: 'top companies' — no specifics"),
    ("top mncs",                    12, "Vague reference: 'top MNCs' — no specifics"),
    ("reputed companies",           12, "Vague reference: 'reputed companies' — no specifics"),
    ("reputed organizations",       12, "Vague reference: 'reputed organizations' — no specifics"),
    ("fortune 500",                 8,  "Vague reference: 'Fortune 500' without naming company"),
    ("multinational companies",     10, "Vague reference: 'multinational companies' — no specifics"),
    ("currently hiring",            8,  "Vague claim: 'currently hiring' without details"),
    ("multiple openings",           8,  "Vague claim: 'multiple openings' without specifics"),
    ("various positions",           8,  "Vague claim: 'various positions' without specifics"),
    ("exciting opportunities",      8,  "Vague claim: 'exciting opportunities'"),
]

# 1h. Registration / form bait — directing to external links
REGISTRATION_BAIT_PATTERNS: List[tuple] = [
    ("register here",           15, "Registration bait: 'register here' link"),
    ("register now",            15, "Registration bait: 'register now' link"),
    ("click here to apply",     12, "Registration bait: 'click here to apply'"),
    ("click here to register",  15, "Registration bait: 'click here to register'"),
    ("submit your details",     12, "Registration bait: 'submit your details'"),
    ("fill the form",           10, "Registration bait: 'fill the form'"),
    ("fill out the form",       10, "Registration bait: 'fill out the form'"),
    ("fill this form",          10, "Registration bait: 'fill this form'"),
    ("apply through this link", 12, "Registration bait: 'apply through this link'"),
    ("apply via link",          12, "Registration bait: 'apply via link'"),
    ("apply here",              8,  "Registration bait: 'apply here'"),
]

# 1i. Unsubscribe / mass-mailer signals — recruitment doesn't use mass emails
MASS_MAILER_PATTERNS: List[tuple] = [
    ("unsubscribe",             10, "Mass mailer signal: 'unsubscribe' link in recruitment email"),
    ("opt out",                 8,  "Mass mailer signal: 'opt out' option in recruitment email"),
    ("if you wish to opt out",  10, "Mass mailer signal: opt-out language typical of spam"),
    ("you are receiving this email because", 8, "Mass mailer signal: automated email disclaimer"),
    ("this is an automated",    8,  "Mass mailer signal: automated email"),
    ("do not reply to this email", 5, "Mass mailer signal: no-reply instruction"),
]

# 1j. Suspicious sender patterns — domains that mimic job portals
SUSPICIOUS_SENDER_PATTERNS: List[tuple] = [
    ("getujobs",                15, "Suspicious sender: 'getujobs' — fake job portal domain"),
    ("aboroad-jobs",            15, "Suspicious sender: fake abroad jobs domain"),
    ("naukri-jobs",             15, "Suspicious sender: impersonating Naukri"),
    ("indeed-apply",            15, "Suspicious sender: impersonating Indeed"),
    ("linkedin-careers",        15, "Suspicious sender: impersonating LinkedIn"),
    ("job-alert",               8,  "Suspicious sender: generic job alert domain"),
    ("hire-now",                10, "Suspicious sender: generic hiring domain"),
    ("dream-job",               10, "Suspicious sender: 'dream-job' domain"),
    ("quick-hire",              10, "Suspicious sender: 'quick-hire' domain"),
    ("easy-jobs",               10, "Suspicious sender: 'easy-jobs' domain"),
    ("skill.get",               12, "Suspicious sender: suspicious subdomain pattern"),
]


# ---------------------------------------------------------------------------
# 2. REGEX-BASED PATTERN CHECKS
# ---------------------------------------------------------------------------

# 2a. Suspicious contact patterns
SUSPICIOUS_EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@(gmail\.com|yahoo\.com|hotmail\.com|outlook\.com)",
    re.IGNORECASE,
)

HR_FREE_EMAIL_REGEX = re.compile(
    r"hr[\._ ][a-zA-Z0-9]+@(gmail\.com|yahoo\.com|hotmail\.com|outlook\.com)",
    re.IGNORECASE,
)

WHATSAPP_ONLY_REGEX = re.compile(
    r"(contact\s+(us\s+)?(on|via|through)\s+whatsapp|whatsapp\s+only)",
    re.IGNORECASE,
)

# 2b. Fake / suspicious domain patterns
SUSPICIOUS_TLD_REGEX = re.compile(
    r"https?://[a-zA-Z0-9.-]+\.(xyz|tk|ml|ga|cf|top|buzz|club|icu|work)\b",
    re.IGNORECASE,
)

RANDOM_NUMBER_DOMAIN_REGEX = re.compile(
    r"https?://[a-zA-Z]+\d{3,}\.(com|net|org|in)",
    re.IGNORECASE,
)

FAKE_BRAND_DOMAIN_REGEX = re.compile(
    r"(amazon|google|microsoft|meta|apple|flipkart|tcs|infosys|wipro)"
    r"[_-](jobs?|hiring|careers?|recruit)\.(com|net|org|in)",
    re.IGNORECASE,
)

# 2c. NEW — Suspicious job portal domains (fake platforms)
FAKE_PORTAL_REGEX = re.compile(
    r"(getujobs|geturjobs|getmyjob|easyhiring|quickjobs|jobsalert24|hirenow24)"
    r"\.(com|in|org|net)",
    re.IGNORECASE,
)

# 2d. NEW — Info@ or noreply@ from non-company domains
INFO_EMAIL_REGEX = re.compile(
    r"(info|noreply|no-reply|support|admin)@[a-zA-Z0-9.-]+\.(com|in|net|org)",
    re.IGNORECASE,
)

# 2e. Positive-signal regexes
OFFICIAL_WEBSITE_REGEX = re.compile(
    r"https?://[a-zA-Z0-9.-]+\.(com|org|in)\b",
    re.IGNORECASE,
)

SALARY_RANGE_REGEX = re.compile(
    r"(salary|ctc|compensation|package)\s*[:.]?\s*[₹$€£]?\s*\d",
    re.IGNORECASE,
)

SPECIFIC_ROLE_REGEX = re.compile(
    r"(responsibilities|job\s+description|key\s+duties|role\s+overview)",
    re.IGNORECASE,
)

# 2f. NEW — Specific job title pattern (positive signal)
JOB_TITLE_REGEX = re.compile(
    r"(position|role|title|designation)\s*[:]\s*\w+",
    re.IGNORECASE,
)

# 2g. NEW — Company name pattern (positive signal)
COMPANY_NAME_REGEX = re.compile(
    r"(company|organization|employer)\s*[:]\s*\w+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 3. STRUCTURAL ANALYSIS — checks for missing critical information
# ---------------------------------------------------------------------------

def _structural_analysis(text: str, text_lower: str) -> tuple:
    """
    Analyze the structure of the text for missing critical job posting elements.
    Returns (score_delta, flags_list).
    """
    score = 0
    flags = []

    # Check for missing job title/role
    has_role = bool(JOB_TITLE_REGEX.search(text)) or any(
        kw in text_lower for kw in [
            "job title", "position:", "role:", "designation:",
            "software engineer", "developer", "analyst", "manager",
            "designer", "consultant", "intern ", "associate",
        ]
    )

    # Check for missing company name
    has_company = bool(COMPANY_NAME_REGEX.search(text)) or any(
        kw in text_lower for kw in [
            "company:", "at google", "at microsoft", "at amazon",
            "at tcs", "at infosys", "at wipro", "pvt ltd", "pvt. ltd",
            "private limited", "corporation", "technologies",
            "solutions pvt", "inc.", "llc",
        ]
    )

    # Check for missing location
    has_location = any(
        kw in text_lower for kw in [
            "location:", "office:", "based in", "remote",
            "hybrid", "on-site", "onsite", "work from office",
            "bangalore", "mumbai", "delhi", "hyderabad", "pune",
            "chennai", "kolkata", "noida", "gurgaon", "gurugram",
            "new york", "london", "san francisco",
        ]
    )

    if not has_role:
        score += 10
        flags.append("Missing info: no specific job title or role mentioned")

    if not has_company:
        score += 10
        flags.append("Missing info: no specific company name mentioned")

    if not has_location:
        score += 5
        flags.append("Missing info: no work location mentioned")

    # Very short text for a "job posting" is suspicious
    word_count = len(text.split())
    if word_count < 30:
        score += 10
        flags.append(f"Suspicious: very short message ({word_count} words) for a job offer")

    return score, flags


# ---------------------------------------------------------------------------
# 4. CORE ANALYSIS FUNCTION
# ---------------------------------------------------------------------------

def analyze_text(text: str) -> Dict[str, Any]:
    """
    Analyse a job / internship posting for scam indicators.

    Parameters
    ----------
    text : str
        The raw text of the job posting to analyse.

    Returns
    -------
    dict
        {
            "score":                int   (0-100, capped),
            "risk_level":           str   ("LOW" | "MEDIUM" | "HIGH"),
            "flags":                list  (descriptive strings of findings),
            "highlighted_phrases":  list  (matched phrases from input text),
            "recommendation":       str   (actionable advice for the user),
            "total_checked":        int   (total patterns evaluated),
        }
    """

    score: int = 0
    flags: List[str] = []
    highlighted_phrases: List[str] = []

    text_lower: str = text.lower()
    total_checked: int = 0

    # ---------------------------------------------------------------
    # 4a. Check all keyword-based pattern lists
    # ---------------------------------------------------------------
    all_keyword_lists = [
        URGENCY_KEYWORDS,
        PAYMENT_RED_FLAGS,
        VAGUE_PATTERNS,
        PERSONAL_INFO_REQUESTS,
        POSITIVE_SIGNALS,
        # NEW categories
        CONGRATULATORY_PATTERNS,
        VAGUE_COMPANY_PATTERNS,
        REGISTRATION_BAIT_PATTERNS,
        MASS_MAILER_PATTERNS,
        SUSPICIOUS_SENDER_PATTERNS,
    ]

    for pattern_list in all_keyword_lists:
        for phrase, delta, flag_label in pattern_list:
            total_checked += 1
            if phrase.lower() in text_lower:
                score += delta
                flags.append(flag_label)
                highlighted_phrases.append(phrase)

    # ---------------------------------------------------------------
    # 4b. Regex-based suspicious contact checks
    # ---------------------------------------------------------------

    # Free-email as official contact
    total_checked += 1
    free_email_matches = SUSPICIOUS_EMAIL_REGEX.findall(text)
    if free_email_matches:
        score += 15
        flags.append("Suspicious contact: free email domain used as official address")
        for match in SUSPICIOUS_EMAIL_REGEX.finditer(text):
            highlighted_phrases.append(match.group(0))

    # HR prefix on free email
    total_checked += 1
    if HR_FREE_EMAIL_REGEX.search(text):
        score += 15
        flags.append("Suspicious contact: HR-prefixed free email (e.g. hr.company@gmail.com)")
        for match in HR_FREE_EMAIL_REGEX.finditer(text):
            highlighted_phrases.append(match.group(0))

    # WhatsApp-only contact
    total_checked += 1
    whatsapp_match = WHATSAPP_ONLY_REGEX.search(text)
    if whatsapp_match:
        score += 15
        flags.append("Suspicious contact: WhatsApp-only communication")
        highlighted_phrases.append(whatsapp_match.group(0))

    # No company website at all
    total_checked += 1
    if not OFFICIAL_WEBSITE_REGEX.search(text):
        score += 15
        flags.append("Suspicious contact: no company website URL found")

    # ---------------------------------------------------------------
    # 4c. Fake / suspicious domain checks
    # ---------------------------------------------------------------

    total_checked += 1
    tld_matches = SUSPICIOUS_TLD_REGEX.finditer(text)
    for match in tld_matches:
        score += 10
        flags.append(f"Fake domain: suspicious TLD detected ({match.group(0)})")
        highlighted_phrases.append(match.group(0))

    total_checked += 1
    rand_domain_matches = RANDOM_NUMBER_DOMAIN_REGEX.finditer(text)
    for match in rand_domain_matches:
        score += 10
        flags.append(f"Fake domain: random numbers in URL ({match.group(0)})")
        highlighted_phrases.append(match.group(0))

    total_checked += 1
    brand_matches = FAKE_BRAND_DOMAIN_REGEX.finditer(text)
    for match in brand_matches:
        score += 10
        flags.append(f"Fake domain: impersonating known brand ({match.group(0)})")
        highlighted_phrases.append(match.group(0))

    # NEW — Fake job portal domains
    total_checked += 1
    portal_matches = FAKE_PORTAL_REGEX.finditer(text)
    for match in portal_matches:
        score += 15
        flags.append(f"Fake portal: suspicious job portal domain ({match.group(0)})")
        highlighted_phrases.append(match.group(0))

    # NEW — info@/noreply@ from non-standard domains
    total_checked += 1
    info_matches = INFO_EMAIL_REGEX.finditer(text)
    for match in info_matches:
        # Only flag if domain is not a well-known company
        email_str = match.group(0).lower()
        well_known = ["google.com", "microsoft.com", "amazon.com", "linkedin.com",
                       "naukri.com", "indeed.com", "tcs.com", "infosys.com", "wipro.com"]
        if not any(wk in email_str for wk in well_known):
            score += 10
            flags.append(f"Suspicious: generic sender address ({match.group(0)})")
            highlighted_phrases.append(match.group(0))

    # ---------------------------------------------------------------
    # 4d. Positive-signal regex checks (reduce score)
    # ---------------------------------------------------------------

    total_checked += 1
    if OFFICIAL_WEBSITE_REGEX.search(text):
        score -= 5
        flags.append("Positive: official website URL found")

    total_checked += 1
    if SALARY_RANGE_REGEX.search(text) and "unlimited" not in text_lower:
        score -= 10
        flags.append("Positive: specific salary / compensation range mentioned")

    total_checked += 1
    if SPECIFIC_ROLE_REGEX.search(text):
        score -= 10
        flags.append("Positive: specific job role with clear responsibilities listed")

    # NEW positive checks
    total_checked += 1
    if JOB_TITLE_REGEX.search(text):
        score -= 8
        flags.append("Positive: specific job title/position mentioned")

    total_checked += 1
    if COMPANY_NAME_REGEX.search(text):
        score -= 8
        flags.append("Positive: specific company name mentioned")

    # ---------------------------------------------------------------
    # 4e. Structural analysis — missing critical info
    # ---------------------------------------------------------------
    struct_score, struct_flags = _structural_analysis(text, text_lower)
    score += struct_score
    flags.extend(struct_flags)
    total_checked += 4  # structural checks

    # ---------------------------------------------------------------
    # 4f. Cap score between 0 and 100
    # ---------------------------------------------------------------
    score = max(0, min(100, score))

    # ---------------------------------------------------------------
    # 4g. Determine risk level and recommendation
    # ---------------------------------------------------------------
    if score <= 30:
        risk_level = "LOW"
        recommendation = (
            "This offer appears relatively safe. Always verify the company "
            "on LinkedIn and their official website before proceeding."
        )
    elif score <= 60:
        risk_level = "MEDIUM"
        recommendation = (
            "Proceed with caution. Multiple suspicious patterns detected. "
            "Research this company thoroughly, check reviews on Glassdoor, "
            "and never pay any fees to get a job."
        )
    else:
        risk_level = "HIGH"
        recommendation = (
            "HIGH SCAM RISK DETECTED. Do NOT share personal information, "
            "do NOT send any money, do NOT click any links. Report this to "
            "cybercrime.gov.in or your institution's placement cell."
        )

    # ---------------------------------------------------------------
    # 4h. Build and return result dict
    # ---------------------------------------------------------------
    return {
        "score": score,
        "risk_level": risk_level,
        "flags": flags,
        "highlighted_phrases": highlighted_phrases,
        "recommendation": recommendation,
        "total_checked": total_checked,
    }


# ---------------------------------------------------------------------------
# 5. QUICK SELF-TEST
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Test with the real scam email
    sample_scam = (
        "Hi Aditi Borkar,\n\n"
        "CONGRATULATIONS!\n\n"
        "We're excited to inform you that your profile matches the requirements "
        "of leading MNCs currently hiring.\n\n"
        "To proceed, kindly submit your details: [Register Here]\n\n"
        "Best regards,\n"
        "Garima Maurya | HR Manager\n\n"
        "From: info@skill.getujobs.com\n"
        "If you wish to opt out of all type of emails, click Unsubscribe."
    )

    result = analyze_text(sample_scam)
    print("=" * 60)
    print("AuthentiHire — Enhanced Rule-Based Self-Test")
    print("=" * 60)
    print(f"Score        : {result['score']}")
    print(f"Risk Level   : {result['risk_level']}")
    print(f"Total Checked: {result['total_checked']}")
    print(f"Flags        :")
    for flag in result["flags"]:
        print(f"  • {flag}")
    print(f"Highlighted  :")
    for phrase in result["highlighted_phrases"]:
        print(f"  » {phrase}")
    print(f"Recommendation: {result['recommendation']}")
