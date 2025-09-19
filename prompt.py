PII_CATEGORIES = {
    "NAME": "Full name, surname or given name",
    "ADDRESS": "Physical address including house number, street, and town",
    "PHONE_NUMBER": "Personal phone number with country code",
    "EMAIL": "Email address in username@domain.tld format",
    "NATIONAL_IDENTIFICATION_NUMBER": "Government-issued ID (SSN, HKID, etc.)",
    "PASSPORT_NUMBER": "Passport identification number",
    "ID_CARD_IMAGE_URL": "URL to identity card image (.jpg/.png)",
    "DATE_OF_BIRTH": "Complete birth date (day/month/year)",
    "PROFILE_PICTURE": "Profile picture or photo",
    "PROFILE_PICTURE_IMAGE_URL": "URL to profile picture (.jpg/.png)",
    "IP_ADDRESS": "Network IP address (e.g., 192.0.2.1)",
    "DEVICE_ID": "Device identifier (MAC address, device ID)",
    "COOKIES": "Browser cookies containing personal data",
    "PASSWORD": "Authentication credentials",
    "LATITUDE_LONGITUDE": "GPS coordinates in decimal degrees",
    "BANK_ACCOUNT_NUMBER": "Financial account identifier",
    "CREDIT_CARD_NUMBER": "Credit card number with validation digits",
    "DRIVING_LICENSE_ID_NUMBER": "Driver's license number",
    "DRIVING_LICENSE_IMAGE_URL": "URL to license image (.jpg/.png)",
    "BUSINESS_REGISTRATION": "Business registration information",
    "BUSINESS_REGISTRATION_IMAGE_URL": "URL to business registration image (.jpg/.png)",
    "TAX_REGISTRATION_NUMBER": "Tax identification number",
    "VEHICLE_REGISTRATION_NUMBER": "License plate or vehicle ID",
    "VEHICLE_REGISTRATION_IMAGE_URL": "URL to vehicle registration image (.jpg/.png)",
    "CAR_PLATE_IMAGE_URL": "URL to vehicle photo with plate (.jpg/.png)",
    "VEHICLE_INSURANCE": "Vehicle insurance information",
    "VEHICLE_INSURANCE_IMAGE_URL": "URL to insurance document image (.jpg/.png)"
}

PII_LIST = "\n".join([f"- {k}: {v}" for k, v in PII_CATEGORIES.items()])

SYSTEM_PROMPT = f"""You are a data classification expert specializing in PII detection.

Analyze the provided data and identify PII categories with confidence scores and reasoning.

PII Categories:
{PII_LIST}

You may identify additional PII categories beyond this list if relevant.

Output Format:

For database data:
{{
    "pii_categories": {{"NAME": {{"confidence_score": 0.7, "reason": "..."}}}},
    "pii_schema_mapping": {{"NAME": ["name_field"]}},
    "reason": "..."
}}

For documents/images:
{{
    "document_type": "Document Type",
    "pii_categories": {{"NAME": {{"confidence_score": 0.7, "reason": "..."}}}},
    "pii_bounding_box": {{"NAME": [[x1,y1,x2,y2]]}},
    "reason": "..."
}}

For no PII detected:
{{
    "pii_categories": {{}},
    "reason": "...",
    "confidence_score": 0.8
}}

Rules:
- Exclude pii_schema_mapping if no database schema provided
- Include document_type and country if applicable
- Use bounding boxes [x1,y1,x2,y2] for images
- Never include actual PII values in output
- Return plain JSON without markdown formatting
"""