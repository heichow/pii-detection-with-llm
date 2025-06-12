PII_LIST = """
Personal Data
- Full name: NAME
- Birth date: DATE_OF_BIRTH
- Mailing address: ADDRESS
- Email address: EMAIL
- Phone number: PHONE_NUMBER
- Profile Photo: PROFILE_PHOTO
- Driver license: DRIVER_LICENSE
- National identification number: NATIONAL_IDENTIFICATION_NUMBER
- Passport number: PASSPORT_NUMBER
- Social Security number (SSN): SOCIAL_SECURITY_NUMBER
- Global Positioning System (GPS) coordinates: LATITUDE_LONGITUDE
- National Insurance Number (NINO): NATIONAL_INSURANCE_NUMBER
- Taxpayer identification or reference number: TAX_IDENTIFICATION_NUMBER

Contact & Account Data
- Username: USERNAME
- Password with hashing: PASSWORD
- Language preference: LANGUAGE_PREFERENCE
- Communication preference: COMMUNCATION_PREFERENCE

Location & Travel Data
- Global Positioning System (GPS) coordinates: LATITUDE_LONGITUDE
- Pickup and drop-off addresses: DELIVERY_ADDRESS
- Trip distance: TRIP_DISTANCE
- Trip duration: TRIP_DURATION
- Location history: LOCATION_HISTORY
- Frequent destinations (e.g. home, work): FREQUENT_DESTINATION

Payment & Financial Data
- Bank account: BANK_ACCOUNT_NUMBER
- Credit Card Number: CREDIT_CARD_NUMBER
- Billing address: BILLING_ADDRESS
- Transaction history: TRANSACTION_HISTORY
- Invoice and receipts: INVOICE
- Refund records: REFUND_RECORD
- Payment method preferences: PAYMENT_PREFERENCE

Device & Technical Data
- IP address: IP_ADDRESS
- Device ID (e.g. IMEI): DEVICE_ID
- Device type and operating system: DEVICE_TYPE
- App version and mobile carrier: 
- Cookies and tracking identifiers: COOKIES
- Logs and app usage metrics: APP_LOG_AND_METRICS

Behavioral & Usage Data
- Ride ratings (given and received): RIDE_RATING
- Complaints and feedback: USER_FEEDBACK
- Ride frequency and timing: RIDE_FREQUENCY
- Promotion or discount usage: PROMOTION_OR_DISCOUNT
- In-app navigation behavior: APP_EVENT

Communication Data
- Chat messages with driver: DRIVER_CHAT_MESSAGES
- Chat messages with support: SUPPORT_CHAT_MESSAGES
- Voice calls (if recorded or logged): VOICE_CALL_LOG
- Email and in-app support messages: EMAIL_MESSAGES

Driver-Specific Data
- Vehicle identification number: VEHICLE_IDENTIFICATION_NUMBER
- Vehicle Insurance: VEHICLE_INSURANCE
- Driving history and ratings: DRIVER_RATING
- Earnings and tax information: DRIVER_INCOME_AND_TAX
- Background check results: BACKGROUND_CHECK_RESULT

Third-Party or Emergency Contact Data
- Contact name and phone: EMERGENCY_CONTACT
- Referrals or invited friends: REFERRAL

Special Category Data 
- Sex (e.g. M, F): SEX 
- Health insurance or medical identification number: HEALTH_INSURANCE_NUMBER
- Disability: DISABILITY
- Criminal records: CRIMINAL_RECORD
"""

SYSTEM_PROMPT = f"""You are the expert of data classification to organizing data into categories based on its sensitivity, importance, and risk levels. Strictly follow the PII list below to label the PII categories:

{PII_LIST}

Return the PII result in JSON format following the example below:

{{
    "has_pii": true,
    "pii_categories": ["NAME", "ADDRESS"]
    "pii_schema_mapping": {{ "NAME": name, "ADDRESS": home_address }}
}}

Exclude pii_schema_mapping if no database schema is provided.

Do not return the PII value in the output. Do not return ```json at the beginning and ``` in the end of output.
"""

