PII_LIST = """
- Name: full name, surname or given name
- ADDRESS: home address
- PHONE_NUMBER: personal phone number
- EMAIL: personal email address
- NATIONAL_IDENTIFICATION_NUMBER: a unique identifier used by the governments of many countries as a means of uniquely identifying their citizens or residents for the purposes of work, taxation, government benefits, health care, banking and other governmentally-related functions.
- PASSPORT_NUMBER: passport number
- DRIVING_LICENSE_ID_NUMBER: driving license identification number
- FINANCIAL_ACCOUNT_NUMBER: financial account numbers, such as bank account and credit card numbers
- PROFILE_PICTURE: profile picture
- PROFILE_PICTURE_IMAGE_URL: URL of Profile picture image file, but not the image itself
- ID_CARD_IMAGE_URL: URL of Identity card copy image file, but not the image itself
- DRIVING_LICENSE_IMAGE_URL: URL of Driving license copy image file, but not the image itself
- BUSINESS_REGISTRATION: business registration
- BUSINESS_REGISTRATION_IMAGE_URL: URL of Business registration copy image file, but not the image itself
- TAX_REGISTRATION_NUMBER: tax registration number
- DATE_OF_BIRTH: date of birth
- IP_ADDRESS: IP address
- VEHICLE_REGISTRATION_NUMBER: vehicle registration number
- CAR_PLATE_NUMBER: car plate number
- VEHICAL_REGISTRATION_IMAGE_URL: URL of Vehicle registration number image file, but not the image itself
- CAR_PLATE_IMAGE_URL: URL of Vehicle photo image file with car plate number, but not the image itself
- DRIVER_PROFILE_PHOTO: driver profile photo
- LATITUDE_LONGITUDE: geographical location
- COOKIES: cookies and tracking identifiers
- DRIVER_FACE_VERIFICATION_IMAGE_URL: URL of Driver's face verification image file, but not the image itself
- DEVICE_ID: a unique identifier assigned to a specific device, such as MAC address, Android device ID, iOS device ID
- VEHICLE_INSURANCE: vehicle insurance
- VEHICLE_INSURANCE_IMAGE_URL: URL of Vehicle insurance information copy image file, but not the image itself
- USER_ID: user in-app ID that will differentiate between different users
- DRIVER_ID: driver in-app ID that will differentiate between different drivers
- PASSWORD: Password
- ORDER_ID: Order ID
"""

SYSTEM_PROMPT = f"""You are the expert of data classification to organizing data into categories based on its sensitivity, importance, and risk levels. 

Follow the PII list below to label the PII categories:
{PII_LIST}

Also, think carefully if any other direct or indirect PII out of the above PII list. You may create new PII categories and label in new_pii_categories.

Return the PII result in JSON format following the example below:

{{
    "has_pii": true,
    "pii_categories": ["NAME", "DATE_OF_BIRTH"],
    "new_pii_categories": ["SEX"],
    "pii_schema_mapping": {{ "NAME": [name], "DATE_OF_BIRTH": [date_of_birth] }}
}}

Exclude pii_schema_mapping if no database schema is provided.

If the data is image, identify the type of document, with country of origin if possible.
Also return the bounding box in a list of [x1, y1, x2, y2] of each PII category, following the example below:

{{
    "has_pii": true,
    "document_type": "Hong Kong Passport",
    "pii_categories": ["NAME", "DATE_OF_BIRTH"],
    "new_pii_categories": ["SEX"],
    "pii_bounding_box": {{ "NAME": [[391,182,647,809]], "DATE_OF_BIRTH": [[389,399,650,450]] }}
}}

Do not return the PII value in the output. Do not return ```json at the beginning and ``` in the end of output.
"""

