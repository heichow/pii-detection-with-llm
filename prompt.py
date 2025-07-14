PII_LIST = """
- NAME: Name
- ADDRESS: Address
- PHONE_NUMBER: Personal phone number
- EMAIL: Personal email address
- GOVERNMENT_ID_NUMBER: Government-issued ID numbers (eg. A1234567)
- PASSPORT_NUMBER: Passport number
- DRIVING_LICENSE_ID_NUMBER: Driving license identification number
- FINANCIAL_ACCOUNT_NUMBER: Financial account numbers, such as bank account and credit card numbers
- PROFILE_PICTURE: Profile picture
- PROFILE_PICTURE_IMAGE_URL: URL of Profile picture image file, but not the image itself
- ID_CARD_IMAGE_URL: URL of Identity card copy image file, but not the image itself
- DRIVING_LICENSE_IMAGE_URL: URL of Driving license copy image file, but not the image itself
- BUSINESS_REGISTRATION: Business registration
- BUSINESS_REGISTRATION_IMAGE_URL: URL of Business registration copy image file, but not the image itself
- TAX_REGISTRATION_NUMBER: Tax registration number
- DATE_OF_BIRTH: Date of birth
- IP_ADDRESS: IP address
- VEHICLE_REGISTRATION_NUMBER: Vehicle registration number
- CAR_PLATE_NUMBER: Car plate number
- VEHICAL_REGISTRATION_IMAGE_URL: URL of Vehicle registration number image file, but not the image itself
- CAR_PLATE_IMAGE_URL: URL of Vehicle photo image file with car plate number, but not the image itself
- DRIVER_PROFILE_PHOTO: Driver profile photo
- LATITUDE_LONGITUDE: Geographical location
- COOKIES: Cookies and tracking identifiers
- DRIVER_FACE_VERIFICATION_IMAGE_URL: URL of Driver's face verification image file, but not the image itself
- Device_ID: Device ID or MAC address
- VEHICLE_INSURANCE: Vehicle insurance
- VEHICLE_INSURANCE_IMAGE_URL: URL of Vehicle insurance information copy image file, but not the image itself
- USER_ID: User in-app ID
- DRIVER_ID: Driver in-app ID
- PASSWORD: Password
- ORDER_ID: Order ID
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

If the data is image, also return the bounding box in a list of [x1, y1, x2, y2] of each PII category, following the example below:

{{
    "has_pii": true,
    "pii_categories": ["NAME", "ADDRESS"]
    "pii_bounding_box": {{ "NAME": [391, 182, 647, 809], "ADDRESS": [65, 204, 280, 449] }}
}}

Do not return the PII value in the output. Do not return ```json at the beginning and ``` in the end of output.
"""

