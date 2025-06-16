import requests
from datetime import datetime

API_KEY = "AIzaSyDQsXbqmP-LlT6Msh_aLfTUXs2WmpTnd6w"
LOG_FILE = "logs.txt"
VALID_SERVICES_FILE = "valid_services.txt"

google_apis = {
    "Geocoding API": "https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key={}",
    "Elevation API": "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={}",
    "Directions API": "https://maps.googleapis.com/maps/api/directions/json?origin=Toronto&destination=Montreal&key={}",
    "Distance Matrix API": "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Seattle&destinations=San+Francisco&key={}",
    "Places API": "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+New+York&key={}",
    "Static Maps API": "https://maps.googleapis.com/maps/api/staticmap?center=Brooklyn+Bridge,New+York,NY&zoom=14&size=400x400&key={}",
    "YouTube Data API": "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={}",
    "Books API": "https://www.googleapis.com/books/v1/volumes?q=harry+potter&key={}",
    "Calendar API": "https://www.googleapis.com/calendar/v3/users/me/calendarList?key={}",
    "Custom Search API": "https://www.googleapis.com/customsearch/v1?q=google&cx=017576662512468239146:omuauf_lfve&key={}",
    "Translate API": "https://translation.googleapis.com/language/translate/v2?q=hello&target=es&key={}",
    "Vision API": "https://vision.googleapis.com/v1/images:annotate?key={}",
    "Gmail API": "https://gmail.googleapis.com/gmail/v1/users/me/profile?key={}",
    "Drive API": "https://www.googleapis.com/drive/v3/about?fields=*&&key={}"
}

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")
    print(f"[{timestamp}] {message}")

log("=== Google API Key Validation Script Started ===")
log(f"Testing API key: {API_KEY[:10]}... (truncated for security)")

valid_services = []

for name, endpoint in google_apis.items():
    url = endpoint.format(API_KEY)
    log(f"Testing {name}...")
    try:
        response = requests.get(url)
        if response.status_code == 200 and "error" not in response.text.lower():
            log(f"{name} is working.")
            valid_services.append(name)
        else:
            log(f"❌ {name} is not accessible or not authorized.")
            log(f"↪ Status: {response.status_code}, Body snippet: {response.text[:100]}...")
    except Exception as e:
        log(f"Error checking {name}: {str(e)}")

if valid_services:
    log("=== Valid Services Found ===")
    with open(VALID_SERVICES_FILE, "w") as f:
        for service in valid_services:
            f.write(f"{service}\n")
            log(f"✔ Logged working service: {service}")
else:
    log("No valid services found with this API key.")

log("Script Completed")
