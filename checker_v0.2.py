import requests
import time
import re
import os
from PIL import ImageGrab
import pyautogui
from termcolor import colored

def validate_domain(domain):
    """
    Validate the domain format.
    """
    pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    if pattern.match(domain):
        return True
    return False

def fetch_ssl_data(domain):
    """
    Fetch SSL/TLS details using the SSL Labs API.
    """
    base_url = "https://api.ssllabs.com/api/v3/analyze"
    params = {"host": domain, "all": "done"}
    print(f"Initiating SSL analysis for: {domain}")

    response = requests.get(base_url, params=params)
    if response.status_code != 200:
        print("Error: Unable to connect to SSL Labs API.")
        return None

    data = response.json()
    while data.get("status") in ["IN_PROGRESS", "STARTING"]:
        print("Analysis in progress, please wait...")
        time.sleep(10)
        response = requests.get(base_url, params=params)
        data = response.json()

    if data.get("status") != "READY":
        print("Error: Analysis could not be completed.")
        return None

    return data

def colorize(text, color):
    """
    Colorize the given text based on the specified color.
    """
    colors = {
        "red": "\033[31m",  # Red for deprecated or outdated
        "green": "\033[32m",  # Green for strong
        "orange": "\033[38;5;214m",  # Orange for weak
        "yellow": "\033[33m",  # Yellow for unknown
        "reset": "\033[0m"  # Reset to default
    }
    return f"{colors.get(color, colors['reset'])}{text}{colors['reset']}"

def parse_ssl_results(data):
    """
    Parse the SSL results and format them with color coding.
    """
    results = []
    for endpoint in data.get("endpoints", []):
        endpoint_results = {
            "ipAddress": endpoint.get("ipAddress"),
            "statusMessage": endpoint.get("statusMessage"),
            "protocols": [],
            "cipherSuites": []
        }

        details = endpoint.get("details", {})
        if details:
            # Parse protocols with annotations
            for protocol in details.get("protocols", []):
                name = protocol.get("name", "Unknown")
                version = protocol.get("version", "Unknown")
                protocol_string = f"{name} {version}"
                if name == "SSLv3" or version in ["TLS 1.0", "TLS 1.1"]:
                    endpoint_results["protocols"].append(f"{protocol_string} - Deprecated")
                elif version in ["TLS 1.2", "TLS 1.3"]:
                    endpoint_results["protocols"].append(f"{protocol_string} - Secure")
                else:
                    endpoint_results["protocols"].append(f"{protocol_string} - Unknown")

            # Parse cipher suites with color coding
            suites = details.get("suites", [])
            if suites:
                for suite in suites:
                    for cipher in suite.get("list", []):
                        name = cipher.get('name', 'Unnamed Cipher')
                        strength = cipher.get('cipherStrength', 0)
                        cipher_string = f"{name} (Strength: {strength})"
                        if strength < 128:
                            endpoint_results["cipherSuites"].append(colorize(cipher_string, "orange"))
                        elif strength >= 128:
                            endpoint_results["cipherSuites"].append(colorize(cipher_string, "green"))
                        else:
                            endpoint_results["cipherSuites"].append(cipher_string)
            else:
                print(f"No cipher suites found for {endpoint.get('ipAddress')}")

        results.append(endpoint_results)
    return results

def display_results(parsed_results):
    """
    Display the parsed SSL results with color-coded output.
    """
    for endpoint in parsed_results:
        print(f"\nResults for IP: {endpoint['ipAddress']}")
        print(f"Status: {endpoint['statusMessage']}")

        # Display protocols
        print("\nSupported Protocols:")
        for protocol in endpoint["protocols"]:
            print(f"- {protocol}")

        # Display cipher suites
        print("\nCipher Suites:")
        for suite in endpoint["cipherSuites"]:
            print(f"- {suite}")

def create_folder(domain):
    """
    Create a folder named after the domain.
    """
    folder_path = os.path.join(os.getcwd(), domain)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return folder_path

def take_screenshot(folder_path, filename_prefix="screenshot", width=800, height=600):
    """
    Capture terminal screenshots in a defined width and height, scrolling as needed.
    """
    screenshot_count = 0
    full_screen_height = pyautogui.size().height

    print("Please focus on the terminal window within 5 seconds...")
    time.sleep(5)

    while True:
        left, top = 0, 0
        region = (left, top, width, height)

        # Take the screenshot
        screenshot_path = os.path.join(folder_path, f"{filename_prefix}_{screenshot_count}.png")
        screenshot = pyautogui.screenshot(region=region)
        screenshot.save(screenshot_path)
        print(f"Screenshot saved to {screenshot_path}")
        screenshot_count += 1

        # Scroll down
        pyautogui.scroll(-full_screen_height // 2)
        time.sleep(1)

        # Check if scrolling is complete
        if pyautogui.pixelMatchesColor(left + 10, top + height - 10, (0, 0, 0)):
            print("Reached the end of the terminal output.")
            break

def save_results_to_file(results, domain, folder_path, filename=None):
    """
    Save the parsed results to a text file inside the specified folder.
    """
    if not filename:
        filename = f"{domain}_ssl_results.txt"
    file_path = os.path.join(folder_path, filename)

    with open(file_path, "w") as file:
        for endpoint in results:
            file.write(f"Results for IP: {endpoint['ipAddress']}\n")
            file.write(f"Status: {endpoint['statusMessage']}\n")

            file.write("\nSupported Protocols:\n")
            for protocol in endpoint["protocols"]:
                file.write(f"- {protocol}\n")

            file.write("\nCipher Suites:\n")
            for suite in endpoint["cipherSuites"]:
                file.write(f"- {suite}\n")
            file.write("\n")

    print(f"Results saved to {file_path}")
    return file_path

def main():
    domain = input("Enter the domain name (e.g., example.com): ")

    if not validate_domain(domain):
        print("Error: Invalid domain format. Please try again.")
        return

    folder_path = create_folder(domain)
    ssl_data = fetch_ssl_data(domain)

    if ssl_data:
        parsed_results = parse_ssl_results(ssl_data)
        display_results(parsed_results)

        file_path = save_results_to_file(parsed_results, domain, folder_path)

        # Take terminal screenshots
        take_screenshot(folder_path, filename_prefix=f"{domain}_terminal_screenshot")

if __name__ == "__main__":
    main()
