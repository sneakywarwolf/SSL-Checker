import requests
import time
import re
import os
from PIL import ImageGrab  # For taking screenshots
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
    Colorize the given text based on the specified color using termcolor.
    """
    colors = {
        "red": "red",     # Red for deprecated or outdated
        "green": "green", # Green for strong
        "orange": "yellow"  # Termcolor does not support orange directly, use yellow
    }
    return colored(text, colors.get(color, "white"))  # Default to white


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
            # Parse protocols with color coding
            for protocol in details.get("protocols", []):
                name = protocol.get("name", "Unknown")
                version = protocol.get("version", "Unknown")
                protocol_string = f"{name} {version}"
                if name == "SSLv3" or version in ["TLS 1.0", "TLS 1.1"]:
                    # Deprecated protocols
                    endpoint_results["protocols"].append(colorize(protocol_string, "red"))
                elif version in ["TLS 1.2", "TLS 1.3"]:
                    # Modern protocols
                    endpoint_results["protocols"].append(colorize(protocol_string, "green"))
                else:
                    # Unknown protocols
                    endpoint_results["protocols"].append(colorize(protocol_string, "yellow"))  # Use yellow for unknown

            # Parse cipher suites with color coding
            suites = details.get("suites", [])
            if suites:
                for suite in suites:
                    for cipher in suite.get("list", []):
                        name = cipher.get('name', 'Unnamed Cipher')
                        strength = cipher.get('cipherStrength', 0)
                        cipher_string = f"{name} (Strength: {strength})"
                        if strength < 128:
                            # Weak ciphers
                            endpoint_results["cipherSuites"].append(colorize(cipher_string, "orange"))
                        elif strength >= 128:
                            # Strong ciphers
                            endpoint_results["cipherSuites"].append(colorize(cipher_string, "green"))
                        else:
                            # Unknown cipher strength
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
            print(f"- {protocol}")  # Directly print the colorized protocol strings

        # Display cipher suites
        print("\nCipher Suites:")
        for suite in endpoint["cipherSuites"]:
            print(f"- {suite}")  # Directly print the colorized cipher suite strings



def create_folder(domain):
    """
    Create a folder named after the domain.
    """
    folder_path = os.path.join(os.getcwd(), domain)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    return folder_path


def take_screenshot(folder_path, filename="screenshot.png"):
    """
    Capture a screenshot and save it to the specified folder.
    """
    screenshot_path = os.path.join(folder_path, filename)
    screenshot = ImageGrab.grab()  # Capture the screen
    screenshot.save(screenshot_path)
    print(f"Screenshot saved to {screenshot_path}")


def save_results_to_file(results, domain, folder_path, filename=None):
    """
    Save the parsed results to a text file inside the specified folder.
    """
    if not filename:
        filename = f"{domain}_ssl_results.txt"  # Default file name based on domain
    file_path = os.path.join(folder_path, filename)

    with open(file_path, "w") as file:
        for endpoint in results:
            file.write(f"Results for IP: {endpoint['ipAddress']}\n")
            file.write(f"Status: {endpoint['statusMessage']}\n")

            # Write protocols
            file.write("\nSupported Protocols:\n")
            for protocol in endpoint["protocols"]:
                file.write(f"- {protocol}\n")

            # Write cipher suites
            file.write("\nCipher Suites:\n")
            for suite in endpoint["cipherSuites"]:
                file.write(f"- {suite}\n")
            file.write("\n")  # Add a newline after each endpoint

    print(f"Results saved to {file_path}")


def main():
    
    domain = input("Enter the domain name (e.g., example.com): ")
    
    if not validate_domain(domain):
        print("Error: Invalid domain format. Please try again.")
        return

    # Create folder for results and screenshots
    folder_path = create_folder(domain)
    
    # Fetch SSL data from SSL Labs API
    ssl_data = fetch_ssl_data(domain)
    
    if ssl_data:
        # Parse and display results
        parsed_results = parse_ssl_results(ssl_data)
        display_results(parsed_results)

        # Save results to the domain-specific folder
        save_results_to_file(parsed_results, domain, folder_path)

        # Capture a screenshot of the terminal output
        take_screenshot(folder_path)


if __name__ == "__main__":
    main()
