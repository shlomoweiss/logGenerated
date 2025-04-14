import argparse
import getpass
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, AuthenticationException, ApiError
import sys
import warnings
import urllib3 # Needed to disable warnings

# --- Configuration ---
# Hardcoded Elasticsearch host and HTTPS settings as requested
ES_HOSTS = ['https://localhost:9200'] # Scheme is included here
VERIFY_CERTS = False # <-- Disable certificate verification

# --- Disable InsecureRequestWarning ---
# Suppress the warning messages from urllib3 that appear when verify_certs=False
if not VERIFY_CERTS:
    print("**********************************************************************")
    print("* WARNING: SSL certificate verification is DISABLED.                 *")
    print("* This is INSECURE and should only be used for testing/development.  *")
    print("* Connecting to:", ES_HOSTS)
    print("**********************************************************************")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # Also suppress the specific warning from the elasticsearch library if needed
    warnings.filterwarnings("ignore", message="Connecting to '.*' using TLS with verify_certs=False is insecure")


def create_es_user(admin_user, admin_password, new_username, new_password, roles):
    """
    Connects to Elasticsearch (using hardcoded settings) and creates a new user.

    Args:
        admin_user (str): Username of an existing user with privileges to create users.
        admin_password (str): Password for the admin user.
        new_username (str): The username for the new user to be created.
        new_password (str): The password for the new user.
        roles (list): A list of roles to assign to the new user (e.g., ['read_only', 'kibana_user']).

    Returns:
        bool: True if user creation was successful, False otherwise.
    """
    print(f"\nAttempting to connect to Elasticsearch at {ES_HOSTS} as user '{admin_user}'...")
    print(f"SSL Verification Disabled: {not VERIFY_CERTS}")

    # --- Connection Setup ---
    # Uses the global configuration defined above
    # REMOVED 'scheme' and 'use_ssl' parameters
    common_params = {
        "hosts": ES_HOSTS,
        "basic_auth": (admin_user, admin_password),
        "request_timeout": 60,
        # Specific settings for HTTPS with verification disabled
        "verify_certs": VERIFY_CERTS,
        "ssl_show_warn": False # Try to suppress elasticsearch client specific warnings
    }

    try:
        # Create Elasticsearch client instance
        es = Elasticsearch(**common_params)

        # Verify connection
        if not es.ping():
            print("Error: Could not connect to Elasticsearch.")
            print("Hints: Is Elasticsearch running? Are the credentials correct?")
            if not VERIFY_CERTS:
                print("       Certificate verification is disabled.")
            return False
        print("Connection successful.")

    except ConnectionError as e:
        print(f"Error: Connection failed: {e}")
        print(f"Hints: Is Elasticsearch running at {ES_HOSTS[0]}?")
        print("       Check network connectivity and firewall rules.")
        if not VERIFY_CERTS:
             print("       Certificate verification is disabled. Ensure the server is reachable via HTTPS, even with invalid certs.")
        return False
    except AuthenticationException as e:
         print(f"Error: Authentication failed for user '{admin_user}'. Check credentials.")
         print(f"       Details: {getattr(e, 'info', e)}")
         return False
    except Exception as e: # Catch other potential init errors (like the original TypeError)
        print(f"An unexpected error occurred during connection setup: {e}")
        # Print traceback for debugging unexpected initialization errors
        import traceback
        traceback.print_exc()
        return False


    # --- User Creation ---
    user_body = {
        "password": new_password,
        "roles": roles,
        # Optional fields can be added here if needed
    }

    print(f"\nAttempting to create user '{new_username}' with roles {roles}...")

    try:
        # Use the Security API client
        response = es.security.put_user(
            username=new_username,
            body=user_body,
            refresh='wait_for'  # Ensure the change is immediately searchable
        )

        # Check response
        if response.get('created') is True:
            print(f"Successfully created user '{new_username}'.")
            return True
        else:
            print(f"User '{new_username}' might not have been created. Response: {response}")
            return False

    except ApiError as e:
        print(f"Error: Failed to create user '{new_username}'.")
        print(f"  Status Code: {e.status_code}")
        error_info = getattr(e, 'info', {}).get('error', {})
        reason = error_info.get('reason', 'Unknown reason')
        error_type = error_info.get('type', 'Unknown type')
        print(f"  Type: {error_type}")
        print(f"  Reason: {reason}")
        if e.status_code == 400 and 'already exists' in reason:
             print(f"Hint: User '{new_username}' already exists.")
        elif e.status_code == 403:
             print(f"Hint: User '{admin_user}' may not have sufficient privileges (needs 'manage_security').")
        return False
    except ConnectionError as e:
         print(f"Error: Connection lost during API call: {e}")
         return False
    except Exception as e: # Catch unexpected errors during API call
        print(f"An unexpected error occurred during user creation: {e}")
        return False
    finally:
        # Cleanly close the connection
        try:
            # Starting elasticsearch v8.x, close() is synchronous
             if hasattr(es, 'close'):
                 es.close()
        except Exception: # nosec # Ignore errors during close
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a new user in Elasticsearch (connects to https://localhost:9200, disables cert verification)."
    )

    # --- Arguments ---
    parser.add_argument(
        "--admin_user",
        default="elastic",
        help="Username of an existing admin user (e.g., 'elastic'). Default: elastic"
    )
    parser.add_argument(
        "--admin_pass",
        help="Password for the admin user. If not provided, will be prompted securely."
    )
    parser.add_argument(
        "--new_user",
        required=True,
        help="Username for the new user."
    )
    parser.add_argument(
        "--new_pass",
        required=True,
        help="Password for the new user."
    )
    parser.add_argument(
        "--roles",
        nargs='+',  # Allows specifying multiple roles
        required=True,
        help="List of roles to assign to the new user (e.g., read_only kibana_user)."
    )

    args = parser.parse_args()

    # Securely get admin password if not provided via argument
    admin_password = args.admin_pass
    if not admin_password:
        try:
             admin_password = getpass.getpass(f"Enter password for admin user '{args.admin_user}' on {ES_HOSTS[0]}: ")
        except Exception as error:
            print('ERROR: Password input failed', error)
            sys.exit(1)
        if not admin_password:
             print("ERROR: Admin password cannot be empty.")
             sys.exit(1)

    # --- Call the main function ---
    success = create_es_user(
        admin_user=args.admin_user,
        admin_password=admin_password,
        new_username=args.new_user,
        new_password=args.new_pass,
        roles=args.roles
    )

    # Exit with appropriate status code
    sys.exit(0 if success else 1)