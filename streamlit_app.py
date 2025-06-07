import streamlit as st
import pandas as pd
import paramiko # For SFTP connections
import requests # For API connections
import os
import json
from datetime import datetime, timedelta
import schedule # Lightweight scheduling library
import time
import threading
from pathlib import Path # For getting the script's path

# --- Configuration and State Management ---
# Use st.session_state for managing persistent data across reruns
# and for storing connection details, schedules, etc.
if 'connections' not in st.session_state:
    # Stores connection details: {'conn_name': {'type': 'SFTP', ...}}
    st.session_state.connections = {}
if 'schedules' not in st.session_state:
    # Stores scheduling info: {'schedule_name': {'connection_name': 'sftp_conn', ...}}
    st.session_state.schedules = {}
if 'connection_health' not in st.session_state:
    # Stores health status: {'conn_name': {'status': 'Green/Red/Unknown', 'last_checked': datetime, 'issues': '...'}}
    st.session_state.connection_health = {}

# --- Helper Functions ---

def save_connection(connection_name, connection_details):
    """
    Saves connection details to st.session_state.
    In a production app, this would save to a persistent backend (e.g., database, secure file).
    """
    st.session_state.connections[connection_name] = connection_details
    st.success(f"Connection '{connection_name}' saved!")

def test_sftp_connection(hostname, port, username, password):
    """
    Tests an SFTP connection using paramiko.
    Returns (True, message) on success, (False, error_message) on failure.
    """
    try:
        transport = paramiko.Transport((hostname, port))
        # Set a timeout for connection to avoid hanging
        transport.connect(username=username, password=password, timeout=10)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.close()
        transport.close()
        return True, "Connection successful"
    except Exception as e:
        return False, f"Connection failed: {e}"

def test_api_connection(api_url, headers=None, payload=None, method='GET'):
    """
    Tests an API connection by making a sample request.
    Returns (True, message) on success, (False, error_message) on failure.
    """
    try:
        # For a basic test, a GET request is usually sufficient.
        # For POST/PUT, a minimal payload might be needed if the endpoint requires it.
        if method.upper() == 'GET':
            response = requests.get(api_url, headers=headers, timeout=10)
        elif method.upper() == 'POST':
            # Use a dummy payload for testing if not provided
            test_payload = payload if payload is not None else {}
            response = requests.post(api_url, headers=headers, json=test_payload, timeout=10)
        else:
            return False, "Unsupported HTTP method for testing (only GET/POST supported for connection test)."

        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return True, f"API connection successful (Status: {response.status_code})"
    except requests.exceptions.RequestException as e:
        return False, f"API connection failed: {e}"
    except json.JSONDecodeError:
        return False, "Invalid JSON in API response or payload."


def execute_sftp_transfer(connection_name, source_path, destination_path, transfer_type):
    """
    Executes an SFTP file transfer (upload or download).
    In a real application, consider streaming large files.
    """
    conn_details = st.session_state.connections.get(connection_name)
    if not conn_details or conn_details['type'] != 'SFTP':
        return False, "Invalid SFTP connection details provided."

    hostname = conn_details['hostname']
    port = conn_details.get('port', 22)
    username = conn_details['username']
    # WARNING: Storing passwords in session_state is not secure for production.
    # Use environment variables, Streamlit secrets, or a dedicated secrets manager.
    password = conn_details['password']

    try:
        transport = paramiko.Transport((hostname, port))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)

        file_size = 0
        if transfer_type == 'upload':
            if not os.path.exists(source_path):
                return False, f"Source file not found locally: {source_path}"
            file_size = os.path.getsize(source_path)
            sftp.put(source_path, destination_path)
            message = f"Uploaded '{source_path}' ({file_size} bytes) to '{destination_path}' on SFTP."
        elif transfer_type == 'download':
            # Check if file exists on SFTP before downloading
            try:
                stat_info = sftp.stat(source_path)
                file_size = stat_info.st_size
            except FileNotFoundError:
                return False, f"Source file not found on SFTP: {source_path}"
            sftp.get(source_path, destination_path)
            message = f"Downloaded '{source_path}' ({file_size} bytes) from SFTP to '{destination_path}'."
        else:
            return False, "Invalid SFTP transfer type. Must be 'upload' or 'download'."

        sftp.close()
        transport.close()
        
        # You'd store volume/frequency data in a more persistent way here
        # For demonstration, we'll just return it.
        return True, message, file_size
    except Exception as e:
        return False, f"SFTP transfer failed: {e}", 0

def execute_api_call(connection_name, endpoint, method, headers=None, payload=None):
    """
    Executes an API call using the requests library.
    """
    conn_details = st.session_state.connections.get(connection_name)
    if not conn_details or conn_details['type'] != 'API':
        return False, "Invalid API connection details provided."

    base_url = conn_details['base_url']
    full_url = f"{base_url}{endpoint}"

    # Merge headers from connection details and call-specific headers
    effective_headers = conn_details.get('headers', {}).copy()
    if headers:
        effective_headers.update(headers)

    try:
        response_obj = None
        if method.upper() == 'GET':
            response_obj = requests.get(full_url, headers=effective_headers, timeout=15)
        elif method.upper() == 'POST':
            response_obj = requests.post(full_url, headers=effective_headers, json=payload, timeout=15)
        elif method.upper() == 'PUT':
            response_obj = requests.put(full_url, headers=effective_headers, json=payload, timeout=15)
        elif method.upper() == 'DELETE':
            response_obj = requests.delete(full_url, headers=effective_headers, timeout=15)
        else:
            return False, "Unsupported HTTP method for API call.", 0

        response_obj.raise_for_status() # Raise HTTPError for bad responses

        response_content_size = len(response_obj.content) # Size in bytes

        message = f"API call to '{full_url}' successful (Status: {response_obj.status_code})."
        try:
            response_data = response_obj.json()
        except requests.exceptions.JSONDecodeError:
            response_data = response_obj.text # If not JSON, return raw text

        return True, message, response_content_size, response_data
    except requests.exceptions.RequestException as e:
        return False, f"API call failed: {e}", 0, None

def run_scheduled_job(job_id):
    """
    Function executed by the scheduler for a specific job.
    """
    job_details = st.session_state.schedules.get(job_id)
    if not job_details:
        st.error(f"Scheduled job '{job_id}' not found. Cannot execute.")
        return

    st.info(f"Executing scheduled job: **{job_details['name']}** at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    connection_name = job_details['connection_name']
    connection_type = st.session_state.connections[connection_name]['type']
    
    success = False
    message = ""
    volume_bytes = 0

    try:
        if connection_type == 'SFTP':
            success, message, volume_bytes = execute_sftp_transfer(
                connection_name,
                job_details['source_path'],
                job_details['destination_path'],
                job_details['transfer_type']
            )
        elif connection_type == 'API':
            # Parse payload and headers from stored string format
            api_payload = json.loads(job_details.get('api_payload', '{}'))
            api_headers = json.loads(job_details.get('api_headers', '{}'))

            success, message, volume_bytes, _ = execute_api_call(
                connection_name,
                job_details['api_endpoint'],
                job_details['api_method'],
                headers=api_headers,
                payload=api_payload
            )
        else:
            message = f"Unsupported connection type for scheduled job: {connection_type}"
    except Exception as e:
        message = f"An unexpected error occurred during job execution: {e}"

    # Update connection health based on job execution
    update_connection_health(connection_name, success, message, volume_bytes)

    if success:
        st.success(f"Scheduled job '{job_details['name']}' completed successfully.")
    else:
        st.error(f"Scheduled job '{job_details['name']}' failed: {message}")

def update_connection_health(connection_name, success, message="No issues.", volume_bytes=0):
    """
    Updates the health status of a connection.
    Includes placeholder for volume and frequency tracking.
    """
    current_health = st.session_state.connection_health.get(connection_name, {})
    
    if success:
        status = 'Green'
        issues = 'None'
    else:
        status = 'Red'
        issues = message # Use the error message as the issue

    # Update volume and frequency (very basic tracking for demo)
    # In a real app, you'd aggregate this data over time
    current_volume_size = current_health.get('volume_size', 0) + volume_bytes
    current_volume_frequency = current_health.get('volume_frequency', 0) + (1 if success else 0)

    st.session_state.connection_health[connection_name] = {
        'status': status,
        'last_checked': datetime.now(),
        'issues': issues,
        'volume_size': current_volume_size, # Total cumulative volume
        'volume_frequency': current_volume_frequency # Total cumulative successful operations
    }

# --- Scheduling Thread ---
# IMPORTANT: This in-app scheduler is for demonstration only.
# For production, use a dedicated external scheduler like Celery, Airflow, or cron.
def run_scheduler():
    """
    Runs the 'schedule' library in a separate thread.
    """
    while True:
        schedule.run_pending()
        time.sleep(1) # Check every second for pending jobs

# Start the scheduler in a separate thread if it's not already running
# The 'daemon=True' ensures the thread exits when the main program exits.
if 'scheduler_thread' not in st.session_state:
    st.session_state.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    st.session_state.scheduler_thread.start()


# --- Streamlit UI Layout ---

st.set_page_config(layout="wide", page_title="Reporting Tool Connector")
st.title("Reporting Tool Connector & Data Hub")

# --- Navigation using tabs ---
tab1, tab2, tab3 = st.tabs(["Connections Setup", "Scheduling & Workflows", "Dashboard"])

# --- Connections Setup Page ---
with tab1:
    st.header("Setup New Connection")

    connection_type = st.radio("Connection Type", ["Local Drive", "SFTP", "API"], key="conn_type_radio")

    with st.form("new_connection_form"):
        connection_name = st.text_input("Connection Name", help="A unique name for this connection", key="conn_name_input")

        if connection_type == "Local Drive":
            st.info("Local Drive connections are typically handled by directly accessing files within the app's environment or using `st.file_uploader` for user-uploaded files. This field is for tracking purposes.")
            local_path = st.text_input("Local Folder Path (e.g., /path/to/reports)", help="This is the path on the server where the Streamlit app is running.", key="local_path_input")
            submitted = st.form_submit_button("Save Local Connection")
            if submitted:
                if connection_name and local_path:
                    save_connection(connection_name, {'type': connection_type, 'path': local_path})
                    update_connection_health(connection_name, True, "Local connection path noted.")
                else:
                    st.error("Please provide a connection name and local path.")

        elif connection_type == "SFTP":
            sftp_hostname = st.text_input("SFTP Hostname", key="sftp_hostname_input")
            sftp_port = st.number_input("SFTP Port", value=22, min_value=1, max_value=65535, key="sftp_port_input")
            sftp_username = st.text_input("SFTP Username", key="sftp_username_input")
            sftp_password = st.text_input("SFTP Password", type="password", key="sftp_password_input")
            submitted = st.form_submit_button("Save SFTP Connection")
            if submitted:
                if connection_name and sftp_hostname and sftp_username and sftp_password:
                    st.info("Attempting to test SFTP connection...")
                    success, message = test_sftp_connection(sftp_hostname, sftp_port, sftp_username, sftp_password)
                    if success:
                        save_connection(connection_name, {
                            'type': connection_type,
                            'hostname': sftp_hostname,
                            'port': sftp_port,
                            'username': sftp_username,
                            'password': sftp_password # Store for re-testing/use, but highlight security warning
                        })
                        update_connection_health(connection_name, True)
                        st.success(f"SFTP Connection '{connection_name}' saved and tested successfully.")
                    else:
                        st.error(f"Failed to connect to SFTP: {message}")
                        update_connection_health(connection_name, False, message)
                else:
                    st.error("Please fill all SFTP connection details.")

        elif connection_type == "API":
            api_base_url = st.text_input("API Base URL (e.g., https://api.example.com/v1)", key="api_base_url_input")
            # For simplicity, we'll omit complex auth methods for basic testing, focusing on headers
            api_headers_raw = st.text_area("Custom Headers (JSON format)", '{}', help="e.g., {'Content-Type': 'application/json', 'Authorization': 'Bearer YOUR_TOKEN'}", key="api_headers_input")
            
            submitted = st.form_submit_button("Save API Connection")
            if submitted:
                if connection_name and api_base_url:
                    try:
                        headers = json.loads(api_headers_raw)
                    except json.JSONDecodeError:
                        st.error("Invalid JSON format for custom headers. Please correct it.")
                        headers = {} # Set to empty dict to avoid further errors

                    st.info("Attempting to test API connection...")
                    # Use a GET method for testing connection, unless user specifies otherwise for a quick test
                    success, message_or_data = test_api_connection(api_base_url, headers=headers, method='GET')
                    if success:
                        save_connection(connection_name, {
                            'type': connection_type,
                            'base_url': api_base_url,
                            'headers': headers
                        })
                        update_connection_health(connection_name, True)
                        st.success(f"API Connection '{connection_name}' saved and tested successfully.")
                    else:
                        st.error(f"Failed to connect to API: {message_or_data}")
                        update_connection_health(connection_name, False, message_or_data)
                else:
                    st.error("Please provide a connection name and API Base URL.")

    st.subheader("Existing Connections")
    if st.session_state.connections:
        connections_df = pd.DataFrame([
            {'Name': name, 'Type': details['type'], 'Details': str(details)}
            for name, details in st.session_state.connections.items()
        ])
        st.dataframe(connections_df, use_container_width=True)
    else:
        st.info("No connections configured yet.")

# --- Scheduling & Workflows Page ---
with tab2:
    st.header("Setup Scheduling and Workflows")

    if not st.session_state.connections:
        st.warning("Please set up connections first in the 'Connections Setup' tab.")
    else:
        with st.form("new_schedule_form"):
            schedule_name = st.text_input("Schedule Name", help="A unique name for this scheduled task", key="schedule_name_input")
            
            available_connections = list(st.session_state.connections.keys())
            selected_connection = st.selectbox("Select Connection", available_connections, key="selected_connection_schedule")

            connection_details_for_schedule = st.session_state.connections.get(selected_connection, {})
            
            if connection_details_for_schedule.get('type') == 'SFTP':
                sftp_transfer_type = st.radio("SFTP Transfer Type", ["Upload", "Download"], key="sftp_transfer_type_radio")
                sftp_source_path = st.text_input("Source Path (Local/SFTP)", help="Path on the local machine for upload, or SFTP server for download", key="sftp_source_path_input")
                sftp_destination_path = st.text_input("Destination Path (SFTP/Local)", help="Path on the SFTP server for upload, or local machine for download", key="sftp_destination_path_input")
                
                schedule_interval = st.selectbox("Schedule Interval", ["Every Minute (for testing)", "Hourly", "Daily", "Weekly", "Custom (Cron)"], key="schedule_interval_sftp")
                cron_string = ""
                if schedule_interval == "Custom (Cron)":
                    cron_string = st.text_input("Cron String (e.g., 0 * * * *)", help="Learn more about cron strings: crontab.guru", key="cron_string_sftp_input")

                submitted = st.form_submit_button("Create SFTP Schedule")
                if submitted:
                    if schedule_name and sftp_source_path and sftp_destination_path:
                        st.session_state.schedules[schedule_name] = {
                            'name': schedule_name,
                            'connection_name': selected_connection,
                            'type': 'SFTP',
                            'transfer_type': sftp_transfer_type.lower(),
                            'source_path': sftp_source_path,
                            'destination_path': sftp_destination_path,
                            'interval_type': schedule_interval,
                            'cron_string': cron_string
                        }
                        
                        # Add job to the simple 'schedule' library
                        if schedule_interval == "Every Minute (for testing)":
                            schedule.every(1).minute.do(run_scheduled_job, schedule_name)
                            st.warning("Scheduled to run every minute for testing. Be mindful of resource usage!")
                        elif schedule_interval == "Hourly":
                            schedule.every().hour.do(run_scheduled_job, schedule_name)
                        elif schedule_interval == "Daily":
                            schedule.every().day.do(run_scheduled_job, schedule_name)
                        elif schedule_interval == "Weekly":
                            schedule.every().week.do(run_scheduled_job, schedule_name)
                        elif schedule_interval == "Custom (Cron)" and cron_string:
                            # Note: The 'schedule' library is not a full cron parser.
                            # For true cron, an external scheduler is required.
                            st.warning("Custom cron scheduling for this in-app scheduler is a placeholder. You would need a separate backend for full cron support.")
                            # You could parse and add specific time-based schedules here if needed for specific cron strings.
                            # Example: schedule.every().day.at("10:30").do(run_scheduled_job, schedule_name)
                        
                        st.success(f"SFTP Schedule '{schedule_name}' created.")
                    else:
                        st.error("Please fill all SFTP schedule details.")

            elif connection_details_for_schedule.get('type') == 'API':
                api_endpoint = st.text_input("API Endpoint (e.g., /data/reports)", help="Relative path to the base URL", key="api_endpoint_input")
                api_method = st.selectbox("HTTP Method", ["GET", "POST", "PUT", "DELETE"], key="api_method_select")
                api_payload_raw = st.text_area("Request Body (JSON format, for POST/PUT)", '{}', help="e.g., {'report_id': 123, 'status': 'completed'}", key="api_payload_input")
                api_headers_for_call_raw = st.text_area("Custom Headers for API Call (JSON format, overrides connection headers)", '{}', help="e.g., {'X-Custom-Header': 'value'}", key="api_headers_call_input")

                schedule_interval = st.selectbox("Schedule Interval", ["Every Minute (for testing)", "Hourly", "Daily", "Weekly", "Custom (Cron)"], key="schedule_interval_api")
                cron_string = ""
                if schedule_interval == "Custom (Cron)":
                    cron_string = st.text_input("Cron String (e.g., 0 * * * *)", key="cron_string_api_input")

                submitted = st.form_submit_button("Create API Schedule")
                if submitted:
                    if schedule_name and api_endpoint:
                        try:
                            json.loads(api_payload_raw) # Validate JSON
                            json.loads(api_headers_for_call_raw) # Validate JSON
                        except json.JSONDecodeError:
                            st.error("Invalid JSON format for API payload or headers. Please correct it.")
                            # Exit early if JSON is invalid
                            st.stop() # Stops execution on current rerun to prevent further errors
                        
                        st.session_state.schedules[schedule_name] = {
                            'name': schedule_name,
                            'connection_name': selected_connection,
                            'type': 'API',
                            'api_endpoint': api_endpoint,
                            'api_method': api_method,
                            'api_payload': api_payload_raw, # Store as string to avoid issues with session state
                            'api_headers': api_headers_for_call_raw, # Store as string
                            'interval_type': schedule_interval,
                            'cron_string': cron_string
                        }

                        # Add job to the simple 'schedule' library
                        if schedule_interval == "Every Minute (for testing)":
                            schedule.every(1).minute.do(run_scheduled_job, schedule_name)
                            st.warning("Scheduled to run every minute for testing. Be mindful of resource usage!")
                        elif schedule_interval == "Hourly":
                            schedule.every().hour.do(run_scheduled_job, schedule_name)
                        elif schedule_interval == "Daily":
                            schedule.every().day.do(run_scheduled_job, schedule_name)
                        elif schedule_interval == "Weekly":
                            schedule.every().week.do(run_scheduled_job, schedule_name)
                        elif schedule_interval == "Custom (Cron)" and cron_string:
                            st.warning("Custom cron scheduling for this in-app scheduler is a placeholder. You would need a separate backend for full cron support.")
                        
                        st.success(f"API Schedule '{schedule_name}' created.")
                    else:
                        st.error("Please fill all API schedule details.")

        st.subheader("Configured Schedules")
        if st.session_state.schedules:
            schedules_data = []
            for name, details in st.session_state.schedules.items():
                schedules_data.append({
                    'Name': name,
                    'Connection': details['connection_name'],
                    'Type': details['type'],
                    'Interval': details['interval_type'],
                    'Last Run Status': st.session_state.connection_health.get(details['connection_name'], {}).get('status', 'N/A')
                })
            schedules_df = pd.DataFrame(schedules_data)
            st.dataframe(schedules_df, use_container_width=True)
        else:
            st.info("No schedules configured yet.")

# --- Dashboard Page ---
with tab3:
    st.header("Connection Dashboard")

    if not st.session_state.connections:
        st.info("No connections to display. Please set up connections first.")
    else:
        col1, col2, col3 = st.columns(3)

        total_connections = len(st.session_state.connections)
        active_connections = sum(1 for health_info in st.session_state.connection_health.values() if health_info.get('status') == 'Green')
        issues_connections = sum(1 for health_info in st.session_state.connection_health.values() if health_info.get('status') == 'Red' or health_info.get('status') == 'Amber')
        unknown_connections = total_connections - active_connections - issues_connections

        with col1:
            st.metric("Total Connections", total_connections)
        with col2:
            st.metric("Active (Green)", active_connections, delta=None, delta_color="normal")
        with col3:
            st.metric("Issues (Red/Amber)", issues_connections, delta=None, delta_color="inverse")

        st.subheader("Connection Details and Health Status")

        display_data = []
        for name, details in st.session_state.connections.items():
            health_info = st.session_state.connection_health.get(name, {'status': 'Unknown', 'last_checked': 'N/A', 'issues': 'Not yet checked.', 'volume_size': 0, 'volume_frequency': 0})
            
            status_color = "green" if health_info['status'] == 'Green' else ("red" if health_info['status'] == 'Red' else "orange")
            
            display_data.append({
                'Connection Name': name,
                'Type': details['type'],
                'Health Status': f":{status_color}[{health_info['status']}]", # Using Streamlit's colored text
                'Last Checked': health_info['last_checked'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(health_info['last_checked'], datetime) else health_info['last_checked'],
                'Issues / Notes': health_info.get('issues', 'None'),
                'Volume (Size)': f"{health_info['volume_size'] / (1024*1024):.2f} MB" if health_info['volume_size'] > 0 else "0 MB",
                'Volume (Frequency)': f"{health_info['volume_frequency']} operations"
            })
        
        connections_status_df = pd.DataFrame(display_data)
        st.dataframe(connections_status_df, use_container_width=True, hide_index=True)

        st.subheader("Connections Needing Review or with Issues")
        issues_df = connections_status_df[
            (connections_status_df['Health Status'].str.contains('red', case=False)) |
            (connections_status_df['Health Status'].str.contains('orange', case=False)) |
            (connections_status_df['Health Status'].str.contains('Unknown', case=False))
        ]
        if not issues_df.empty:
            st.dataframe(issues_df, use_container_width=True, hide_index=True)
        else:
            st.info("All connections currently appear healthy or have been reviewed.")

        st.subheader("Data Volume Visualization (Sample)")
        # Sample data for charting; replace with actual tracked data
        if st.session_state.connection_health:
            volume_chart_data = []
            for conn_name, health_info in st.session_state.connection_health.items():
                volume_chart_data.append({
                    'Connection': conn_name,
                    'Volume (MB)': health_info.get('volume_size', 0) / (1024*1024),
                    'Frequency': health_info.get('volume_frequency', 0)
                })
            volume_chart_df = pd.DataFrame(volume_chart_data).set_index('Connection')

            if not volume_chart_df.empty:
                st.write("Volume by Connection (MB)")
                st.bar_chart(volume_chart_df[['Volume (MB)']])
                st.write("Frequency by Connection (Operations)")
                st.bar_chart(volume_chart_df[['Frequency']])
            else:
                st.info("No volume data available yet.")
        else:
             st.info("No volume data available yet.")


# --- Feature: Show App Code ---
st.markdown("---")
st.header('App Source Code', divider='gray')

current_script_path = Path(__file__)

try:
    with open(current_script_path, 'r') as f:
        app_code = f.read()
    with st.expander("Click to view the Python code for this app"):
        st.code(app_code, language='python')
except Exception as e:
    st.error(f"Could not load app source code: {e}")
