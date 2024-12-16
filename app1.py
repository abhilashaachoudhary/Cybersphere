import streamlit as st
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from ipaddress import ip_address
import requests
import pathlib
import matplotlib.pyplot as plt
import seaborn as sns
from groq import Groq



# Add a slider to the sidebar:

def load_css(file_path):
    with open(file_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Load the external CSS
css_path = pathlib.Path("styles.css")
load_css(css_path)

st.markdown(
     '<h class="custom-markdown"><strong>CyberSphere</strong></h>',
    unsafe_allow_html=True,
)
st.write(
    '<div class="custom-tagline">Maximizing Network Efficiency, Minimizing Risk!</div>',
    unsafe_allow_html=True
)

def get_country_name(country_code):
    try:
        return pycountry.countries.get(alpha_2=country_code).name
    except AttributeError:
        return "Unknown"

# Function to query VirusTotal API for public IPs
def check_ip_with_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            country_code = data.get('data', {}).get('attributes', {}).get('country', 'Unknown')
            country = get_country_name(country_code)
            return malicious_count, country
        else:
            return f"Error {response.status_code}", "Unknown"
    except Exception as e:
        return f"Error: {e}", "Unknown"

# Function to check if an IP is private
def is_private(ip):
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False

# Function to classify public IPs
def classify_ip(ip, api_key):
    if is_private(ip):
        return 'Private', None, None
    else:
        malicious_count, country = check_ip_with_virustotal(ip, api_key)
        try:
            malicious_count = int(malicious_count)
        except ValueError:
            malicious_count = 0
        classification = malicious_count if malicious_count > 0 else 'Malicious'
        return 'Public', classification, country

# Define a function to get IP details from VirusTotal (IP Address Analysis)
def get_ip_details(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        ip_score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        country = data.get("data", {}).get("attributes", {}).get("country", "Unknown")
        return ip_score, country
    else:
        return None, None


# Initialize Groq client
client = Groq(api_key="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") 


# Function to preprocess IP score and analyze it using Groq
def preprocess_ip_score_and_analyze_with_groq(ip_score, country):
    # Prepare the score summary for the prompt
    score_summary = [
        f"Harmless: {ip_score['harmless']}",
        f"Malicious: {ip_score['malicious']}",
        f"Suspicious: {ip_score['suspicious']}",
        f"Undetected: {ip_score['undetected']}",
        f"Timeout: {ip_score['timeout']}"
    ]
    score_summary_text = "\n".join(score_summary)

    # Prepare the refined prompt for Groq AI
    prompt = f"""
    Based on the VirusTotal analysis of the IP address, here are the findings:

    *IP Score Summary:*
    {score_summary_text}

    *Country:* {country}

    Analyze the provided data and provide a security assessment of this IP address. Specifically:

    1. *Harmless Entries*: If a high number of harmless results are found, it suggests the IP is likely to be safe.
    2. *Malicious Entries*: A high number of malicious results would indicate a high likelihood that this IP is a security risk.
    3. *Suspicious Entries*: A moderate number of suspicious results may require further investigation or monitoring.
    4. *Undetected Entries*: A significant number of undetected results may suggest that the IP address is not well-known or hasn't been flagged yet, warranting caution.
    5. *Timeout*: If there are timeout entries, this could indicate issues with connectivity or unreliable data.

    Based on these findings, provide a security assessment and conclude whether the IP is safe, suspicious, or malicious. Please provide a conclusion in plain text, and also suggest any next steps for investigating the security of this IP address.

    Return the conclusion in the following format:
    {{
      Security Assessment: <Your conclusion here> \n
      Recommendation: <Your recommendation here>
    }}
    """

    # Send the prompt to Groq AI and get the response
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-8b-8192",  # Use the appropriate model
    )

    # Return the response
    return chat_completion.choices[0].message.content


# Function to preprocess input data and analyze it using Groq
def preprocess_user_input_and_analyze_with_groq(org_details, threat_concerns, infrastructure, security_measures):
    # Prepare the summary for the prompt
    details_summary = f"""
    *Organization Details:*
    - Type: {org_details['type']}
    - Industry: {org_details['industry']}
    - Size: {org_details['size']}
    - Critical Assets: {org_details['critical_assets']}

    *Threat Concerns:* {', '.join(threat_concerns)}

    *IT Infrastructure:* {', '.join(infrastructure)}

    *Current Security Measures:* {', '.join(security_measures)}
    """

    # Refined prompt for Groq AI
    prompt = f"""
    Based on the provided organizational details and threat landscape, simulate a cybersecurity scenario. 

    Details:
    {details_summary}

    Simulate plausible attack scenarios, their step-by-step progression, and propose countermeasures. Include:
    1. Attack Scenarios: Simulate attacks such as phishing, ransomware, and insider threats tailored to the organization.
    2. Countermeasures: Provide strategies and tools to detect, mitigate, or prevent the simulated attacks.
    3. Incident Response Playbook: Outline a detailed guide for handling the simulated attacks.
    4. Compliance Mapping: Map security recommendations to regulatory frameworks like PCI DSS, GDPR, or HIPAA.

    Return the conclusion in the following format:
    {{
      "Simulated Attacks": [List of attack scenarios],
      "Countermeasures": [List of countermeasures],
      "Incident Response Playbook": [Playbook details],
      "Compliance Mapping": [Compliance details]
    }}
    """

    # Send the prompt to Groq AI and get the response
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-8b-8192",  # Replace with your desired Groq model
    )

    # Return the response
    return chat_completion.choices[0].message.content



import streamlit as st
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

# Initialize session state variables if they don't exist
if 'uploaded_file' not in st.session_state:
    st.session_state['uploaded_file'] = None

if 'data' not in st.session_state:
    st.session_state['data'] = None

# Sidebar for navigation between sections
# Add a heading for the sidebar
st.sidebar.markdown('<div class="sidebar-header">Pick Your Analysis</div>', unsafe_allow_html=True)

# Add the radio button menu
menu = st.sidebar.radio(
    "",
    ["Threat Detection", "Traffic Analysis", "Anomaly Detection", "Bandwidth Utilization","IP Address Analysis" ,"Clustering", "About Me"],
    key="sidebar"
)


if menu == "Threat Detection":
    st.title("Network Data Processing with VirusTotal Integration")

    # Step 1: File Upload
    uploaded_file = st.file_uploader("Upload your Excel file", type=["csv", "xlsx"])

    # Store the uploaded file in session state
    if uploaded_file is not None:
        st.session_state['uploaded_file'] = uploaded_file
        st.session_state['data'] = None  # Reset data when a new file is uploaded

    # Retrieve the uploaded file from session state
    uploaded_file = st.session_state.get('uploaded_file')

    # Check if there's an uploaded file in session state
    if uploaded_file is not None:
        # Step 2: Read the File
        file_extension = uploaded_file.name.split(".")[-1]
        if file_extension == "csv":
            data = pd.read_csv(uploaded_file)
        else:
            data = pd.read_excel(uploaded_file)

        # Save the data to session state to reuse in other sections
        st.session_state['data'] = data

        st.write("Uploaded Data:")
        st.dataframe(data.head())

        # Ensure column names match the dataset structure
        data.columns = ['avg_packet_size', 'number_of_connections', 'data_transferred',  'source_ip', 'destination_ip', 'event_timestamp']

        # Step 3: Clustering
        features = data[['number_of_connections', 'data_transferred', 'avg_packet_size']]
        kmeans = KMeans(n_clusters=3, random_state=42)
        data['cluster'] = kmeans.fit_predict(features)

        # Step 4: Anomaly Detection
        iso_forest = IsolationForest(random_state=42)
        data['anomaly'] = iso_forest.fit_predict(features)
        data['anomaly'] = data['anomaly'].map({1: 'Normal', -1: 'Anomalous'})

        # Step 5: IP Classification

        api_key = "f353d9b08b3c7cb743595b0"  # Replace with your VirusTotal API Key
        source_classifications, source_malicious_scores, source_countries = [], [], []
        dest_classifications, dest_malicious_scores, dest_countries = [], [], []

        for ip in data['source_ip']:
            classification, malicious_score, country = classify_ip(ip, api_key)
            source_classifications.append(classification)
            source_malicious_scores.append(malicious_score)
            source_countries.append(country)

        for ip in data['destination_ip']:
            classification, malicious_score, country = classify_ip(ip, api_key)
            dest_classifications.append(classification)
            dest_malicious_scores.append(malicious_score)
            dest_countries.append(country)

        data['source_ip_classification'] = source_classifications
        data['source_ip_malicious_score'] = source_malicious_scores
        #data['source_ip_country'] = source_countries

        data['destination_ip_classification'] = dest_classifications
        data['destination_ip_malicious_score'] = dest_malicious_scores
        #data['destination_ip_country'] = dest_countries

        # Display the Processed Data
        st.write("Processed Data:")
        st.dataframe(data)

        # Step 6: File Download
        output_file = 'processed_network_data_with_malicious_ips.csv'
        st.download_button(
            label="Download Processed File",
            data=data.to_csv(index=False).encode('utf-8'),
            file_name=output_file,
            mime='text/csv'
        )
    else:
        st.write("No file uploaded. Please upload a file to proceed.")

elif menu == "Traffic Analysis":
    st.title("Traffic Analysis")

    # Check if the file is uploaded and data exists in session_state
    if st.session_state['data'] is not None:
        data = st.session_state['data']

        st.write("Processed Data from Section 1:")
        st.dataframe(data)

        # Dropdown to select numeric columns for visualization
        numeric_columns = data.select_dtypes(include=['int64', 'float64']).columns.tolist()
        if numeric_columns:
            selected_column = st.selectbox("Select a numeric column for visualization:", numeric_columns)

            if selected_column:
                st.subheader(f"Visualization for '{selected_column}'")

                # Histogram
                st.write("Histogram:")
                fig, ax = plt.subplots()
                sns.histplot(data[selected_column], kde=True, ax=ax, bins=30, color="blue")
                ax.set_title(f"Histogram of {selected_column}")
                st.pyplot(fig)

                # Boxplot
                st.write("Boxplot:")
                fig, ax = plt.subplots()
                sns.boxplot(data=data, y=selected_column, ax=ax, color="orange")
                ax.set_title(f"Boxplot of {selected_column}")
                st.pyplot(fig)

        # Pairplot for numeric columns
        if len(numeric_columns) > 1:
            st.write("Pairplot:")
            fig = sns.pairplot(data[numeric_columns])
            st.pyplot(fig)

        # Correlation Heatmap
        st.write("Correlation Heatmap:")
        correlation_matrix = data[numeric_columns].corr()
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.heatmap(correlation_matrix, annot=True, fmt=".2f", cmap="coolwarm", ax=ax)
        ax.set_title("Correlation Heatmap")
        st.pyplot(fig)

        # Scatter Plot
        st.write("Scatter Plot:")
        scatter_x = st.selectbox("Select X-axis for scatter plot:", numeric_columns, key="scatter_x")
        scatter_y = st.selectbox("Select Y-axis for scatter plot:", numeric_columns, key="scatter_y")

        if scatter_x and scatter_y:
            fig, ax = plt.subplots()
            sns.scatterplot(data=data, x=scatter_x, y=scatter_y, hue="cluster" if "cluster" in data.columns else None, ax=ax)
            ax.set_title(f"Scatter Plot: {scatter_x} vs {scatter_y}")
            st.pyplot(fig)



    else:
        st.write("No data available. Please upload a file in Section 1.")

elif menu == "Anomaly Detection":
    st.title("Anomaly Detection")

    # Check if data exists in session state
    # Check if data exists in session state
    # Check if data exists in session state
    if st.session_state['data'] is not None:
        data = st.session_state['data']

        # Show the data before anomaly detection
        st.write("Data Before Anomaly Detection:")
        st.dataframe(data.head())

        # Step 1: Prepare the data for anomaly detection
        # Select the columns relevant for anomaly detection (you can modify this based on your data)
        features = data[['number_of_connections', 'data_transferred', 'avg_packet_size']]

        # Step 2: Initialize the Isolation Forest model without specifying contamination
        model = IsolationForest(random_state=42)  # No contamination specified

        # Step 3: Fit the model and predict anomalies
        model.fit(features)
        data['anomaly'] = model.predict(features)

        # Step 4: Map anomaly results to more understandable labels (1 = normal, -1 = anomalous)
        data['anomaly'] = data['anomaly'].map({1: 'Normal', -1: 'Anomalous'})

        # Display results
        st.write("Processed Data with Anomaly Detection:")
        st.dataframe(data)

        # Step 5: Show the statistics of anomalies detected
        anomaly_count = data['anomaly'].value_counts()
        st.write("Anomaly Detection Summary:")
        st.write(f"Total Normal Data Points: {anomaly_count['Normal']}")
        st.write(f"Total Anomalous Data Points: {anomaly_count['Anomalous']}")

        # Step 6: Display Anomalous data points and their isolation path lengths
        # The Isolation Forest model has the decision_function method that gives the anomaly score (path length)
        anomaly_scores = model.decision_function(features)

        # Add the scores to the data
        data['anomaly_score'] = anomaly_scores

        # Sort the data by anomaly scores in ascending order (lower score = more anomalous)
        sorted_data = data.sort_values(by='anomaly_score', ascending=True)

        # Show top 5 anomalies
        st.write("Top 5 Anomalous Data Points (Lowest Anomaly Scores):")
        st.dataframe(sorted_data.head())

        # Step 7: Plot the anomaly scores to visualize the severity of anomalies
        plt.figure(figsize=(12, 8))
        plt.hist(anomaly_scores, bins=50, color='#FFBD73', alpha=0.8, edgecolor='black', linewidth=0.7)
        plt.axvline(x=0, color='#FF4500', linestyle='--', linewidth=2, label="Threshold")
        plt.title('Anomaly Scores Distribution', fontsize=18, fontweight='bold', color='#C4E1F6')
        plt.xlabel('Anomaly Score', fontsize=14, fontweight='bold', color='#C4E1F6')
        plt.ylabel('Frequency', fontsize=14, fontweight='bold', color='#C4E1F6')
        plt.xticks(fontsize=12, color='#ffffff')
        plt.yticks(fontsize=12, color='#ffffff')
        plt.grid(color='yellow', linestyle=':', linewidth=0.5, alpha=0.7)
        plt.legend(fontsize=12, loc='upper right', frameon=True, fancybox=True, framealpha=0.8, edgecolor='gray')
        plt.tight_layout()

        # Annotate the threshold line for clarity
        threshold_y = plt.gca().get_ylim()[1] * 0.9  # Set annotation height near the top
        plt.text(0, threshold_y, 'Threshold', color='#FF4500', fontsize=12, ha='center', va='bottom')

        st.pyplot(plt)

        # Step 8: Provide an option to download the processed file with anomaly labels and scores
        output_file = 'network_data_with_anomalies.csv'
        st.download_button(
            label="Download Processed Data with Anomalies",
            data=data.to_csv(index=False).encode('utf-8'),
            file_name=output_file,
            mime='text/csv'
        )
    else:
        st.write("No data available. Please upload a file in Section 1.")

elif menu == "Bandwidth Utilization":
    st.title("Bandwidth Utilization")

    # Check if the file is uploaded and data exists in session_state
    if st.session_state['data'] is not None:
        data = st.session_state['data']

        # Display the top 5 rows with the highest number of connections
        st.subheader("Top 5 Rows with Highest Number of Connections")
        top_num_connections = data.nlargest(5, 'number_of_connections')
        st.dataframe(top_num_connections)

        # Display the top 5 rows with the highest data transferred
        st.subheader("Top 5 Rows with Highest Data Transferred (MB)")
        top_data_transferred = data.nlargest(5, 'data_transferred')
        st.dataframe(top_data_transferred)

        # Display top 5 source IPs with the highest number of connections
        st.subheader("Top 5 Source IPs by Number of Connections")
        top_source_ips_num_connections = (
            data.groupby('source_ip')['number_of_connections']
            .sum()
            .nlargest(5)
            .reset_index()
        )
        st.dataframe(top_source_ips_num_connections.rename(columns={
            'source_ip': 'Source IP',
            'number_of_connections': 'Total Number of Connections'
        }))

        # Display top 5 source IPs with the highest data transferred
        st.subheader("Top 5 Source IPs by Data Transferred (MB)")
        top_source_ips_data_transferred = (
            data.groupby('source_ip')['data_transferred']
            .sum()
            .nlargest(5)
            .reset_index()
        )
        st.dataframe(top_source_ips_data_transferred.rename(columns={
            'source_ip': 'Source IP',
            'data_transferred': 'Total Data Transferred (MB)'
        }))

        # Analyze Packet Size Efficiency
        st.subheader("Packet Size Efficiency")
        avg_packet_size_threshold = 512  # Define a threshold for inefficient packet size
        inefficient_packets = data[data['avg_packet_size'] < avg_packet_size_threshold]
        total_inefficient = len(inefficient_packets)
        st.write(f"Total rows with inefficient packet sizes (< {avg_packet_size_threshold} bytes): {total_inefficient}")
        st.write("Sample Rows with Inefficient Packet Sizes:")
        st.dataframe(inefficient_packets.head(5))

    else:
        st.write("No data available. Please upload a file in Section 1.")


elif menu == "IP Address Analysis":
    st.title("IP Address Analysis")

    # Input for VirusTotal API key
    api_key = st.text_input("Enter your VirusTotal API Key:", type="password")

    # Input for IP address
    ip_address = st.text_input("Enter an IP Address:")

    if st.button("Analyze IP"):
        if not api_key:
            st.error("Please enter a valid VirusTotal API key.")
        elif not ip_address:
            st.error("Please enter an IP address.")
        else:
            with st.spinner("Fetching IP details..."):
                ip_score, country = get_ip_details(ip_address, api_key)

            if ip_score is not None:
                st.success("IP Analysis Complete!")
                st.markdown(f'<p class="ip-address">IP Address: {ip_address}</p>', unsafe_allow_html=True)
                st.markdown(f'<p class="country-box">Country: {country}</p>', unsafe_allow_html=True)

                # Convert IP score to a DataFrame for a clean table display
                ip_score_df = pd.DataFrame.from_dict(ip_score, orient='index', columns=['Count'])
                ip_score_df.index.name = 'Analysis Type'
                st.table(ip_score_df)

                # Convert to HTML and apply the custom dark table class
                #html_table = ip_score_df.to_html(classes='dark-table', escape=False)
                # Display the HTML table with the dark theme styling
                #st.markdown(html_table, unsafe_allow_html=True)


                # Use Groq model to analyze and generate security assessment
                result = preprocess_ip_score_and_analyze_with_groq(ip_score, country)

                # Display Groq result (security assessment and recommendation)
                # Display Groq result (security assessment and recommendation) with styling
                st.markdown('<p class="security-assessment">Security Assessment:</p>', unsafe_allow_html=True)
                st.markdown(f'<div class="assessment-text">{result.split("Recommendation:")[0]}</div>',unsafe_allow_html=True)

                st.markdown('<p class="recommendation-header">Recommendation:</p>', unsafe_allow_html=True)
                st.markdown(f'<div class="recommendation-text">{result.split("Recommendation:")[1]}</div>',unsafe_allow_html=True)

            else:
                st.error("Failed to fetch IP details. Please check the IP address and API key.")

elif menu == "Clustering":
    st.title("Clustering Data into 3 Groups")

    # Check if data exists in session state
    if st.session_state.get('data') is not None:
        data = st.session_state['data']

        # Show the data before clustering
        st.write("Data Before Clustering:")
        st.dataframe(data.head())

        # Step 1: Prepare the data for clustering
        # Select features for clustering
        features = data[['number_of_connections', 'data_transferred', 'avg_packet_size']]

        # Step 2: Initialize and fit the KMeans model
        kmeans = KMeans(n_clusters=3, random_state=42)
        clusters = kmeans.fit_predict(features)

        # Step 3: Add cluster labels to the data
        data['Cluster'] = clusters

        # Display the clustered data
        st.write("Data After Clustering:")
        st.dataframe(data)

        # Step 4: Visualize the clusters
        st.write("### Cluster Visualization (2D Plot):")
        plt.figure(figsize=(12, 8))

        # Improved scatter plot with enhancements
        scatter = plt.scatter(
            data['data_transferred'],
            data['number_of_connections'],
            c=data['Cluster'],
            cmap='coolwarm',
            s=100,  # Larger marker size
            edgecolors='black',  # Add borders to markers
            linewidth=0.7,  # Border thickness
            alpha=0.8  # Slight transparency for better visibility
        )

        # Adding labels, grid, and title
        plt.title('Clustering of Data', fontsize=18, fontweight='bold', color='#FFD700')
        plt.xlabel('Data Transferred (MB)', fontsize=14, color='#FFFFFF')
        plt.ylabel('Number of Connections', fontsize=14, color='#FFFFFF')
        plt.grid(color='#444444', linestyle='--', linewidth=0.5)  # Subtle grid lines for reference

        # Adding colorbar
        cbar = plt.colorbar(scatter, label='Cluster')
        cbar.ax.tick_params(labelsize=12, colors='white')  # Styling colorbar

        # Customizing plot aesthetics for dark mode
        plt.gca().set_facecolor('#1E1E2F')  # Set background for the plot
        plt.gcf().set_facecolor('#29293D')  # Set background for the figure
        plt.tick_params(colors='white', which='both')  # Change axis tick colors

        st.pyplot(plt)

        # Step 5: Show cluster centroids
        centroids = kmeans.cluster_centers_
        st.write("Cluster Centroids:")
        centroids_df = pd.DataFrame(centroids, columns=['Number of Connections', 'Data Transferred', 'Avg Packet Size'])
        st.dataframe(centroids_df)

        # Display tables for each cluster
        st.write("Data Tables for Each Cluster:")
        for cluster_id in sorted(data['Cluster'].unique()):
            st.write(f"Cluster {cluster_id} Data:")
            st.dataframe(data[data['Cluster'] == cluster_id])

        # Step 6: Provide an option to download the clustered data
        output_file = 'network_data_with_clusters.csv'
        st.download_button(
            label="Download Clustered Data",
            data=data.to_csv(index=False).encode('utf-8'),
            file_name=output_file,
            mime='text/csv'
        )
    else:
        st.write("No data available. Please upload a file in Section 1.")

elif menu == "About Me":
    # Title of the Section
    st.title("About Me")

    # User Profile
    st.markdown("""
        <div class="profile-card">
            <h2 class="profile-name">Abhilasha Choudhary</h2>
            <p class="profile-description">I am a passionate Cyber Security Specialist, currently pursuing my studies at National Forensic Science University.</p>
            <p class="profile-description">My primary interest lies in the field of cyber security, where I aim to contribute to enhancing digital safety and solving security challenges.</p>
        </div>
    """, unsafe_allow_html=True)

    # Education Info
    st.markdown("""
        <div class="education-card">
            <h3 class="education-title">Education</h3>
            <p><strong>College:</strong> National Forensic Science University</p>
            <p><strong>Specialization:</strong> Cyber Security</p>
        </div>
    """, unsafe_allow_html=True)

    # About My Journey
    st.markdown("""
        <div class="journey-card">
            <h3 class="journey-title">About My Journey</h3>
            <p class="journey-description">
                My journey in the world of cyber security began with a curiosity for how digital systems are secured and protected against evolving threats.
                I am excited about exploring various aspects of cyber security such as threat detection, risk management, and digital forensics.
                My goal is to continue learning and working on innovative solutions that can help protect sensitive data and critical infrastructures.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Add a personal image (optional)
    #st.image("path_to_your_image.jpg", caption="Abhilasha Choudhary", use_column_width=True)

    # Optional: Add contact information or social media links
    st.markdown('<h2 class="connect-title">Connect with Me</h2>', unsafe_allow_html=True)
    st.write("Feel free to reach out or connect on LinkedIn or other platforms.")

    st.markdown(
        '<div class="contact-card"><p class="contact-link"><strong>LinkedIn:</strong> <a href="https://www.linkedin.com/in/abhilasha-choudhary-b71208195?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app" target="_blank">Abhilasha Choudhary</a></p></div>',
        unsafe_allow_html=True)
    st.markdown(
        '<div class="contact-card"><p class="contact-link"><strong>Email:</strong> <a href="mailto:adchaudhary27@gmail.com">adchaudhary27@gmail.com</a></p></div>',
        unsafe_allow_html=True)
    st.markdown(
        '<div class="contact-card"><p class="contact-link"><strong>Blog:</strong> <a href="https://woorkk.wixsite.com/website" target="_blank">My work</a></p></div>',
        unsafe_allow_html=True)

