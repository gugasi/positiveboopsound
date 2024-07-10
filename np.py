import csv
import pandas as pd

# Define the file path
file_path = "/home/liveuser/shared/Product _Reference System - Rel5_- Authenticated Nessus_scan n05052824.csv"

# Read the CSV file into a pandas DataFrame
df = pd.read_csv(file_path)

# Drop rows with missing Plugin ID, CVE, and CVSS
df.dropna(subset=['Plugin ID', 'CVE', 'CVSS'], inplace=True)

# Function to categorize risks
def categorize_risk(risk):
    risk_levels = {
        'None': 0,
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 4
    }
    return risk_levels.get(risk, -1)

# Add a numerical risk level column for sorting
df['Risk Level'] = df['Risk'].apply(categorize_risk)

# Group by Host and sort by Risk Level and CVSS within each group
grouped_df = df.groupby('Host').apply(lambda x: x.sort_values(by=['Risk Level', 'CVSS'], ascending=[False, False]))

# Function to format and display vulnerabilities
def display_vulnerabilities(df):
    for host, group in df.groupby('Host'):
        print(f"Host: {host}")
        for _, row in group.iterrows():
            print(f"\nPlugin ID: {row['Plugin ID']}")
            print(f"Name: {row['Name']}")
            print(f"Risk: {row['Risk']}")
            print(f"CVSS: {row['CVSS']}")
            print(f"Description: {row['Description']}")
            print(f"Solution: {row['Solution']}")
            print(f"CVE: {row['CVE']}")
            print(f"Protocol: {row['Protocol']}")
            print(f"Port: {row['Port']}")
            print(f"Plugin Output: {row['Plugin Output']}")
            print(f"STIG Severity: {row['STIG Severity']}")
            print(f"Plugin Publication Date: {row['Plugin Publication Date']}")
            print(f"Plugin Modification Date: {row['Plugin Modification Date']}")
            print(f"Metasploit: {row['Metasploit']}")
            print(f"Core Impact: {row['Core Impact']}")
            print(f"CANVAS: {row['CANVAS']}")
            print("-" * 40)

# Display vulnerabilities
display_vulnerabilities(grouped_df)