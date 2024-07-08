import pandas as pd

def load_csv(file_path):
    # Load the CSV file into a DataFrame
    return pd.read_csv(file_path)

def filter_vulnerabilities(df):
    # Filter for 'High' or 'Critical' risk vulnerabilities
    return df[df['Risk'].isin(['High', 'Critical'])]

def group_vulnerabilities(df):
    # Group by Host and Risk level
    grouped = df.groupby(['Host', 'Risk'])
    return grouped

def format_report(grouped_df):
    report = []
    
    for (host, risk), group in grouped_df:
        report.append(f"Host: {host}, Risk Level: {risk}")
        for _, row in group.iterrows():
            report.append(f"  - PluginID: {row['PluginID']} | Name: {row['PluginName']}")
            report.append(f"    Synopsis: {row['Synopsis']}")
            report.append(f"    Solution: {row['Solution']}")
            report.append(f"    CVSS v3.0 Base Score: {row['CVSS v3.0 Base Score']}")
        report.append("\n")  # Add a newline for better readability between hosts/risk levels
    
    return "\n".join(report)

def main(file_path):
    # Load the CSV file
    df = load_csv(file_path)
    
    # Filter for high and critical vulnerabilities
    filtered_df = filter_vulnerabilities(df)
    
    # Group the vulnerabilities by Host and Risk
    grouped_df = group_vulnerabilities(filtered_df)
    
    # Format the report
    report = format_report(grouped_df)
    
    return report

# Example usage
file_path = 'product_reference_system_ReL5.csv'
report = main(file_path)
print(report)