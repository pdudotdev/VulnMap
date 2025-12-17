import nmap
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pprint import pprint
from colorama import Fore, Style
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Supress Matplotlib deprecation warnings
import warnings
warnings.filterwarnings("ignore")

# Initialize the nmap scanner
nm = nmap.PortScanner()

# Scan the local network to find hosts
print("Starting initial Nmap scan to find hosts...")
hosts = "192.168.56.0/24"
nm.scan(hosts=hosts, arguments='-sn --exclude 192.168.56.110')
print("Initial Nmap scan completed.")

# List all hosts found
all_hosts = nm.all_hosts()
print(f"All hosts:")

# Print all the discovered hosts
for host in all_hosts:
    print("• " + host)

# DataFrame to store scan results
columns = ['IP', 'Exploitable Vulnerabilities', 'Open Ports', 'Successful Brute Force Attacks', 'Successfully Brute-Forced Ports']
df = pd.DataFrame(columns=columns)

# Brute force scripts mapping
brute_force_scripts = {
    21: 'ftp-brute',
    22: 'ssh-brute',
    23: 'telnet-brute',
    25: 'smtp-brute',
    139: 'smb-brute',
    161: 'snmp-brute',
    3306: 'mysql-brute',
    5432: 'pgsql-brute',
    5902: 'vnc-brute',
    6002: 'vnc-brute',
    6379: 'redis-brute'
}

# Parse scan results for each host
data = []
for host in all_hosts:
    ip = host
    print(f"\nStarting detailed Nmap scan on {ip}...")
    
    # Execute Nmap scan with specified arguments
    detailed_scan = nm.scan(hosts=ip, arguments='-sV --script vulners')
    
    # Initializing variables for feature extraction
    open_ports = []
    available_exploits = 0
    brute_force_results = []
    successful_brute_force_ports = []
    successful_brute_force_count = 0
    
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            # Append port to the list of open ports
            open_ports.append(port)

            # The number of exploits available for services running on open ports
            try:
                exploits = detailed_scan['scan'][ip][proto][port]['script']['vulners'].count('*EXPLOIT*')
                available_exploits += exploits
            except KeyError:
                available_exploits = available_exploits
            #print(available_exploits)
            
            # Attempt brute force attack if port is in the specified list
            if port in brute_force_scripts:
                print(f"Attempting brute force attack on {ip}:{port}... Waiting...")
                brute_result = nm.scan(hosts=ip, ports=str(port), arguments=f"--script {brute_force_scripts[port]} --script-args brute.credfile='my.txt'")
                #pprint(brute_result)
                brute_force_results.append(brute_result)
                # Check if brute force was successful
                if not('Valid credentials' in str(brute_result)):
                    continue
                else:
                    successful_brute_force_ports.append(port)
                    successful_brute_force_count += 1
                    continue
    
    # Append data to list
    data.append({
        'IP': ip,
        'Exploitable Vulnerabilities': available_exploits,
        'Open Ports': open_ports,
        'Successful Brute Force Attacks': successful_brute_force_count,
        'Successfully Brute-Forced Ports': successful_brute_force_ports
    })

# Convert list to DataFrame
df = pd.DataFrame(data, columns=columns)

# Save DataFrame to CSV
df.to_csv('network_scan_results.csv', index=False)
print("Results saved to network_scan_results.csv")

# Function to generate tree-like structure
def generate_tree_structure(df):
    tree_str = ""
    for index, row in df.iterrows():
        tree_str += Style.BRIGHT + f"|---> Host: {row['IP']}\n" + Style.RESET_ALL
        tree_str += f"  |--- Open TCP Ports: {', '.join(map(str, row['Open Ports']))}\n"

        if row['Exploitable Vulnerabilities'] > 0:
            tree_str += Fore.BLUE + f"  |--- Exploitable Vulnerabilities: {row['Exploitable Vulnerabilities']}\n" + Style.RESET_ALL
        else:
            tree_str += f"  |--- Exploitable Vulnerabilities: {row['Exploitable Vulnerabilities']}\n"

        tree_str += f"  ||--- See more details on potential exploits using: nmap -sV --script vulners <IP>\n"

        if row['Successful Brute Force Attacks'] > 0:
            tree_str += Fore.RED + f"  |--- Successful Brute Force Attacks: {row['Successful Brute Force Attacks']}\n" + Style.RESET_ALL
        else:
            tree_str += f"  |--- Successful Brute Force Attacks: {row['Successful Brute Force Attacks']}\n"

        if row['Successful Brute Force Attacks'] > 0:
            tree_str += Fore.RED + f"  |--- Successfully Brute-Forced Ports: {', '.join(map(str, row['Successfully Brute-Forced Ports']))}\n" + Style.RESET_ALL
        tree_str += "\n"
    return tree_str

# Generate and print the tree-like structure
tree_structure = generate_tree_structure(df)
print(tree_structure)

# Calculate distances from origin and normalize them
df['Distance'] = np.sqrt(df['Exploitable Vulnerabilities']**2 + df['Successful Brute Force Attacks']**2)
df['Normalized Distance'] = (df['Distance'] - df['Distance'].min()) / (df['Distance'].max() - df['Distance'].min())

# Matplotlib visualization
plt.figure(figsize=(10, 6))

# Scatter plot with colors based on normalized distance
colors = plt.cm.Reds(df['Normalized Distance'])
plt.scatter(df['Exploitable Vulnerabilities'], df['Successful Brute Force Attacks'], s=100, c=colors)

# Annotate each point with the IP address
for i in range(len(df)):
    plt.text(df['Exploitable Vulnerabilities'][i], df['Successful Brute Force Attacks'][i], df['IP'][i], fontsize=9)

# Plot data
plt.title('Network Scan Results')
plt.xlabel('Number of Exploitable Vulnerabilities')
plt.ylabel('Number of Successful Brute Force Attacks')
plt.grid(True)

# Plot the colorbar (Vulnerability Scale)
plt.colorbar(plt.cm.ScalarMappable(cmap=plt.cm.Reds), label='Vulnerability Scale')

# Save the plot as an image file
plot_filename = "network_scan_plot.png"
plt.savefig(plot_filename)
#plt.show()

'''
# Email configuration
smtp_server = 'smtp.example.com'
smtp_port = 587
smtp_user = 'your_email@example.com'
smtp_password = 'your_password'
sender_email = 'your_email@example.com'
receiver_email = 'receiver_email@example.com'
subject = 'Network Scan Report'
body = f'Please find attached the network scan report.\n\n{tree_structure}'

# Create the email message
msg = MIMEMultipart()
msg['From'] = sender_email
msg['To'] = receiver_email
msg['Subject'] = subject
msg.attach(MIMEText(body, 'plain'))

# Attach the plot image
with open(plot_filename, 'rb') as f:
    mime = MIMEBase('image', 'png', filename=plot_filename)
    mime.add_header('Content-Disposition', 'attachment', filename=plot_filename)
    mime.add_header('X-Attachment-Id', '0')
    mime.add_header('Content-ID', '<0>')
    mime.set_payload(f.read())
    encoders.encode_base64(mime)
    msg.attach(mime)

# Send the email
with smtplib.SMTP(smtp_server, smtp_port) as server:
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.sendmail(sender_email, receiver_email, msg.as_string())

print("Email sent successfully.")
'''