from dash import Dash, html, dcc, Input, Output
import plotly.express as px
import pandas as pd

external_scripts = [
    {'src': 'https://cdn.tailwindcss.com'}
]

# Load the CSV dataset
df = pd.read_csv("nmap_results.csv")

# Filter out only the rows where the Status is 'Up'
df_up = df[df["Status"] == "up"]

# Count the occurrences of each OS
os_counts = df["OS"].value_counts()

# Initialize an empty dictionary to store IP addresses and their corresponding number of open ports
ip_open_ports = {}

# Iterate through each row in the DataFrame
for _, row in df.iterrows():
    ip_address = row["IP"]
    open_ports = row["Open Ports"].split()

    # Store the number of open ports for each IP address
    ip_open_ports[ip_address] = len(open_ports)

df_open_ports = pd.DataFrame(
    list(ip_open_ports.items()), columns=["IP Address", "Open Ports Count"]
)

# Create a list of IP addresses and their corresponding counts
ip_addresses = list(ip_open_ports.keys())
open_port_counts = list(ip_open_ports.values())

# Define essential ports that should not be open
essential_ports = {"137", "139", "22", "53", "25", "3389", "20", "21", "23"}

# Create an empty DataFrame to store the data
essential_ports_data = pd.DataFrame(columns=["IP", "Essential Port"])

# Iterate through each row in the DataFrame
for _, row in df.iterrows():
    ip_address = row["IP"]
    open_ports = row["Open Ports"].split()

    # Check if any of the open ports are in the list of essential ports
    for port in open_ports:
        if port in essential_ports:
            # If the port is an essential port, add the IP address and essential port to the DataFrame
            essential_ports_data = pd.concat(
                [
                    essential_ports_data,
                    pd.DataFrame({"IP": [ip_address], "Essential Port": [port]}),
                ],
                ignore_index=True,
            )


# Classify devices into network device, server, or client based on active ports and services
def classify_device(row):
    network_ports = {"22", "23", "80", "443"}  # Common network ports
    server_services = {
        "21",
        "22",
        "80",
        "443",
        "3306",
        "3389",
        "8080",
    }  # Typical server services

    open_ports = set(row["Open Ports"].split())

    if open_ports.issubset(network_ports):
        return "Network Device"
    elif open_ports.intersection(server_services):
        return "Server"
    else:
        return "Client"


# Apply classification function to each row
df["Device Type"] = df.apply(classify_device, axis=1)
device_type_counts = df["Device Type"].value_counts()

# Plot device type distribution
fig_device_type = px.pie(
    values=device_type_counts.values,
    names=device_type_counts.index,
    title="Device Type Distribution",
)

# Extract individual ports and create a histogram
all_ports = [port for ports in df["Open Ports"].str.split() for port in ports]
port_counts = pd.Series(all_ports).value_counts()

# Plot distribution of individual ports
fig_port_distribution = px.bar(
    x=port_counts.index,
    y=port_counts.values,
    labels={"x": "Port", "y": "Count"},
    title="Distribution of Open Ports",
)

# Update layout for better visibility of x-axis labels
fig_port_distribution.update_layout(
    xaxis=dict(tickangle=45),
)

# Create the Plotly bar figure for OS counts
fig_os = px.bar(
    x=os_counts.index,
    y=os_counts.values,
    labels={"x": "Operating System", "y": "Count"},
    title="Number of Up Operating Systems",
)

# Create the Plotly line figure for open ports
fig_port = px.line(
    df_open_ports,
    x="IP Address",
    y="Open Ports Count",
    title="Open Ports Count per IP Address",
)

# Create the scatter plot using Plotly Express
fig = px.scatter(
    essential_ports_data,
    x="Essential Port",
    y="IP",
    title="IP Addresses with Essential Ports Open",
    labels={"Essential Port": "Essential Port", "IP": "IP Address"},
    color="Essential Port",
)

# Distribution of Open Ports
fig_open_ports_dist = px.histogram(
    df, x="Open Ports", title="Distribution of Open Ports"
)

# Operating System Distribution
fig_os_distribution = px.pie(
    values=os_counts.values,
    names=os_counts.index,
    title="Operating System Distribution",
)

# Temporal Analysis: Number of devices online over time
# Parse the timestamp column as datetime
df["Timestamp"] = pd.to_datetime(df["Timestamp"])

# Group by timestamp and count the number of devices online at each timestamp
temporal_data = (
    df.groupby(pd.Grouper(key="Timestamp", freq="h"))
    .size()
    .reset_index(name="Device Count")
)

# Plot time series graph showing the number of devices online over time
fig_temporal_analysis = px.line(
    temporal_data,
    x="Timestamp",
    y="Device Count",
    title="Number of Devices Online Over Time",
)

# Initialize the Dash app
app = Dash(__name__, external_scripts=external_scripts)

# Define the layout of the Dash app
app.layout = html.Div(
    children=[
        html.H1(className='text-2xl font-bold m-10',children="Visualization of Up Operating Systems and Open Ports"),
        html.Div(
            # className=' ',
            children=[
                html.Button("Run Nmap Scan",className='py-4 font-bold border-2 rounded-lg px-5 ml-10 hover:bg-blue-200', id="run-nmap-button", n_clicks=0),
                html.Div(id="nmap-output"),
            ]
        ),
        html.Div(
            children=[
                dcc.Graph(className='border-2 m-16 rounded-lg ', id="os-bar-graph", figure=fig_os),
                dcc.Graph(className='border-2 m-16 rounded-lg ', id="open-ports-line-chart", figure=fig_port),
                dcc.Graph(className='border-2 m-16 rounded-lg ', id="essential-ports-scatter-plot", figure=fig),
                dcc.Graph(className='border-2 m-16 rounded-lg ', id="device-type-distribution", figure=fig_device_type),
            ]
        ),
        html.Div(
            children=[
                dcc.Graph(className='border-2 m-16 rounded-lg ',id="port-distribution", figure=fig_port_distribution),
                dcc.Graph(className='border-2 m-16 rounded-lg ', id="os-distribution", figure=fig_os_distribution),
            ]
        ),
        html.Div(
            children=[
                dcc.Graph(className='border-2 m-16 rounded-lg ', id="temporal-analysis", figure=fig_temporal_analysis),
            ]
        ),
    ]
)

if __name__ == "__main__":
    app.run_server(debug=True)
