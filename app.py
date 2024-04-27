from dash import Dash, html, dcc, callback, Input, Output
import plotly.express as px
import pandas as pd

# Load the CSV dataset
df = pd.read_csv("nmap_results1.csv")

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
    print(open_ports)

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

# Group data by device and count unique open ports
open_ports_count = df.groupby("IP")["Open Ports"].nunique()
print(open_ports_count)


# Initialize the Dash app
app = Dash(__name__)

# Define the layout of the Dash app
app.layout = html.Div(
    children=[
        html.H1(children="Visualization of Up Operating Systems and Open Ports"),
        html.Div(
            children=[
                dcc.Graph(id="os-bar-graph", figure=fig_os),
                html.H1(children="Open Ports Count per IP Address"),
                dcc.Graph(id="open-ports-line-chart", figure=fig_port),
                html.H1(children="IP Addresses with Essential Ports Open"),
                dcc.Graph(id="essential-ports-scatter-plot", figure=fig),
            ]
        ),
    ]
)

if __name__ == "__main__":
    app.run_server(debug=True)
