# Python Interactsh

A Python client library for interacting with [Interactsh](https://github.com/projectdiscovery/interactsh) servers for out-of-band application security testing (OAST).

## Features

- Full compatibility with Interactsh servers
- Support for multiple protocols (HTTP, DNS, SMTP, etc.)
- Encrypted communication using RSA-OAEP + AES-CFB
- Session management and restoration
- Polling for real-time interactions
- Thread-safe implementation
- Keep-alive functionality
- Support for custom server URLs and authentication tokens

## Installation

```bash
pip install python-interactsh
```

## Quick Start

### Basic Usage

```python
from interactsh import InteractshClient

# Create a client
client = InteractshClient()

# Generate a unique URL for testing
url = client.url()
print(f"Test this URL: http://{url}")

# Define callback to handle interactions
def on_interaction(interaction):
    print(f"Received {interaction.protocol} interaction from {interaction.remote_address}")
    print(f"Full request: {interaction.raw_request}")

# Start polling for interactions
client.start_polling(interval=5.0, callback=on_interaction)

# Your application testing code here...
# The callback will be triggered when interactions are received

# Stop polling and close the client
client.stop_polling()
client.close()
```

### Using Custom Server and Token

```python
from interactsh import InteractshClient, Options

# Configure client options
options = Options(
    server_url="https://your-interactsh-server.com",
    token="your-auth-token"
)

client = InteractshClient(options)
```

### Session Management

```python
# Save session for later use
client.save_session("my_session.yaml")

# Restore session
client = InteractshClient.from_session_file("my_session.yaml")
```

## API Reference

### InteractshClient

The main client class for interacting with Interactsh servers.

#### Constructor

```python
InteractshClient(options: Optional[Options] = None)
```

#### Methods

- `url() -> str`: Generate a new interaction URL
- `start_polling(interval: float, callback: Callable[[Interaction], None])`: Start polling for interactions
- `stop_polling()`: Stop polling
- `close()`: Close client and deregister from server
- `save_session(filename: str)`: Save session to file
- `from_session_file(filename: str) -> InteractshClient`: Create client from saved session

### Options

Configuration options for the client.

```python
@dataclass
class Options:
    server_url: str = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"
    token: str = ""
    disable_http_fallback: bool = False
    correlation_id_length: int = 20
    correlation_id_nonce_length: int = 13
    http_client: Optional[requests.Session] = None
    session_info: Optional[SessionInfo] = None
    keep_alive_interval: float = 0
```

### Interaction

Data structure representing a received interaction.

```python
@dataclass
class Interaction:
    protocol: str
    unique_id: str
    full_id: str
    q_type: Optional[str] = None
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    smtp_from: Optional[str] = None
    remote_address: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    asn_info: List[Dict[str, str]] = field(default_factory=list)
```

## Examples

### Web Application Testing

```python
import requests
from interactsh_client import InteractshClient

client = InteractshClient()

# Test for SSRF vulnerability
payload_url = client.url()
test_payload = f"http://{payload_url}/ssrf-test"

def check_interaction(interaction):
    if interaction.protocol == "http":
        print(f"SSRF detected! Request from {interaction.remote_address}")
        print(f"Request: {interaction.raw_request}")

client.start_polling(5.0, check_interaction)

# Send payload to target application
requests.post("https://target-app.com/api/fetch", 
              json={"url": test_payload})

# Wait for interaction...
```

### DNS Exfiltration Detection

```python
from interactsh_client import InteractshClient

client = InteractshClient()
domain = client.url()

def dns_callback(interaction):
    if interaction.protocol == "dns":
        print(f"DNS query detected: {interaction.full_id}")
        print(f"Query type: {interaction.q_type}")

client.start_polling(2.0, dns_callback)

# Your DNS exfiltration test code here
print(f"Monitor DNS queries to: {domain}")
```

## Requirements

- Python 3.12+
- requests >= 2.31.0
- cryptography >= 41.0.0
- pyyaml >= 6.0

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This library is designed for security testing purposes. Please use responsibly and only on systems you own or have explicit permission to test.