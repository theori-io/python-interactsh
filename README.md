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
import asyncio
from interactsh import InteractshClient

async def main():
    # Create a client
    client = InteractshClient()
    
    try:
        # Generate a unique URL for testing
        url = await client.url()
        print(f"Test this URL: {url}")
        
        # Poll for interactions using async context manager
        async with client.interact(poll_interval=1.0) as session:
            async for interaction in session:
                print(f"Received {interaction.protocol} interaction from {interaction.remote_address}")
                if interaction.raw_request:
                    print(f"Request preview: {interaction.raw_request[:200]}...")
    finally:
        await client.close()

# Run the async main function
asyncio.run(main())
```

### Using Custom Server and Token

```python
import asyncio
from interactsh import InteractshClient, Options

async def main():
    # Configure client options
    options = Options(
        server_url="https://your-interactsh-server.com",
        token="your-auth-token"
    )
    
    client = InteractshClient(options)
    
    try:
        url = await client.url()
        print(f"Test URL: {url}")
        
        # Use the client...
    finally:
        await client.close()

asyncio.run(main())
```

### Session Management

```python
import asyncio
from interactsh import InteractshClient

async def save_session():
    client = InteractshClient()
    try:
        # Initialize client
        await client.initialize()
        
        # Save session for later use
        session_string = client.serialize_session()
        with open("my_session.yaml", "w") as f:
            f.write(session_string)
    finally:
        await client.close()

async def restore_session():
    # Restore session
    with open("my_session.yaml", "r") as f:
        session_string = f.read()
    
    client = await InteractshClient.from_session_string(session_string)
    try:
        # Use restored client...
        url = await client.url()
        print(f"Restored session URL: {url}")
    finally:
        await client.close()
```

## API Reference

### InteractshClient

The main client class for interacting with Interactsh servers.

#### Constructor

```python
InteractshClient(options: Optional[Options] = None)
```

#### Methods

- `async url() -> str`: Generate a new interaction URL
- `interact(poll_interval: float = 1.0) -> InteractionSession`: Create an interaction session for polling
- `async poll_once() -> list[Interaction]`: Poll server once and return interactions
- `async close()`: Close client and deregister from server
- `serialize_session() -> str`: Serialize session to YAML string
- `async from_session_string(session_string: str) -> InteractshClient`: Create client from session string

### Options

Configuration options for the client.

```python
class Options(BaseModel):
    server_url: str = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"
    token: str = ""
    disable_http_fallback: bool = False
    correlation_id_length: int = 20
    correlation_id_nonce_length: int = 13
    http_client: Optional[aiohttp.ClientSession] = None
    session_info: Optional[SessionInfo] = None
    keep_alive_interval: float = 0
```

### Interaction

Data structure representing a received interaction.

```python
class Interaction(BaseModel):
    protocol: str = Field(default="")
    unique_id: str = Field(alias="unique-id", default="")
    full_id: str = Field(alias="full-id", default="")
    q_type: Optional[str] = Field(alias="q-type", default=None)
    raw_request: Optional[str] = Field(alias="raw-request", default=None)
    raw_response: Optional[str] = Field(alias="raw-response", default=None)
    smtp_from: Optional[str] = Field(alias="smtp-from", default=None)
    remote_address: str = Field(alias="remote-address", default="")
    timestamp: datetime = Field(default_factory=datetime.now)
```

## Examples

### Web Application Testing

```python
import asyncio
import aiohttp
from interactsh import InteractshClient

async def test_ssrf():
    client = InteractshClient()
    
    try:
        # Test for SSRF vulnerability
        payload_url = await client.url()
        test_payload = f"{payload_url}/ssrf-test"
        
        print(f"Testing with payload: {test_payload}")
        
        # Send payload to target application
        async with aiohttp.ClientSession() as session:
            await session.post("https://target-app.com/api/fetch", 
                             json={"url": test_payload})
        
        # Poll for interactions
        async with client.interact(poll_interval=2.0) as interaction_session:
            async for interaction in interaction_session:
                if interaction.protocol == "http":
                    print(f"SSRF detected! Request from {interaction.remote_address}")
                    if interaction.raw_request:
                        print(f"Request: {interaction.raw_request[:500]}...")
                    break  # Stop after first interaction
    finally:
        await client.close()

asyncio.run(test_ssrf())
```

### DNS Exfiltration Detection

```python
import asyncio
from interactsh import InteractshClient

async def monitor_dns():
    client = InteractshClient()
    
    try:
        domain = await client.domain()
        print(f"Monitor DNS queries to: {domain}")
        
        # Poll for DNS interactions
        async with client.interact(poll_interval=1.0) as session:
            async for interaction in session:
                if interaction.protocol == "dns":
                    print(f"DNS query detected: {interaction.full_id}")
                    print(f"Query type: {interaction.q_type}")
                    print(f"Remote address: {interaction.remote_address}")
    except KeyboardInterrupt:
        print("\nStopping DNS monitoring...")
    finally:
        await client.close()

asyncio.run(monitor_dns())
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This library is designed for security testing purposes. Please use responsibly and only on systems you own or have explicit permission to test.
