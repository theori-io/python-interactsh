# pyright: strict
"""
Interactsh Client - Python implementation
Compatible with Python 3.12+
"""

__all__ = [
    'InteractshClient',
    'InteractionSession',
    'Options', 
    'Interaction',
    'SessionInfo',
    'State',
    'InteractshError',
    'AuthenticationError',
    'RegistrationError', 
    'PollingError',
    'ClientStateError',
    'ServerError',
    'CryptoError'
]

import asyncio
import base64
import json
import logging
import os
import random
import string
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Callable, Optional, Any
from urllib.parse import urlparse, ParseResult

from pydantic import BaseModel, Field, field_validator
from epyxid import XID

import aiohttp
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger(__name__)


class InteractshError(Exception):
    """Base exception for all Interactsh client errors"""
    pass


class AuthenticationError(InteractshError):
    """Raised when authentication fails"""
    pass


class RegistrationError(InteractshError):
    """Raised when server registration fails"""
    pass


class PollingError(InteractshError):
    """Raised when polling for interactions fails"""
    pass


class ClientStateError(InteractshError):
    """Raised when client is in an invalid state for the requested operation"""
    pass


class ServerError(InteractshError):
    """Raised when server returns an error response"""
    pass


class CryptoError(InteractshError):
    """Raised when cryptographic operations fail"""
    pass


class State(Enum):
    IDLE = 0
    CLOSED = 1


class SessionInfo(BaseModel):
    """Session information for resuming sessions"""
    server_url: str
    token: str
    private_key: str
    correlation_id: str
    secret_key: str
    public_key: str


class Interaction(BaseModel):
    """Interaction data received from the server"""
    protocol: str = Field(default="")
    unique_id: str = Field(alias="unique-id", default="")
    full_id: str = Field(alias="full-id", default="")
    q_type: Optional[str] = Field(alias="q-type", default=None)
    raw_request: Optional[str] = Field(alias="raw-request", default=None)
    raw_response: Optional[str] = Field(alias="raw-response", default=None)
    smtp_from: Optional[str] = Field(alias="smtp-from", default=None)
    remote_address: str = Field(alias="remote-address", default="")
    timestamp: datetime = Field(default_factory=datetime.now)
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        elif isinstance(v, datetime):
            return v
        else:
            return datetime.now()
    
    class Config:
        populate_by_name = True


class RegisterRequest(BaseModel):
    """Registration request data"""
    public_key: str
    secret_key: str
    correlation_id: str


class PollResponse(BaseModel):
    """Poll response data"""
    data: list[str]
    extra: list[str]
    aes_key: str
    tld_data: Optional[list[str]] = None


class DeregisterRequest(BaseModel):
    """Deregistration request data"""
    correlation_id: str
    secret_key: str


class Options(BaseModel):
    """Client configuration options"""
    server_url: str = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"
    token: str = ""
    disable_http_fallback: bool = False
    # N.B. correlation ID length must match the server
    correlation_id_length: int = 20
    correlation_id_nonce_length: int = 13
    http_client: Optional[aiohttp.ClientSession] = None
    session_info: Optional[SessionInfo] = None
    keep_alive_interval: float = 0
    
    class Config:
        arbitrary_types_allowed = True


class InteractionSession:
    """Async iterator session for receiving interactions"""
    
    def __init__(self, client: 'InteractshClient', poll_interval: float = 1.0) -> None:
        self.client = client
        self.poll_interval = poll_interval
        self._closed = False
        self._interaction_queue: asyncio.Queue[Interaction] = asyncio.Queue()
        self._poll_task: Optional[asyncio.Task[None]] = None
        self._stop_event = asyncio.Event()
    
    async def __aenter__(self) -> 'InteractionSession':
        """Enter the session context"""
        if not self.client._initialized:
            await self.client._initialize()
        
        if self.client.state == State.CLOSED:
            raise ClientStateError("Client is closed")
        
        # Start polling task
        self._stop_event.clear()
        self._poll_task = asyncio.create_task(self._poll_worker())
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the session context"""
        self._closed = True
        self._stop_event.set()
        
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
    
    async def _poll_worker(self) -> None:
        """Background worker that polls for interactions"""
        poll_count = 0
        while not self._closed and not self._stop_event.is_set():
            poll_count += 1
            try:
                logger.debug(f"Poll #{poll_count}: Starting poll...")
                interactions = await self.client._poll_once()
                logger.debug(f"Poll #{poll_count}: Received {len(interactions)} interactions")
                for i, interaction in enumerate(interactions):
                    logger.debug(f"Poll #{poll_count}: Queueing interaction {i+1}: {interaction.protocol} from {interaction.remote_address}")
                    await self._interaction_queue.put(interaction)
            except (PollingError, aiohttp.ClientError) as e:
                logger.debug(f"Poll #{poll_count}: Polling error: {e}")
            except Exception as e:
                logger.debug(f"Poll #{poll_count}: Unexpected error: {e}")
            
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.poll_interval
                )
                break
            except asyncio.TimeoutError:
                continue
    
    def __aiter__(self) -> 'InteractionSession':
        """Return self as async iterator"""
        return self
    
    async def __anext__(self) -> Interaction:
        """Get next interaction from the queue"""
        if self._closed and self._interaction_queue.empty():
            raise StopAsyncIteration
        
        try:
            # Try to get an interaction, checking periodically if we're closed
            while True:
                try:
                    return await asyncio.wait_for(
                        self._interaction_queue.get(),
                        timeout=0.1
                    )
                except asyncio.TimeoutError:
                    if self._closed and self._interaction_queue.empty():
                        raise StopAsyncIteration
        except asyncio.CancelledError:
            raise StopAsyncIteration


class InteractshClient:
    """Client for communicating with interactsh server instance"""
    
    def __init__(self, options: Optional[Options] = None) -> None:
        self.options: Options = options or Options()
        self._state: State = State.IDLE
        self._state_lock: asyncio.Lock = asyncio.Lock()
        self._busy_lock: asyncio.Lock = asyncio.Lock()
        
        # Initialize HTTP client
        self.http_client: Optional[aiohttp.ClientSession] = self.options.http_client
        self._session_created: bool = False
        if not self.http_client:
            self.http_client = None
            self._session_created = True
        
        # Client properties
        self.correlation_id: str = ""
        self.secret_key: str = ""
        self.server_url: Optional[ParseResult] = None
        self.token: str = self.options.token
        self.disable_http_fallback: bool = self.options.disable_http_fallback
        self.correlation_id_length: int = self.options.correlation_id_length
        self.correlation_id_nonce_length: int = self.options.correlation_id_nonce_length
        
        # RSA keys
        self.private_key: Optional[RSAPrivateKey] = None
        self.public_key: Optional[RSAPublicKey] = None
        
        # Async tasks
        self._keep_alive_task: Optional[asyncio.Task[None]] = None
        self._keep_alive_stop_event: asyncio.Event = asyncio.Event()
        
        # Initialize client will be called when starting async operations
        self._initialized: bool = False
    
    @property
    def state(self) -> State:
        return self._state
    
    async def _set_state(self, value: State) -> None:
        async with self._state_lock:
            self._state = value
    
    async def _initialize(self) -> None:
        """Initialize the client with session info or new keys"""
        if not self.http_client:
            self.http_client = aiohttp.ClientSession(
                headers={'User-Agent': 'Interactsh-Python-Client/1.0'}
            )
            self._session_created = True
        
        if self.options.session_info:
            await self._restore_session(self.options.session_info)
        else:
            await self._initialize_new_session()
        
        # Start keep-alive if configured
        if self.options.keep_alive_interval > 0:
            await self._start_keep_alive()
        
        self._initialized = True
    
    async def _restore_session(self, session_info: SessionInfo) -> None:
        """Restore a previous session"""
        self.correlation_id = session_info.correlation_id
        self.secret_key = session_info.secret_key
        self.token = session_info.token
        
        # Restore RSA keys
        private_key_data = base64.b64decode(session_info.private_key)
        loaded_private_key = serialization.load_der_private_key(
            private_key_data, password=None, backend=default_backend()
        )
        if not isinstance(loaded_private_key, RSAPrivateKey):
            raise ValueError("Session contains non-RSA private key")
        self.private_key = loaded_private_key
        self.public_key = self.private_key.public_key()
        
        # Parse server URL
        self.server_url = urlparse(session_info.server_url)
        
        # Try to re-register
        try:
            registration_data = self._encode_registration_request(
                session_info.public_key,
                session_info.secret_key,
                session_info.correlation_id
            )
            await self._perform_registration(session_info.server_url, registration_data)
        except (RegistrationError, ServerError):
            pass  # Silently fail if session is still active
    
    async def _initialize_new_session(self) -> None:
        """Initialize a new session with new keys"""
        # Generate correlation ID and secret key
        self.correlation_id = self._generate_correlation_id()
        self.secret_key = str(uuid.uuid4())
        
        # Generate RSA keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Encode public key and create registration payload
        assert self.public_key is not None
        public_key_str = self._encode_public_key(self.public_key)
        payload = self._encode_registration_request(
            public_key_str,
            self.secret_key,
            self.correlation_id
        )
        
        # Register with server
        await self._parse_server_urls(self.options.server_url, payload)
    
    def _generate_correlation_id(self) -> str:
        """Generate a correlation ID"""

        # N.B. this must be a XID string, it will be parsed by the server
        correlation_id = str(XID())
        
        if len(correlation_id) > self.correlation_id_length:
            correlation_id = correlation_id[:self.correlation_id_length]
        
        return correlation_id
    
    def _encode_public_key(self, public_key: RSAPublicKey) -> str:
        """Encode RSA public key to base64 PEM format"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pem).decode('utf-8')
    
    def _decode_public_key(self, data: str) -> RSAPublicKey:
        """Decode base64 PEM public key"""
        decoded = base64.b64decode(data)
        loaded_public_key = serialization.load_pem_public_key(decoded, backend=default_backend())
        if not isinstance(loaded_public_key, RSAPublicKey):
            raise ValueError("Invalid RSA public key")
        return loaded_public_key
    
    def _encode_registration_request(self, public_key: str, secret_key: str, correlation_id: str) -> bytes:
        """Encode registration request"""
        request = {
            "public-key": public_key,
            "secret-key": secret_key,
            "correlation-id": correlation_id
        }
        return json.dumps(request).encode('utf-8')
    
    async def _parse_server_urls(self, server_urls: str, payload: bytes) -> None:
        """Parse and try multiple server URLs"""
        if not server_urls:
            raise ValueError("Invalid server URL provided")
        
        urls = [url.strip() for url in server_urls.split(',')]
        random.shuffle(urls)
        
        errors: list[str] = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            try:
                if await self._try_registration(url, payload):
                    return
            except (RegistrationError, ServerError) as e:
                errors.append(f"{url}: {str(e)}")
                continue
        
        raise RegistrationError(f"Could not register to any server: {'; '.join(errors)}")
    
    async def _try_registration(self, url: str, payload: bytes) -> bool:
        """Try to register with a specific server URL"""
        parsed_url = urlparse(url)
        
        # Try HTTPS first
        try:
            await self._perform_registration(url, payload)
            self.server_url = parsed_url
            return True
        except (RegistrationError, ServerError) as e:
            if not self.disable_http_fallback and parsed_url.scheme == 'https':
                # Try HTTP fallback
                http_url = url.replace('https://', 'http://')
                try:
                    await self._perform_registration(http_url, payload)
                    self.server_url = urlparse(http_url)
                    return True
                except (RegistrationError, ServerError):
                    pass
            raise e
    
    async def _perform_registration(self, server_url: str, payload: bytes) -> None:
        """Perform registration with the server"""
        url = f"{server_url}/register"
        headers = {'Content-Type': 'application/json'}
        
        if self.token:
            headers['Authorization'] = self.token
        
        assert self.http_client is not None
        async with self.http_client.post(
            url,
            data=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as response:
        
            if response.status == 401:
                raise AuthenticationError("Invalid token provided for interactsh server")
            
            if response.status != 200:
                text = await response.text()
                raise RegistrationError(f"Could not register to server: {text}")
            
            data = await response.json()
            if data.get('message') != 'registration successful':
                raise RegistrationError(f"Could not get register response: {data.get('message', 'unknown error')}")
            
            await self._set_state(State.IDLE)
    
    async def _start_keep_alive(self) -> None:
        """Start keep-alive thread"""
        self._keep_alive_stop_event.clear()
        self._keep_alive_task = asyncio.create_task(self._keep_alive_worker())
    
    async def _keep_alive_worker(self) -> None:
        """Keep-alive worker thread"""
        while not self._keep_alive_stop_event.is_set():
            if self.state == State.CLOSED:
                break
            
            try:
                # Re-register to keep session alive
                assert self.public_key is not None
                public_key_str = self._encode_public_key(self.public_key)
                payload = self._encode_registration_request(
                    public_key_str,
                    self.secret_key,
                    self.correlation_id
                )
                assert self.server_url is not None
                await self._perform_registration(self.server_url.geturl(), payload)
            except (RegistrationError, ServerError):
                pass  # Silently fail
            
            try:
                await asyncio.wait_for(
                    self._keep_alive_stop_event.wait(),
                    timeout=self.options.keep_alive_interval
                )
                break  # Event was set, exit loop
            except asyncio.TimeoutError:
                pass  # Timeout reached, continue loop
    
    async def url(self) -> str:
        """Generate a new URL for interaction"""
        if not self._initialized:
            await self._initialize()
        
        if self.state == State.CLOSED:
            return ""
        
        # Generate random nonce
        random_bytes = os.urandom(self.correlation_id_nonce_length)
        random_data = base64.b32encode(random_bytes).decode('ascii').lower().rstrip('=')
        
        if len(random_data) > self.correlation_id_nonce_length:
            random_data = random_data[:self.correlation_id_nonce_length]
        
        # Build URL
        assert self.server_url is not None
        return f"{self.correlation_id}{random_data}.{self.server_url.netloc}"
    
    def interact(self, poll_interval: float = 1.0) -> InteractionSession:
        """Create an interaction session for receiving interactions
        
        Usage:
            async with client.interact() as session:
                async for interaction in session:
                    print(interaction)
        
        Args:
            poll_interval: Interval between polls in seconds (default: 1.0)
            
        Returns:
            InteractionSession: Context manager and async iterator for interactions
        """
        return InteractionSession(self, poll_interval)
    
    
    async def _poll_once(self) -> list[Interaction]:
        """Poll server once and return list of interactions"""
        async with self._busy_lock:
            assert self.server_url is not None
            url = f"{self.server_url.geturl()}/poll?id={self.correlation_id}&secret={self.secret_key}"
            headers: dict[str, str] = {}
            
            if self.token:
                headers['Authorization'] = self.token
            
            logger.debug(f"Polling URL: {url}")
            
            assert self.http_client is not None
            async with self.http_client.get(
                url, 
                headers=headers, 
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
            
                if response.status == 401:
                    raise AuthenticationError("Authentication failed")
                
                if response.status != 200:
                    text = await response.text()
                    raise PollingError(f"Could not poll interactions: {text}")
                
                poll_response = await response.json(content_type=None)
                logger.debug(f"Poll response: {poll_response}")
            
                interactions: list[Interaction] = []
                
                # Process encrypted data
                data_list: list[str] = poll_response.get('data') or []
                logger.debug(f"Processing {len(data_list)} encrypted data items")
                for data in data_list:
                    try:
                        aes_key_str: str = poll_response['aes_key']
                        plaintext = self._decrypt_message(aes_key_str, data)
                        interaction = Interaction.model_validate_json(plaintext)
                        interactions.append(interaction)
                    except CryptoError:
                        logger.exception("Error decrypting interaction")
                
                # Process extra data
                extra_list: list[str] = poll_response.get('extra') or []
                logger.debug(f"Processing {len(extra_list)} extra data items")
                for data in extra_list:
                    try:
                        interaction = Interaction.model_validate_json(data)
                        interactions.append(interaction)
                    except ValueError:
                        logger.exception("Error parsing extra interaction")
                
                # Process TLD data
                tld_list: list[str] = poll_response.get('tlddata', []) or []
                for data in tld_list:
                    try:
                        interaction = Interaction.model_validate_json(data)
                        interactions.append(interaction)
                    except ValueError:
                        logger.exception("Error parsing TLD interaction")
                
                logger.debug(f"Total interactions parsed: {len(interactions)}")
                return interactions
    
    
    def _decrypt_message(self, key_b64: str, message_b64: str) -> bytes:
        """Decrypt AES-256-RSA-OAEP encrypted message"""
        try:
            # Decode the RSA-encrypted AES key
            encrypted_key = base64.b64decode(key_b64)
            
            # Decrypt the AES key using RSA
            assert self.private_key is not None
            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decode the ciphertext
            ciphertext = base64.b64decode(message_b64)
            
            if len(ciphertext) < 16:  # AES block size
                raise CryptoError("Ciphertext block size is too small")
            
            # Extract IV and actual ciphertext
            iv = ciphertext[:16]
            actual_ciphertext = ciphertext[16:]
            
            # Decrypt using AES-CFB
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            return plaintext
        except (ValueError, TypeError) as e:
            raise CryptoError(f"Failed to decrypt message: {e}") from e
    
    
    async def close(self) -> None:
        """Close the client and deregister from server"""
        async with self._busy_lock:
            if self.state == State.CLOSED:
                raise ClientStateError("Client is already closed")
            
            # Stop keep-alive
            self._keep_alive_stop_event.set()
            if self._keep_alive_task:
                try:
                    await asyncio.wait_for(self._keep_alive_task, timeout=5)
                except asyncio.TimeoutError:
                    self._keep_alive_task.cancel()
            
            # Deregister from server
            try:
                deregister_request = {
                    "correlation-id": self.correlation_id,
                    "secret-key": self.secret_key
                }
                
                assert self.server_url is not None
                url = f"{self.server_url.geturl()}/deregister"
                headers = {'Content-Type': 'application/json'}
                
                if self.token:
                    headers['Authorization'] = self.token
                
                assert self.http_client is not None
                async with self.http_client.post(
                    url,
                    json=deregister_request,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        text = await response.text()
                        logger.warning(f"Could not deregister from server: {text}")
            except (ServerError, aiohttp.ClientError):
                logger.exception("Error during deregistration")
            
            # Close HTTP session if we created it
            if self._session_created and self.http_client:
                await self.http_client.close()
            
            await self._set_state(State.CLOSED)
    
    def serialize_session(self) -> str:
        """Serialize session info to a string"""
        assert self.private_key is not None
        private_key_der = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        assert self.public_key is not None
        public_key_str = self._encode_public_key(self.public_key)
        
        assert self.server_url is not None
        session_info = {
            'server-url': self.server_url.geturl(),
            'server-token': self.token,
            'private-key': base64.b64encode(private_key_der).decode('utf-8'),
            'correlation-id': self.correlation_id,
            'secret-key': self.secret_key,
            'public-key': public_key_str
        }
        
        return yaml.dump(session_info)
    
    @classmethod
    async def from_session_string(cls, session_string: str) -> 'InteractshClient':
        """Create client from serialized session string"""
        data = yaml.safe_load(session_string)
        
        session_info = SessionInfo(
            server_url=data['server-url'],
            token=data.get('server-token', ''),
            private_key=data['private-key'],
            correlation_id=data['correlation-id'],
            secret_key=data['secret-key'],
            public_key=data['public-key']
        )
        
        options = Options(session_info=session_info)
        client = cls(options)
        await client._initialize()
        return client


# Example usage
async def main():
    # Create a new client
    client = InteractshClient()
    
    # Generate URLs
    url = await client.url()
    print(f"Interaction URL: {url}")
    
    # Poll for interactions using async iterator
    try:
        print("Polling for interactions... Press Ctrl+C to stop")
        async with client.interact() as session:
            async for interaction in session:
                print(f"Received {interaction.protocol} interaction from {interaction.remote_address}")
                print(f"Full ID: {interaction.full_id}")
                if interaction.raw_request:
                    print(f"Request preview: {interaction.raw_request[:200]}...")
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
