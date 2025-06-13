#!/usr/bin/env python3
"""
Pytest test suite for the interactsh client library.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import aiohttp

from interactsh import InteractshClient, InteractionSession, Options, Interaction, State, AuthenticationError, ClientStateError


class TestInteractshClient:
    """Test cases for InteractshClient"""
    
    @pytest.mark.asyncio
    async def test_client_initialization_default(self):
        """Test client initialization with default options"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            client = InteractshClient()
            await client._initialize()
            assert client.state == State.IDLE
            assert client.correlation_id != ""
            assert client.secret_key != ""
            assert client.private_key is not None
            assert client.public_key is not None
            await client.close()
    
    @pytest.mark.asyncio
    async def test_client_initialization_with_options(self):
        """Test client initialization with custom options"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            options = Options(
                server_url="https://oast.fun",
                correlation_id_length=15,
                correlation_id_nonce_length=10
            )
            client = InteractshClient(options)
            await client._initialize()
            assert client.correlation_id_length == 15
            assert client.correlation_id_nonce_length == 10
            await client.close()
    
    @pytest.mark.asyncio
    async def test_url_generation(self):
        """Test URL generation"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            client = InteractshClient()
            url1 = await client.url()
            url2 = await client.url()
            
            # URLs should be different
            assert url1 != url2
            
            # URLs should contain the correlation ID
            assert client.correlation_id in url1
            assert client.correlation_id in url2
            
            # URLs should be valid format
            assert "." in url1
            assert "." in url2
            
            await client.close()
    
    @pytest.mark.asyncio
    async def test_url_generation_when_closed(self):
        """Test URL generation when client is closed"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            client = InteractshClient()
            await client._initialize()
            await client.close()
            
            url = await client.url()
            assert url == ""
    
    @pytest.mark.asyncio
    async def test_state_management(self):
        """Test client state management"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            client = InteractshClient()
            await client._initialize()
            
            # Initial state
            assert client.state == State.IDLE
            
            # Close client
            await client.close()
            assert client.state == State.CLOSED
            
            # Cannot close again
            with pytest.raises(ClientStateError, match="already closed"):
                await client.close()
    
    @pytest.mark.asyncio
    async def test_session_serialize_and_restore(self):
        """Test session serialization and restore functionality"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            # Create client and serialize session
            client1 = InteractshClient()
            await client1._initialize()
            original_correlation_id = client1.correlation_id
            original_secret_key = client1.secret_key
            
            # Serialize session to string
            session_string = client1.serialize_session()
            await client1.close()
            
            # Restore session from string
            client2 = await InteractshClient.from_session_string(session_string)
            
            # Verify session was restored
            assert client2.correlation_id == original_correlation_id
            assert client2.secret_key == original_secret_key
            
            await client2.close()
    
    @pytest.mark.asyncio
    async def test_registration_success(self):
        """Test successful registration with server"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Mock successful registration response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            options = Options(server_url="https://oast.fun")
            client = InteractshClient(options)
            await client._initialize()
            
            # Verify registration was called
            mock_post.assert_called()
            assert client.state == State.IDLE
            
            await client.close()
    
    @pytest.mark.asyncio
    async def test_registration_auth_failure(self):
        """Test registration with authentication failure"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Mock auth failure response
            mock_response = AsyncMock()
            mock_response.status = 401
            mock_post.return_value.__aenter__.return_value = mock_response
            
            options = Options(server_url="https://oast.fun", token="invalid-token")
            client = InteractshClient(options)
            
            with pytest.raises(AuthenticationError, match="Invalid token"):
                await client._initialize()
    
    @pytest.mark.asyncio
    async def test_interact_with_interactions(self):
        """Test interact async iterator with mock interactions"""
        with patch('aiohttp.ClientSession.post') as mock_post, \
             patch('aiohttp.ClientSession.get') as mock_get:
            
            # Mock registration response
            mock_reg_response = AsyncMock()
            mock_reg_response.status = 200
            mock_reg_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_reg_response
            
            # Mock poll response with interactions
            mock_poll_response = AsyncMock()
            mock_poll_response.status = 200
            mock_poll_response.json = AsyncMock(return_value={
                'data': [],  # Empty for simplicity
                'extra': ['{"protocol": "http", "unique-id": "test123", "full-id": "test123.example.com", "remote-address": "1.2.3.4", "timestamp": "2023-01-01T00:00:00Z"}'],
                'aes_key': 'dummy_key',
                'tlddata': []
            })
            mock_get.return_value.__aenter__.return_value = mock_poll_response
            
            client = InteractshClient()
            interactions_received = []
            
            # Use interact context manager
            async with client.interact(poll_interval=0.1) as session:
                # Collect first interaction
                async for interaction in session:
                    interactions_received.append(interaction)
                    break  # Exit after first interaction
            
            await client.close()
            
            # Verify interactions were processed
            assert len(interactions_received) == 1
            assert interactions_received[0].protocol == "http"
            assert interactions_received[0].unique_id == "test123"
    
    @pytest.mark.asyncio
    async def test_interact_with_timeout(self):
        """Test interact with asyncio.timeout"""
        with patch('aiohttp.ClientSession.post') as mock_post, \
             patch('aiohttp.ClientSession.get') as mock_get:
            
            # Mock registration response
            mock_reg_response = AsyncMock()
            mock_reg_response.status = 200
            mock_reg_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_reg_response
            
            # Mock poll response with no interactions
            mock_poll_response = AsyncMock()
            mock_poll_response.status = 200
            mock_poll_response.json = AsyncMock(return_value={
                'data': [],
                'extra': [],
                'aes_key': '',
                'tlddata': []
            })
            mock_get.return_value.__aenter__.return_value = mock_poll_response
            
            client = InteractshClient()
            interactions_received = []
            
            # Test timeout behavior
            async with client.interact(poll_interval=0.1) as session:
                try:
                    async with asyncio.timeout(0.5):
                        async for interaction in session:
                            interactions_received.append(interaction)
                except asyncio.TimeoutError:
                    pass  # Expected
            
            await client.close()
            
            # Should have no interactions due to empty response
            assert len(interactions_received) == 0
    
    @pytest.mark.asyncio
    async def test_interact_multiple_interactions(self):
        """Test interact with multiple interactions"""
        with patch('aiohttp.ClientSession.post') as mock_post, \
             patch('aiohttp.ClientSession.get') as mock_get:
            
            # Mock registration response
            mock_reg_response = AsyncMock()
            mock_reg_response.status = 200
            mock_reg_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_reg_response
            
            # Mock poll responses with multiple interactions
            interactions = [
                '{"protocol": "http", "unique-id": "test1", "full-id": "test1.example.com", "remote-address": "1.2.3.4", "timestamp": "2023-01-01T00:00:00Z"}',
                '{"protocol": "dns", "unique-id": "test2", "full-id": "test2.example.com", "remote-address": "5.6.7.8", "timestamp": "2023-01-01T00:00:01Z"}'
            ]
            
            # First poll returns interactions, subsequent polls return empty
            call_count = 0
            def poll_side_effect():
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return AsyncMock(
                        status=200,
                        json=AsyncMock(return_value={
                            'data': [],
                            'extra': interactions,
                            'aes_key': '',
                            'tlddata': []
                        })
                    )
                else:
                    return AsyncMock(
                        status=200,
                        json=AsyncMock(return_value={
                            'data': [],
                            'extra': [],
                            'aes_key': '',
                            'tlddata': []
                        })
                    )
            
            mock_get.return_value.__aenter__.side_effect = poll_side_effect
            
            client = InteractshClient()
            interactions_received = []
            
            # Collect all interactions with a timeout
            async with client.interact(poll_interval=0.1) as session:
                try:
                    async with asyncio.timeout(0.5):
                        async for interaction in session:
                            interactions_received.append(interaction)
                except asyncio.TimeoutError:
                    pass  # Expected after collecting all
            
            await client.close()
            
            # Should have received both interactions
            assert len(interactions_received) == 2
            assert interactions_received[0].protocol == "http"
            assert interactions_received[0].unique_id == "test1"
            assert interactions_received[1].protocol == "dns"
            assert interactions_received[1].unique_id == "test2"
    
    @pytest.mark.asyncio
    async def test_interact_error_handling(self):
        """Test interact error handling"""
        with patch('aiohttp.ClientSession.post') as mock_post, \
             patch('aiohttp.ClientSession.get') as mock_get:
            
            # Mock registration response
            mock_reg_response = AsyncMock()
            mock_reg_response.status = 200
            mock_reg_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_reg_response
            
            # Mock poll response that returns error
            mock_poll_response = AsyncMock()
            mock_poll_response.status = 500
            mock_poll_response.text = AsyncMock(return_value="Internal Server Error")
            mock_get.return_value.__aenter__.return_value = mock_poll_response
            
            client = InteractshClient()
            
            # Should handle polling errors gracefully
            async with client.interact(poll_interval=0.1) as session:
                try:
                    async with asyncio.timeout(0.5):
                        async for interaction in session:
                            pass  # Should not receive any due to error
                except asyncio.TimeoutError:
                    pass  # Expected
            
            await client.close()
    
    @pytest.mark.asyncio
    async def test_keep_alive_functionality(self):
        """Test keep-alive functionality"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            options = Options(
                server_url="https://oast.fun",
                keep_alive_interval=0.1
            )
            
            client = InteractshClient(options)
            await client._initialize()
            
            # Wait for keep-alive to trigger
            await asyncio.sleep(0.2)
            
            await client.close()
            
            # Keep-alive should have made additional registration calls
            assert mock_post.call_count > 1


class TestInteractionParsing:
    """Test cases for interaction parsing"""
    
    def test_interaction_creation(self):
        """Test Interaction dataclass creation"""
        interaction = Interaction(
            protocol="http",
            unique_id="test123",
            full_id="test123.example.com",
            remote_address="1.2.3.4"
        )
        
        assert interaction.protocol == "http"
        assert interaction.unique_id == "test123"
        assert interaction.full_id == "test123.example.com"
        assert interaction.remote_address == "1.2.3.4"
        assert interaction.timestamp is not None


class TestInteractionSession:
    """Test cases for InteractionSession"""
    
    @pytest.mark.asyncio
    async def test_session_context_manager(self):
        """Test session context manager behavior"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            client = InteractshClient()
            session = client.interact()
            
            # Test entering context
            async with session as s:
                assert s == session
                assert not session._closed
                assert session._poll_task is not None
            
            # After exiting context, session should be closed
            assert session._closed
            assert session._stop_event.is_set()
            
            await client.close()
    
    @pytest.mark.asyncio
    async def test_session_closed_client(self):
        """Test session with closed client"""
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={'message': 'registration successful'})
            mock_post.return_value.__aenter__.return_value = mock_response
            
            client = InteractshClient()
            await client._initialize()
            await client.close()
            
            # Should raise error when trying to use session with closed client
            with pytest.raises(ClientStateError, match="closed"):
                async with client.interact() as session:
                    pass


class TestOptions:
    """Test cases for Options configuration"""
    
    def test_default_options(self):
        """Test default options values"""
        options = Options()
        
        assert "oast.pro" in options.server_url
        assert options.token == ""
        assert options.disable_http_fallback is False
        assert options.correlation_id_length == 20
        assert options.correlation_id_nonce_length == 13
        assert options.keep_alive_interval == 0
    
    def test_custom_options(self):
        """Test custom options values"""
        options = Options(
            server_url="https://oast.fun",
            token="test-token",
            disable_http_fallback=True,
            correlation_id_length=15,
            correlation_id_nonce_length=10,
            keep_alive_interval=5.0
        )
        
        assert options.server_url == "https://oast.fun"
        assert options.token == "test-token"
        assert options.disable_http_fallback is True
        assert options.correlation_id_length == 15
        assert options.correlation_id_nonce_length == 10
        assert options.keep_alive_interval == 5.0


class TestIntegration:
    """Integration tests with real server (if available)"""
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_server_connection(self):
        """Test connection to real oast.fun server"""
        options = Options(server_url="https://oast.fun")
        client = InteractshClient(options)
        await client._initialize()
        
        # Generate URL
        url = await client.url()
        assert url != ""
        assert "oast.fun" in url
        
        await client.close()
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_interaction_polling(self):
        """Test real interaction polling (manual verification)"""
        options = Options(server_url="https://oast.fun")
        client = InteractshClient(options)
        await client._initialize()
        
        # Generate test URL
        test_url = await client.url()
        print(f"\nGenerated test URL: http://{test_url}")
        print("To test interactions, make requests to this URL in another terminal")
        
        interactions_received = []
        
        # Poll for a short time using async iterator
        try:
            async with client.interact(poll_interval=1.0) as session:
                async with asyncio.timeout(3.0):  # Poll for 3 seconds
                    async for interaction in session:
                        interactions_received.append(interaction)
                        print(f"Received {interaction.protocol} interaction from {interaction.remote_address}")
        except asyncio.TimeoutError:
            pass  # Expected timeout after 3 seconds
        
        await client.close()
        print(f"Total interactions received: {len(interactions_received)}")
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_interaction_with_http_request(self):
        """Test real interaction polling with actual HTTP request"""
        options = Options(server_url="https://oast.fun")
        client = InteractshClient(options)
        await client._initialize()
        
        # Generate test URL
        test_url = await client.url()
        http_url = f"http://{test_url}"
        print(f"Generated test URL: {http_url}")
        
        interactions_received = []
        
        # First make the HTTP request
        print(f"Making HTTP request to {http_url}")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(http_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    print(f"HTTP request completed with status: {response.status}, {await response.text()}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            print(f"HTTP request failed (expected): {e}")
        
        # Now poll for interactions
        print("Starting polling for interactions...")
        try:
            async with client.interact(poll_interval=1.0) as session:
                async with asyncio.timeout(5.0):  # Poll for up to 10 seconds
                    async for interaction in session:
                        print(f"Received interaction: {interaction.protocol} from {interaction.remote_address}")
                        interactions_received.append(interaction)
                        if len(interactions_received) >= 2:
                            break
        except asyncio.TimeoutError:
            print("Polling timed out")
        
        await client.close()
        
        print(f"Interactions received: {len(interactions_received)}")
        
        # Verify we received at least two interaction (DNS + HTTP)
        assert len(interactions_received) >= 2
        
        print(f"Successfully received HTTP interaction from {interaction.remote_address}")
        print(f"Full ID: {interaction.full_id}")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
