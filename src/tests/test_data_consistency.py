"""
Property tests for data model consistency
Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
"""

import pytest
from hypothesis import given, strategies as st
from datetime import datetime, timedelta
import uuid
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.device import Device, DeviceStatus
from models.esim_profile import eSIMProfile
from models.user import User
from models.ai_context import AIContext, AIMessage, AIServiceType
from models.mcp_models import MCPRequest, MCPResponse

# Hypothesis strategies for generating test data
device_status_strategy = st.sampled_from(list(DeviceStatus))
ai_service_type_strategy = st.sampled_from(list(AIServiceType))
user_role_strategy = st.sampled_from(["admin", "operator", "user"])

device_id_strategy = st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Pc")))
email_strategy = st.text(min_size=5, max_size=50, alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"))).map(lambda x: f"{x}@example.com")
uuid_strategy = st.uuids().map(str)

@given(
    device_id=device_id_strategy,
    device_type=st.text(min_size=1, max_size=20),
    status=device_status_strategy
)
def test_device_serialization_consistency(device_id, device_type, status):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any device data, serialization and deserialization should maintain consistency
    """
    # Create device
    device = Device(
        device_id=device_id,
        device_type=device_type,
        status=status,
        last_seen=datetime.utcnow(),
        metadata={"test": "data"}
    )
    
    # Serialize to dict
    device_dict = device.to_dict()
    
    # Deserialize back to object
    restored_device = Device.from_dict(device_dict)
    
    # Verify consistency
    assert restored_device.device_id == device.device_id
    assert restored_device.device_type == device.device_type
    assert restored_device.status == device.status
    assert restored_device.metadata == device.metadata
    assert device.validate()
    assert restored_device.validate()

@given(
    profile_id=uuid_strategy,
    iccid=st.text(min_size=15, max_size=20, alphabet=st.characters(whitelist_categories=("Nd",))),
    operator=st.text(min_size=1, max_size=50),
    plan_type=st.text(min_size=1, max_size=20)
)
def test_esim_profile_serialization_consistency(profile_id, iccid, operator, plan_type):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any eSIM profile data, serialization and deserialization should maintain consistency
    """
    # Create eSIM profile
    profile = eSIMProfile(
        profile_id=profile_id,
        iccid=iccid,
        operator=operator,
        plan_type=plan_type,
        activation_date=datetime.utcnow(),
        data_usage={"2024-01": 100, "2024-02": 200}
    )
    
    # Serialize to dict
    profile_dict = profile.to_dict()
    
    # Deserialize back to object
    restored_profile = eSIMProfile.from_dict(profile_dict)
    
    # Verify consistency
    assert restored_profile.profile_id == profile.profile_id
    assert restored_profile.iccid == profile.iccid
    assert restored_profile.operator == profile.operator
    assert restored_profile.plan_type == profile.plan_type
    assert restored_profile.data_usage == profile.data_usage
    assert profile.validate()
    assert restored_profile.validate()

@given(
    user_id=uuid_strategy,
    email=email_strategy,
    display_name=st.text(min_size=1, max_size=50),
    role=user_role_strategy
)
def test_user_serialization_consistency(user_id, email, display_name, role):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any user data, serialization and deserialization should maintain consistency
    """
    # Create user
    user = User(
        user_id=user_id,
        email=email,
        display_name=display_name,
        role=role,
        permissions=["read", "write"],
        preferences={"theme": "dark"}
    )
    
    # Serialize to dict
    user_dict = user.to_dict()
    
    # Deserialize back to object
    restored_user = User.from_dict(user_dict)
    
    # Verify consistency
    assert restored_user.user_id == user.user_id
    assert restored_user.email == user.email
    assert restored_user.display_name == user.display_name
    assert restored_user.role == user.role
    assert restored_user.permissions == user.permissions
    assert restored_user.preferences == user.preferences
    assert user.validate()
    assert restored_user.validate()

@given(
    context_id=uuid_strategy,
    user_id=uuid_strategy,
    message_content=st.text(min_size=1, max_size=1000),
    service_type=ai_service_type_strategy
)
def test_ai_context_serialization_consistency(context_id, user_id, message_content, service_type):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any AI context data, serialization and deserialization should maintain consistency
    """
    # Create AI context with messages
    context = AIContext(
        context_id=context_id,
        user_id=user_id,
        session_data={"session": "data"},
        preferences={"model": "gemini"}
    )
    
    # Add a message
    message = AIMessage.create_user_message(message_content, service_type)
    context.add_message(message)
    
    # Serialize to dict
    context_dict = context.to_dict()
    
    # Deserialize back to object
    restored_context = AIContext.from_dict(context_dict)
    
    # Verify consistency
    assert restored_context.context_id == context.context_id
    assert restored_context.user_id == context.user_id
    assert restored_context.session_data == context.session_data
    assert restored_context.preferences == context.preferences
    assert len(restored_context.conversation_history) == len(context.conversation_history)
    assert restored_context.conversation_history[0].content == message_content
    assert context.validate()
    assert restored_context.validate()

@given(
    request_id=uuid_strategy,
    service_name=st.text(min_size=1, max_size=50),
    method=st.text(min_size=1, max_size=50),
    parameters=st.dictionaries(st.text(min_size=1, max_size=20), st.text(min_size=1, max_size=100))
)
def test_mcp_request_serialization_consistency(request_id, service_name, method, parameters):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any MCP request data, serialization and deserialization should maintain consistency
    """
    # Create MCP request
    request = MCPRequest(
        request_id=request_id,
        service_name=service_name,
        method=method,
        parameters=parameters,
        priority=1,
        timeout=30
    )
    
    # Serialize to dict
    request_dict = request.to_dict()
    
    # Deserialize back to object
    restored_request = MCPRequest.from_dict(request_dict)
    
    # Verify consistency
    assert restored_request.request_id == request.request_id
    assert restored_request.service_name == request.service_name
    assert restored_request.method == request.method
    assert restored_request.parameters == request.parameters
    assert restored_request.priority == request.priority
    assert restored_request.timeout == request.timeout
    assert request.validate()
    assert restored_request.validate()

@given(
    request_id=uuid_strategy,
    success=st.booleans(),
    data=st.one_of(
        st.none(),
        st.dictionaries(st.text(min_size=1, max_size=20), st.text(min_size=1, max_size=100))
    ),
    error=st.one_of(st.none(), st.text(min_size=1, max_size=200))
)
def test_mcp_response_serialization_consistency(request_id, success, data, error):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any MCP response data, serialization and deserialization should maintain consistency
    """
    # Ensure valid response (success with data or error with message)
    if success and data is None:
        data = {"result": "success"}
    if not success and error is None:
        error = "Test error"
    
    # Create MCP response
    response = MCPResponse(
        request_id=request_id,
        success=success,
        data=data,
        error=error,
        processing_time=0.5,
        tokens_used=100
    )
    
    # Serialize to dict
    response_dict = response.to_dict()
    
    # Deserialize back to object
    restored_response = MCPResponse.from_dict(response_dict)
    
    # Verify consistency
    assert restored_response.request_id == response.request_id
    assert restored_response.success == response.success
    assert restored_response.data == response.data
    assert restored_response.error == response.error
    assert restored_response.processing_time == response.processing_time
    assert restored_response.tokens_used == response.tokens_used
    assert response.validate()
    assert restored_response.validate()

@given(
    device_id=device_id_strategy,
    operator=st.text(min_size=1, max_size=50),
    plan_type=st.text(min_size=1, max_size=20)
)
def test_device_esim_profile_relationship_consistency(device_id, operator, plan_type):
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any device with eSIM profile, the relationship should maintain consistency
    """
    # Create eSIM profile for device
    profile = eSIMProfile.create_new(device_id, operator, plan_type)
    
    # Create device with profile
    device = Device(
        device_id=device_id,
        device_type="smartphone",
        status=DeviceStatus.ACTIVE,
        esim_profile=profile
    )
    
    # Serialize and deserialize
    device_dict = device.to_dict()
    restored_device = Device.from_dict(device_dict)
    
    # Verify relationship consistency
    assert restored_device.esim_profile is not None
    assert restored_device.esim_profile.operator == operator
    assert restored_device.esim_profile.plan_type == plan_type
    assert device_id in restored_device.esim_profile.profile_id
    assert device.validate()
    assert restored_device.validate()
    assert restored_device.esim_profile.validate()

def test_concurrent_data_operations_consistency():
    """
    Feature: igsim-ai-agent-platform, Property 33: Data Consistency and Integrity
    For any concurrent data operations, consistency should be maintained
    """
    import threading
    import time
    
    # Shared data structure
    shared_context = AIContext.create_new("test_user")
    results = []
    
    def add_messages(thread_id):
        """Add messages concurrently"""
        for i in range(10):
            message = AIMessage.create_user_message(
                f"Message {i} from thread {thread_id}",
                AIServiceType.GEMINI
            )
            shared_context.add_message(message)
            time.sleep(0.001)  # Small delay to simulate real operations
        results.append(thread_id)
    
    # Create multiple threads
    threads = []
    for i in range(3):
        thread = threading.Thread(target=add_messages, args=(i,))
        threads.append(thread)
    
    # Start all threads
    for thread in threads:
        thread.start()
    
    # Wait for completion
    for thread in threads:
        thread.join()
    
    # Verify consistency
    assert len(results) == 3  # All threads completed
    assert len(shared_context.conversation_history) == 30  # All messages added
    assert shared_context.validate()
    
    # Verify message integrity
    for message in shared_context.conversation_history:
        assert message.validate()
        assert "Message" in message.content
        assert "thread" in message.content

if __name__ == "__main__":
    # Run property tests with increased iterations
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])