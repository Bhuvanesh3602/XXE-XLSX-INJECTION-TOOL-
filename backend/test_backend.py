import requests
import json

def test_backend():
    base_url = "http://localhost:5000/api"
    
    print("🔍 Testing XXE XLSX Tool Backend...")
    print("=" * 50)
    
    # Test 1: Health Check
    print("\n1. Testing Health Check...")
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health Check: {data['status']}")
            print(f"   Message: {data['message']}")
            print(f"   Version: {data['version']}")
        else:
            print(f"❌ Health Check Failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health Check Error: {e}")
    
    # Test 2: Generate Payloads
    print("\n2. Testing Payload Generation...")
    try:
        payload_data = {
            "target_url": "http://internal.server/resource",
            "collaborator": "https://test.burpcollaborator.net",
            "attack_type": "all"
        }
        
        response = requests.post(f"{base_url}/generate-payloads", json=payload_data)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Payload Generation: {data['success']}")
            print(f"   Generated {data['count']} payloads")
            
            # Show first payload as example
            if data['payloads']:
                first_payload = data['payloads'][0]
                print(f"   Example: {first_payload['name']} ({first_payload['type']})")
        else:
            print(f"❌ Payload Generation Failed: {response.status_code}")
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"❌ Payload Generation Error: {e}")
    
    # Test 3: Invalid Payload Generation
    print("\n3. Testing Invalid Input Handling...")
    try:
        invalid_data = {
            "attack_type": "invalid_type"
        }
        
        response = requests.post(f"{base_url}/generate-payloads", json=invalid_data)
        if response.status_code == 400:
            print("✅ Invalid Input Properly Handled")
        else:
            print(f"❌ Invalid Input Not Handled: {response.status_code}")
    except Exception as e:
        print(f"❌ Invalid Input Test Error: {e}")
    
    print("\n" + "=" * 50)
    print("Backend testing completed!")

if __name__ == "__main__":
    test_backend()