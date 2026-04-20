
import requests

def test_api():
    try:
        r = requests.get("http://localhost:8000/nodes")
        print(f"Status: {r.status_code}")
        print(f"Nodes: {r.json()}")
    except Exception as e:
        print(f"API Error: {e}")

if __name__ == "__main__":
    test_api()
