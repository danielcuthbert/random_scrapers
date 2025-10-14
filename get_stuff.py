import requests, json

def bbc_data():
  try:
    r = requests.get("https://www.bbc.co.uk/")
    r.raise_for_status()
    data = {"title": "BBC Homepage", "length": len(r.text)}
    return json.dumps(data, indent=4)
  except:
    return None

if __name__ == "__main__":
  print(bbc_data())
