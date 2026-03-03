import pickle

def load_user_session(data):
    # MEDIUM/HIGH RISK: pickle.load is dangerous on untrusted data
    # It can lead to Remote Code Execution (RCE)
    return pickle.loads(data)

with open("session.pkl", "rb") as f:
    session = load_user_session(f.read())