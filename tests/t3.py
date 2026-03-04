import pickle

def load_user_session(data):
    # unsafe pickle on untrusted data
    return pickle.loads(data)

with open("session.pkl", "rb") as f:
    session = load_user_session(f.read())