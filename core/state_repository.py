import json
import os


def load_state(state_file):
    if not os.path.exists(state_file):
        return {"pulses": []}

    with open(state_file, "r") as f:
        try:
            data = json.load(f)
            if "pulses" not in data:
                data["pulses"] = []
            return data
        except Exception:
            return {"pulses": []}


def save_state(state_file, state):
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(state_file, "w") as f:
        json.dump(state, f)
