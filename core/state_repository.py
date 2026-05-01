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
    directory = os.path.dirname(state_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(state_file, "w") as f:
        json.dump(state, f)


class PulseStateRepository:
    def __init__(self, state_file):
        self.state_file = state_file
        self.state = load_state(state_file)

    def has_pulse(self, pulse_id):
        return pulse_id in self.state["pulses"]

    def mark_pulse(self, pulse_id):
        if self.has_pulse(pulse_id):
            return

        self.state["pulses"].append(pulse_id)
        save_state(self.state_file, self.state)
