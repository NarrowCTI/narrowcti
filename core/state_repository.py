import json
import os


DEFAULT_STATE_KEY = "pulses"


def load_state(state_file, collection_key=DEFAULT_STATE_KEY):
    if not os.path.exists(state_file):
        return {collection_key: []}

    with open(state_file, "r") as f:
        try:
            data = json.load(f)
        except Exception:
            return {collection_key: []}

    if not isinstance(data, dict):
        return {collection_key: []}

    if collection_key not in data or not isinstance(data[collection_key], list):
        data[collection_key] = []

    return data


def save_state(state_file, state):
    directory = os.path.dirname(state_file)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(state_file, "w") as f:
        json.dump(state, f)


class ProcessedItemStateRepository:
    def __init__(self, state_file, collection_key):
        self.state_file = state_file
        self.collection_key = collection_key
        self.state = load_state(state_file, collection_key)

    def refresh(self):
        self.state = load_state(self.state_file, self.collection_key)

    def has_item(self, item_id):
        self.refresh()
        return item_id in self.state[self.collection_key]

    def mark_item(self, item_id):
        self.refresh()
        if item_id in self.state[self.collection_key]:
            return

        self.state[self.collection_key].append(item_id)
        save_state(self.state_file, self.state)


class PulseStateRepository(ProcessedItemStateRepository):
    def __init__(self, state_file):
        super().__init__(state_file, "pulses")

    def has_pulse(self, pulse_id):
        return self.has_item(pulse_id)

    def mark_pulse(self, pulse_id):
        self.mark_item(pulse_id)


class MISPEventStateRepository(ProcessedItemStateRepository):
    def __init__(self, state_file):
        super().__init__(state_file, "misp_events")

    def has_event(self, event_id):
        return self.has_item(event_id)

    def mark_event(self, event_id):
        self.mark_item(event_id)
