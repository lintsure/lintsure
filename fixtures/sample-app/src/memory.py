# Planted: memories are added and never removed.
from mem0 import Memory

memory = Memory()

def remember(user_id, text):
    memory.add(text, user_id=user_id)
