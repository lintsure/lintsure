# Near miss: memories can be removed again.
from mem0 import Memory

memory = Memory()

def remember(user_id, text):
    memory.add(text, user_id=user_id)

def forget(user_id):
    memory.delete_all(user_id=user_id)
