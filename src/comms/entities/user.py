class User:
    def __init__(self, user_id: int, username: str):
        self.user_id = user_id
        self.username = username

    def __str__(self):
        return f"User(id={self.user_id}, username='{self.username}')"
