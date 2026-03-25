class User:
    def __init__(self, user_id: int, username: str):
        self.user_id = user_id
        self.username = username

    def __str__(self):
        return f"User(id={self.user_id}, username='{self.username}')"


class Channel:
    def __init__(self, channel_id: int, name: str):
        self.channel_id = channel_id
        self.name = name

    def __str__(self):
        return f"Channel(id={self.channel_id}, name='{self.name}')"
