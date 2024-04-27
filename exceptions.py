
class DisplayableException(Exception):
    """
    An exception that has a message that can be displayed to the user.
    """
    def __init__ (self, displayMessage):
        self.displayMessage = displayMessage
    def __str__(self):
        return self.displayMessage