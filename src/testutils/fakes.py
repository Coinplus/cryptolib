import datetime


class FakeTimeSource(object):

    def __init__(self, time=0):
        self.time = time

    def get_time(self):
        return self.time

    def get_time_us(self):
        return self.time

    def get_utcnow(self):
        return datetime.datetime.utcfromtimestamp(self.time)
