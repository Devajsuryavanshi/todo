from django.db import models
from django.contrib.auth.models import User

class Todo(models.Model):
    title = models.CharField(max_length=100)
    memo = models.TextField(blank=True)
    Ctime = models.DateTimeField(auto_now_add=True)
    completedTime = models.DateTimeField(null=True, blank=True)
    important = models.BooleanField(default=False) 
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title
