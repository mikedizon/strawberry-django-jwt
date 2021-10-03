from django.db import models


class MyTestModel(models.Model):
    id = models.AutoField(primary_key=True)
    test = models.CharField(max_length=100)

    class Meta:
        app_label = "tests"
