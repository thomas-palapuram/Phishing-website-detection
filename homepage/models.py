from django.db import models

# Create your models here.
class details(models.Model):
    domain_name=models.CharField(max_length=2000)
    rank=models.BigIntegerField()
    ip_check=models.IntegerField()
    valid=models.IntegerField()
    active_duration=models.IntegerField()
    urlLEn=models.IntegerField()
    at_check=models.IntegerField()
    redirect_check=models.IntegerField()
    have_dash=models.IntegerField()
    domain_len=models.IntegerField()
    nu_of_subdomain=models.IntegerField()
    result=models.IntegerField()