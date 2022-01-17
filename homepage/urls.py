# -*- coding: utf-8 -*- THOMAS ELDHO 20BCT0113

from django.urls import path
from . import views
urlpatterns=[
   path('',views.home,name='homepage'),#initially when no action is done home in views is called which requests index.html 
   path('result',views.result,name='result')#when 'result' is called it calls the function result in views which requests result.html
   ]
