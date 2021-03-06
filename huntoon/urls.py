"""huntoon URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views import *
from django.conf.urls.static import static
#from django.conf.urls import patterns, include, url
from django.conf import settings
from django.conf.urls import (handler400, handler403, handler404, handler500)

urlpatterns = [
    # path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('encode/', my_encode, name='encode'),
    path('decode/', my_decode, name='decode'),
    path('encrypt/', encrypt, name='encrypt'),
    path('decrypt/', decrypt, name='decrypt'),
    path('download/', download, name='download'),
]

handler404 = 'huntoon.views.mypagenotfound'
handler500 = 'huntoon.views.myservererror'
handler403 = 'huntoon.views.mypermissiondenied'
handler400 = 'huntoon.views.mybadrequest'

#if settings.DEBUG:
 #   urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
