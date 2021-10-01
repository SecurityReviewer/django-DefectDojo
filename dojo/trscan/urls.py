from django.conf.urls import url

from dojo.trscan import views

urlpatterns = [
    #  trscan
    url(r'^trscan$',
        views.trscan, name='trscan'),
    url(r'^trscan/RunStatic$',
        views.RunStatic, name='RunStatic'),
]
