import logging
import mimetypes
import os
import subprocess
import sys
import re
import urllib.parse
from datetime import datetime, timedelta
from django.views.generic import CreateView

from django.urls import reverse_lazy
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.http import Http404, HttpResponseRedirect, HttpResponseForbidden, JsonResponse
from django.http import HttpResponse
from django_filters.filters import _truncate
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.db.models import Q
from dojo.celery import app
from dojo.endpoint.views import get_endpoint_ids
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Dojo_User, Endpoint, Risk_Acceptance
from django.views.generic import ListView
#from .models import Client
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting, get_period_counts_legacy, Product_Tab, \
    get_words_for_field, redirect
from dojo.user.helper import check_auth_users_list
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission_or_403
from rest_framework.authtoken.models import Token


logger = logging.getLogger(__name__)

class trscan(CreateView):
    success_url = reverse_lazy("RunStatic")

def RunStatic(request):
    
    host = trscan_url_resolver(request)
    import os.path

    
    #try:
        # For compatibility to Python 3.6 res=subprocess.run(['cat','/tmp/text.txt'], capture_output=True, text=True).stdout is not used
        #res = subprocess.run(['wine C:\\Security Reviewer\\SRCheck.bat', '-a', '-v', '-p'], stdout=subprocess.PIPE, universal_newlines=True).stdout
        #for line in iter(res.stdout.readline, b''): 
        #    print(line.strip())
        #    sys.stdout.flush()
        #now = datetime.now() 
        #date_time = now.strftime("%m/%d/%Y, %H:%")
        #res = "Started at " + str(date_time)
        # return render('results.html', {'res':res.decode("utf-8")}, context_instance=RequestContext(request))
        #return render('results.html', {'res':res.decode("utf-8")})

    #except Exception as e:
    	#return render('results.html', {'res':e})
    if os.getenv('WINEPREFIX'):
        now = datetime.now() 

        msg = f'Analysis Started at: {now}'

    else:
        msg = f'Missed Static Reviewer executable'
    
    return HttpResponse(msg, content_type='text/plain')

def down(request):
    return render(request, 'disabled.html')

def upload_media(request):
    if request.method == 'POST':
        source_folder = request.FILES['media']

def trscan_url_resolver(request):
    try:
        url_resolver = request.META['HTTP_X_FORWARDED_PROTO'] + "://" + request.META['HTTP_X_FORWARDED_FOR']
    except:
        hostname = request.META['HTTP_HOST']
        port_index = hostname.find(":")
        if port_index != -1:
            url_resolver = request.scheme + "://" + hostname[:port_index]
        else:
            url_resolver = request.scheme + "://" + hostname
    return url_resolver + ":" + request.META['SERVER_PORT']


def trscan(request):
    add_breadcrumb(title="Static Analysis", top_level=True, request=request)
    findings = Finding.objects.all()
    #findings = ReportAuthedFindingFilter(request.GET, queryset=findings)

    api_key = ''
    api_key = Token.objects.get(user=request.user)
    return render(request,
                  'dojo/TRScan.html',
                  {"key": api_key})

def validate_date(date, filter_lookup):
    # Today
    if date == 1:
        filter_lookup['date__year'] = now().year
        filter_lookup['date__month'] = now().month
        filter_lookup['date__day'] = now().day
    # Past 7 Days
    elif date == 2:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=7))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))
    # Past 30 Days
    elif date == 3:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=30))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))
    # Past 90 Days
    elif date == 4:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=90))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))
    # Current Month
    elif date == 5:
        filter_lookup['date__year'] = now().year
        filter_lookup['date__month'] = now().month
    # Current Year
    elif date == 6:
        filter_lookup['date__year'] = now().year
    # Past Year
    elif date == 7:
        filter_lookup['date__gte'] = _truncate(now() - timedelta(days=365))
        filter_lookup['date__lt'] = _truncate(now() + timedelta(days=1))


def validate(field, value):
    validated_field = field
    validated_value = None
    # Boolean values
    if value in ['true', 'false', 'unknown']:
        if value == 'true':
            validated_value = True
        elif value == 'false':
            validated_value = False
    # Tags (lists)
    elif 'tags' in field:
        validated_field = value.split(', ')
        validated_field = field + '__in'
    else:
        # Integer (ID) values
        try:
            validated_value = int(value)
            if field not in ['nb_occurences', 'nb_occurences', 'date', 'cwe']:
                validated_field = field + '__id'
        except ValueError:
            # Okay it must be a string
            validated_value = None if not len(value) else value
    return (validated_field, validated_value)


#class TRScanTable(ListView):
#    model = Client
#    template_name = "TRScanTable.html"



