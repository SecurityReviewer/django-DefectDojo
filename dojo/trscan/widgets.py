import abc
import json
from datetime import datetime, date
from collections import OrderedDict

from django import forms
from django.forms import Widget as form_widget
from django.forms.fields import FilePathField
from django.forms.utils import flatatt
from django.http import QueryDict
from django.template.loader import render_to_string
from django.utils.encoding import force_text
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from dojo.filters import EndpointFilter
from dojo.models import Endpoint, Finding
from dojo.utils import get_page_items, get_words_for_field

#from .views import RunStatic

"""
Widgets are content sections that can be included on reports.  The report builder will allow any number of widgets
 to be included.  Each widget will provide a set of options, reporesented by form elements, to be included.
"""


class CustomReportJsonForm(forms.Form):
    json = forms.CharField()

    def clean_json(self):
        jdata = self.cleaned_data['json']
        try:
            json_data = json.loads(jdata)
        except:
            raise forms.ValidationError("Invalid data in json")
        return jdata

class ExclusionContentForm(forms.Form):
    exclusions = forms.FilePathField(label="Exclusions", allow_files=True, allow_folders=False, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Specify the Exclusion List file", widget=forms.ClearableFileInput(attrs={'multiple': True}))
    
    class Meta:
        exclude = []

class FPContentForm(forms.Form):
    FPositives = forms.FilePathField(label="False Positives", allow_files=True, allow_folders=False, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Specify the False Positives List file", widget=forms.ClearableFileInput(attrs={'multiple': True}))
    
    class Meta:
        exclude = []

class AnalysisContentForm(forms.Form):

    linesBefore = forms.IntegerField(required=False,  
                     label= "Source Code Lines Before", initial=5) 
    linesAfter = forms.IntegerField(required=False,  
                     label= "Source Code Lines After", initial=4)
    warningTimeOut = forms.IntegerField(required=False,  
                     label= "Warning TimeOut", initial=50) 
    maxVulnPerLine = forms.IntegerField(required=False,  
                     label= "Max vulnerabilities per line of code", initial=3) 
    maxVulnIssues = forms.IntegerField(required=False,  
                     label= "Max vulnerabilities issues", initial=1500)
    applyExclusionList = forms.BooleanField(required=False, label="Apply Exclusion List", initial=True)
    trustedApplication = forms.BooleanField(required=False, label="Trusted Application", initial=True)
    internetApplication = forms.BooleanField(required=False, label="Internet Application", initial=False)

    TARGETBROWSER_CHOICES = (
	    ('Any', 'Any Browser'),
	    ('Edge_Chromium', 'Internet Explorer Edge Chromium'),
	    ('Edge', 'Internet Explorer Edge'),
	    ('IE11','Internet Explorer 11'),
	    ('IE8_10','Internet Explorer (8-10)'),
	    ('IE6_7','Internet Explorer (6-7)'),
	    ('Chrome','Chrome'),
	    ('Safari','Safari'),
	    ('FireFox','FireFox'),
	    ('Opera_Chromium','Opera Chromium'),
	    ('Opera','Opera'),
    )

    targetBrowser = forms.ChoiceField(choices=TARGETBROWSER_CHOICES, required=False, label='Target Browser')

    attackVectors = forms.BooleanField(required=False, label="Attack Vectors", initial=False)
    baseline = forms.BooleanField(required=False, label="Baseline", initial=False)
    trusted = forms.CharField(label="Trusted Environments", required=False, max_length=1, widget = forms.TextInput(attrs={'readonly':'readonly'}))
    publicFunctions = forms.BooleanField(required=False, label="Public Functions", initial=True)
    dbQueries = forms.BooleanField(required=False, label="DB Queries", initial=True)
    envVariables = forms.BooleanField(required=False, label="Environment Variables", initial=False)
    socket = forms.BooleanField(required=False, label="Socket", initial=False)
    servlet = forms.BooleanField(required=False, label="Servlet/WS Requests", initial=False)
    noDeadCode = forms.BooleanField(required=False, label=".NET - No Dead Code for Partial Classes", initial=True)
    defaultSourceFolder = forms.FilePathField(label="Default Source Folder", allow_files=False, allow_folders=True, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Specify the Default Source Folder", widget=forms.ClearableFileInput(attrs={'multiple': True}))
    
    
    class Meta:
        exclude = []

class LanguageContentForm(forms.Form):
    cpp = forms.CharField(label="C/C++", required=False, max_length=1, widget = forms.TextInput(attrs={'readonly':'readonly'}))
    TARGETCPP_CHOICES = (
	    ('cppPosix', 'posix'),
	    ('cppC89', 'c89'),
	    ('cppC99', 'c99'),
	    ('cppC11', 'c11'),
	    ('cppCpp03', 'c++03'),
	    ('cppCpp11', 'c++11'),
	    ('cppCpp14', 'c++14'),
	    ('cppCpp17', 'c++17'),
	    ('cppEmbedded', 'Embedded'),
	    ('cppUnixLinux32','Unix/Linux 32'),
	    ('cppUnixLinu64','Unix/Linux 64'),
	    ('cppWin32A','Win32A (ASCII)'),
	    ('cppWin32W','Win32W (UNICODE)'),
	    ('cppWin64','Win64'),
    )

    targetCPP = forms.ChoiceField(choices=TARGETCPP_CHOICES, label="C/C++ Target Platforms", required=False, initial='posix')

    TARGETSET_CHOICES = (
	    ('setGCC','GCC'),
	    ('setIBMXL','IBM XL C/C++'),
	    ('setHP','HP C/ac++'),
	    ('setSun','Sun Pro C/C++'),
	    ('setLLVM','LLVM Clang'),
	    ('setARM','ARM RealView'),
	    ('setARC','ARC MQX Synopsys'),
	    ('setAtmel','Atmel AVR Studio'),
	    ('setAtollic','Atollic True Studio'),
	    ('setAvocet','Avocet ProTools'),
	    ('setBatronix','Batronix uC51'),
	    ('setBiPOM','BiPOM Electronics'),
	    ('setByte','Byte Craft eTPU C'),
	    ('setCCS','CCS PIC/dsPIC/DSC'),
	    ('setCeibo','Ceibo-8051C++'),
	    ('setCodeWarrior','CodeWarrior'),
	    ('setCosmic','Cosmic Software'),
	    ('setCrossware','Crossware'),
	    ('setELLCC','ELLCC C/C++'),
	    ('setGreenHills','Green Hills Multi'),
	    ('setHighTec','HighTec'),
	    ('setIAR','IAR C/C++'),
	    ('setINRIA','INRIA CompCert'),
	    ('setIntel','Intel C/C++'),
	    ('setIntrol','Introl C Compiler'),
	    ('setKeil','Keil ARm C/C++'),
	    ('setMentor','Mentor Graphics CodeSourcery'),
	    ('setMicroChip','MicroChip MPLAB'),
	    ('setMikroC','MikroC Pro'),
	    ('setNXP','NXP'),
	    ('setRenesas','Renesas HEW'),
	    ('setSDCC','SDCC'),
	    ('setSoftools','Softools Z/Rabbit'),
	    ('setTasking','Tasking ESD'),
	    ('setTexas','Texas Instruments CodeComposer'),
	    ('setZWorld','Z World Dynamic C32'),
	    ('setWDC','WDC 8/16-bit'),
	    ('setWind','Wind River C/C++'),
    )

    targetSet = forms.ChoiceField(choices=TARGETSET_CHOICES, label="C/C++ Compiler", required=False, initial='GCC')

    CERTMISRACERT_CHOICES = (
	    ('Misra', 'MISRA'),
	    ('Cert', 'CERT'),
    )

    targetCertMisra = forms.CharField(max_length=5, widget=forms.Select(choices=CERTMISRACERT_CHOICES), required=False, label='Industry Standard')

    cobol = forms.CharField(label="COBOL", required=False, max_length=1, widget = forms.TextInput(attrs={'readonly':'readonly'}))

    TARGETCOBOL_CHOICES = (
	    ('IBMZOS', 'IBM z/OS Enterprise COBOL'),
	    ('IBMILE', 'IBM ILE COBOL (iSeries)'),
	    ('VisualCobol', 'Visual COBOL (Micro Focus)'),
	    ('MicroFocus', 'Micro Focus COBOL'),	
            ('NetCobol', 'NetCOBOL (Fujitsu/GTSoftware)'),
	    ('GNUCobol', 'GnuCOBOL (formerly OpenCOBOL)'),
	    ('MCP', 'MCP (Unisys)'),
	    ('Teradata', 'Teradata IMS COBOL'),
	    ('CobolIT', 'COBOL-IT'),
	    ('RainCode', 'RainCode COBOL'),
	    ('Elastic', 'Elastic COBOL'),
	    ('Veryant', 'Veryant isCOBOL Evolve'),
    )

    targetCobol = forms.ChoiceField(choices=TARGETCOBOL_CHOICES, required=False, label='Target COBOL Version', help_text="* Legacy Versions, like AcuCOBOL-GT, VS-COBOL-II, Oracle*Pro COBOL, RM-COBOL, Hitachi COBOL or CA-REALIA, are not reported because they are discontinued")

    STATEMENT_CHOICES = (
	    ('COBOL88', '88'),
	    ('COBOL132', '132'),
	    ('COBOLFree', 'Free Format'),
    )
    report_type = forms.ChoiceField(choices=STATEMENT_CHOICES, required=False, label='Statement Length', initial='88')
    # statementCobol = forms.CharField(max_length=29, widget=forms.Select(choices=STATEMENT_CHOICES), required=False, label='Statement Length', initial='88')

    untrustedWS = forms.BooleanField(required=False, label="Untrusted Working Storage", initial=False)
    allowCICSProgramming = forms.BooleanField(required=False, label="Allow CICS System Programming", initial=True)
    copybookFolder = forms.FilePathField(label="CopyBooks Folder", allow_files=False, allow_folders=True, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Specify the CopyBooks Folder", widget=forms.ClearableFileInput(attrs={'multiple': True}))

    rubyLang = forms.CharField(label="Ruby", required=False, max_length=1, widget = forms.TextInput(attrs={'readonly':'readonly'}))
    rubyFolder = forms.FilePathField(label="Ruby Folder", allow_files=False, allow_folders=True, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Specify the Ruby installation Folder", widget=forms.ClearableFileInput(attrs={'multiple': True}))


    pythonLang = forms.CharField(label="Python", required=False, max_length=1, widget = forms.TextInput(attrs={'readonly':'readonly'}))
    pythonFolder = forms.FilePathField(label="Python Folder", allow_files=False, allow_folders=True, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Specify the Python installation Folder", widget=forms.ClearableFileInput(attrs={'multiple': True}))
    
    class Meta:
        exclude = []

class OpenXMLContentForm(forms.Form):
    xmlAnalysis = forms.FilePathField(label="Analysis XML", allow_files=True, allow_folders=False, path="/home/securityreviewer/.wine/drive_c/", recursive=True, help_text="Load an Analysis from XML", widget=forms.ClearableFileInput(attrs={'multiple': True}))
    
    class Meta:
        exclude = []


class Div(form_widget):
    def __init__(self, attrs=None):
        # Use slightly better defaults than HTML's 20x2 box
        default_attrs = {'style': 'width:100%;min-height:400px'}
        if attrs:
            default_attrs.update(attrs)
        super(Div, self).__init__(default_attrs)

    def render(self, name, value, attrs=None, renderer=None):
        if value is None:
            value = ''
        final_attrs = self.build_attrs(attrs)
        return format_html(
            '<div class="btn-toolbar" data-role="editor-toolbar" data-target=""><div class="btn-group">'
            '<a class="btn btn-default" data-edit="bold" title="Bold (Ctrl/Cmd+B)"><i class="fa fa-bold"></i></a>'
            '<a class="btn btn-default" data-edit="italic" title="Italic (Ctrl/Cmd+I)"><i class="fa fa-italic"></i></a>'
            '<a class="btn btn-default" data-edit="strikethrough" title="Strikethrough">'
            '<i class="fa fa-strikethrough"></i></a>'
            '<a class="btn btn-default" data-edit="underline" title="Underline (Ctrl/Cmd+U)">'
            '<i class="fa fa-underline"></i></a></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="insertunorderedlist" title="Bullet list">'
            '<i class="fa fa-list-ul"></i></a>'
            '<a class="btn btn-default" data-edit="insertorderedlist" title="Number list">'
            '<i class="fa fa-list-ol"></i></a>'
            '<a class="btn btn-default" data-edit="outdent" title="Reduce indent (Shift+Tab)"><i class="fa fa-outdent">'
            '</i></a><a class="btn btn-default" data-edit="indent" title="Indent (Tab)"><i class="fa fa-indent"></i>'
            '</a></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="justifyleft" title="Align Left (Ctrl/Cmd+L)">'
            '<i class="fa fa-align-left"></i></a>'
            '<a class="btn btn-default" data-edit="justifycenter" title="Center (Ctrl/Cmd+E)">'
            '<i class="fa fa-align-center"></i></a>'
            '<a class="btn btn-default" data-edit="justifyright" title="Align Right (Ctrl/Cmd+R)">'
            '<i class="fa fa-align-right"></i></a>'
            '<a class="btn btn-default" data-edit="justifyfull" title="Justify (Ctrl/Cmd+J)">'
            '<i class="fa fa-align-justify"></i></a></div><div class="btn-group">'
            '<a class="btn btn-default dropdown-toggle" data-toggle="dropdown" title="Hyperlink">'
            '<i class="fa fa-link"></i></a><div class="dropdown-menu input-append">'
            '<input placeholder="URL" type="text" data-edit="createLink" />'
            '<button class="btn" type="button">Add</button></div></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="unlink" title="Remove Hyperlink">'
            '<i class="fa fa-unlink"></i></a></div><div class="btn-group">'
            '<a class="btn btn-default" data-edit="undo" title="Undo (Ctrl/Cmd+Z)">'
            '<i class="fa fa-undo"></i></a><a class="btn btn-default" data-edit="redo" title="Redo (Ctrl/Cmd+Y)">'
            '<i class="fa fa-repeat"></i></a></div><br/><br/></div><div{}>\r\n{}</div>',
            flatatt(final_attrs),
            force_text(value))

# base Widget class others will inherit from
class Widget(object):
    def __init__(self, *args, **kwargs):
        self.title = 'Base Widget'
        self.form = None
        self.multiple = "false"

    @abc.abstractmethod
    def get_html(self, request):
        return

    @abc.abstractmethod
    def get_asciidoc(self):
        return

    @abc.abstractmethod
    def get_option_form(self):
        return

class TrscanOptions(Widget):
    def __init__(self, *args, **kwargs):
        super(TrscanOptions, self).__init__(*args, **kwargs)
        self.title = 'Scan Details'
        self.form = TrscanOptionsForm()
        self.extra_help = "Fill out the following field and press Save and Run"
        

    class Meta:
        exclude = []

    def get_asciidoc(self):
        return mark_safe('')

    def get_html(self):
        return mark_safe('')

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)

class ExclusionContent(Widget):
    def __init__(self, *args, **kwargs):
        super(ExclusionContent, self).__init__(*args, **kwargs)
        self.title = 'Exclusion List'
        self.form = ExclusionContentForm()
        self.extra_help = "Select the Exclusion List File"
        

    class Meta:
        exclude = []

    def get_asciidoc(self):
        return mark_safe('')

    def get_html(self):
        return mark_safe('')

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)

class FPContent(Widget):
    def __init__(self, *args, **kwargs):
        super(FPContent, self).__init__(*args, **kwargs)
        self.title = 'False Positives'
        self.form = FPContentForm()
        self.extra_help = "Select the False Positives File"
        

    class Meta:
        exclude = []

    def get_asciidoc(self):
        return mark_safe('')

    def get_html(self):
        return mark_safe('')

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)

class AnalysisContent(Widget):
    def __init__(self, *args, **kwargs):
        super(AnalysisContent, self).__init__(*args, **kwargs)
        self.title = 'Analysis Options'
        self.form = AnalysisContentForm()
        self.extra_help = "Check the Analysis Options"
        
    class Meta:
        exclude = []

    def get_asciidoc(self):
        return mark_safe('')

    def get_html(self):
        return mark_safe('')

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)

class LanguageContent(Widget):
    def __init__(self, *args, **kwargs):
        super(LanguageContent, self).__init__(*args, **kwargs)
        self.title = 'Language Options'
        self.form = LanguageContentForm()
        self.extra_help = "Check the Language Options"
        

    class Meta:
        exclude = []

    def get_asciidoc(self):
        return mark_safe('')

    def get_html(self):
        return mark_safe('')

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)

class OpenXMLContent(Widget):
    def __init__(self, *args, **kwargs):
        super(OpenXMLContent, self).__init__(*args, **kwargs)
        self.title = 'Open XML Analysis'
        self.form = OpenXMLContentForm()
        self.extra_help = "Load a Scan from XML"
        

    class Meta:
        exclude = []

    def get_asciidoc(self):
        return mark_safe('')

    def get_html(self):
        return mark_safe('')

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title,
                                                            "extra_help": self.extra_help})
        return mark_safe(html)

class LoadFilesContent(Widget):
    def __init__(self, *args, **kwargs):
        super(LoadFilesContent, self).__init__(*args, **kwargs)
        self.title = 'Load Files'
        self.form = LoadFilesContentForm()
        self.multiple = 'true'

    def get_html(self):
        html = render_to_string("dojo/custom_html_report_wysiwyg_content.html", {"title": self.title,
                                                                                "content": self.content})
        return mark_safe(html)

    def get_asciidoc(self):
        asciidoc = render_to_string("dojo/custom_asciidoc_report_wysiwyg_content.html", {"title": self.title,
                                                                                         "content": self.content})
        return mark_safe(asciidoc)

    def get_option_form(self):
        html = render_to_string("dojo/report_widget.html", {"form": self.form,
                                                            "multiple": self.multiple,
                                                            "title": self.title})
        return mark_safe(html)


class FindingList(Widget):
    def __init__(self, *args, **kwargs):
        if 'request' in kwargs:
            self.request = kwargs.get('request')
        if 'user_id' in kwargs:
            self.user_id = kwargs.get('user_id')

        if 'host' in kwargs:
            self.host = kwargs.get('host')

        if 'findings' in kwargs:
            self.findings = kwargs.get('findings')
        else:
            raise Exception("Need to instantiate with finding queryset.")

        if 'finding_notes' in kwargs:
            self.finding_notes = kwargs.get('finding_notes')
        else:
            self.finding_notes = False

        if 'finding_images' in kwargs:
            self.finding_images = kwargs.get('finding_images')
        else:
            self.finding_images = False

        super(FindingList, self).__init__(*args, **kwargs)

        self.title = 'Finding List'
        if hasattr(self.findings, 'form'):
            self.form = self.findings.form
        else:
            self.form = None
        self.multiple = 'true'
        self.extra_help = "You can use this form to filter Findings and select only the ones regarding the Analysis"
        self.title_words = get_words_for_field(self.findings.qs, 'title')
        self.component_words = get_words_for_field(self.findings.qs, 'component_name')

        if self.request is not None:
            self.paged_findings = get_page_items(self.request, self.findings.qs, 25)
        else:
            self.paged_findings = self.findings

    def get_asciidoc(self):
        asciidoc = render_to_string("dojo/custom_asciidoc_report_findings.html",
                                    {"findings": self.findings.qs,
                                     "host": self.host,
                                     "include_finding_notes": self.finding_notes,
                                     "include_finding_images": self.finding_images,
                                     "user_id": self.user_id})
        return mark_safe(asciidoc)

    def get_html(self):
        html = render_to_string("dojo/custom_html_report_finding_list.html",
                                {"title": self.title,
                                 "findings": self.findings.qs,
                                 "include_finding_notes": self.finding_notes,
                                 "include_finding_images": self.finding_images,
                                 "host": self.host,
                                 "user_id": self.user_id})
        return mark_safe(html)

    def get_option_form(self):
        html = render_to_string('dojo/report_findings.html',
                                {"findings": self.paged_findings,
                                 "filtered": self.findings,
                                 "title_words": self.title_words,
                                 "component_words": self.component_words,
                                 "request": self.request,
                                 "title": self.title,
                                 "extra_help": self.extra_help,
                                 })
        return mark_safe(html)
