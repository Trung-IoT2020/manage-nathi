from django.contrib import admin
from .models import Customer, Gateway, Rule, Node, History, DetailReportNode

admin.site.register(Customer)
admin.site.register(Gateway)
admin.site.register(Rule)
admin.site.register(Node)
admin.site.register(History)
admin.site.register(DetailReportNode)