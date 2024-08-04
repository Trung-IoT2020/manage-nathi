from django.db import models

class Customer(models.Model):
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # 'pass' is a reserved keyword in Python
    phone = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(max_length=255, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    rule = models.CharField(max_length=50, blank=True, null=True)
    dateCreate =  models.TextField()

    def __str__(self):
        return self.username

class Gateway(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='gateways')
    node_gateway = models.IntegerField(unique=True)  # Add unique constraint here
    node = models.TextField()
    node_data = models.JSONField(default=dict)
    dateCreate = models.TextField()

    def __str__(self):
        return f"Gateway {self.id} for Customer {self.customer.username}"

class Rule(models.Model):
    customer = models.OneToOneField(Customer, on_delete=models.CASCADE, unique=True, related_name='customer_rule')
    value = models.CharField(max_length=255)
    dateCreate =  models.TextField()

    def __str__(self):
        return f"Rule for Customer {self.customer.username}"

class Node(models.Model):
    gateway = models.ForeignKey(Gateway, on_delete=models.CASCADE, related_name='nodes')
    value = models.TextField()
    dateCreate =  models.TextField()

    def __str__(self):
        return f"Node {self.id} for Gateway {self.gateway.id}"

class History(models.Model):
    gateway = models.ForeignKey(Gateway, on_delete=models.CASCADE, related_name='histories')
    data = models.TextField()
    dateCreate = models.TextField()

    def __str__(self):
        return f"History {self.id} for Gateway {self.gateway.id}"

class DetailReportNode(models.Model):
    gateway = models.ForeignKey(Gateway, on_delete=models.CASCADE, related_name='detail_report_nodes')
    report = models.TextField()
    dateCreate =models.TextField()

    def __str__(self):
        return f"DetailReportNode {self.id} for Gateway {self.gateway.id}"
    
class DataGatewayOneDay(models.Model):
    customer_id = models.IntegerField()
    node_gateway = models.IntegerField()
    node = models.CharField(max_length=255, blank=True, null=True)
    date_create = models.TextField()
    node_data = models.JSONField()

    class Meta:
        db_table = 'data_gateway_one_day'

class HistoryReport(models.Model):
    node_gateway = models.ForeignKey(Gateway, on_delete=models.CASCADE, related_name='history_report_gateway')
    node = models.CharField(max_length=255, blank=True, null=True)
    date = models.DateField()
    node_data = models.JSONField()
    def __str__(self):
        return f"HistoryReport {self.id} for Gateway {self.gateway.id}"
    
    class Meta:
        db_table = 'history_report'