from django.contrib.auth import authenticate
from rest_framework import serializers
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from myapp.models import Customer,Gateway,HistoryReport,DataGatewayOneDay
from datetime import datetime, timedelta
from pytz import timezone
import bcrypt
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ('username', 'password', 'email','phone','address')

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = ('username', 'password', 'phone', 'email', 'address','rule')


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)


    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            try:
                # Assuming `Customer` model has a `username` and `password` field
                customer = Customer.objects.get(username=username)
            except Customer.DoesNotExist:
                raise serializers.ValidationError("Không thể đăng nhập. Thông tin sai tài khoản hoặc sai mật khẩu.")
    
            if bcrypt.checkpw(password.encode(), customer.password.encode()):
                data['username'] = customer  # Assuming `customer.user` is a OneToOne field to the `User` model
            else:
                raise serializers.ValidationError("Không thể đăng nhập. Thông tin sai tài khoản hoặc sai mật khẩu.")
        else:
            raise serializers.ValidationError("'username' and 'password' không hợp lệ.")

        return data


class GatewayTSerializer(serializers.ModelSerializer):
    customer = serializers.SlugRelatedField(queryset=Customer.objects.all(), slug_field='username')
    node_gateway = serializers.CharField()
    node = serializers.CharField(required=False, allow_blank=True, default='')
    dateCreate = serializers.DateTimeField(default=datetime.now().astimezone(timezone('Asia/Ho_Chi_Minh')).strftime('%Y-%m-%d %H:%M:%S'))


    

    class Meta:
        model = Gateway
        fields = ['customer', 'node_gateway', 'node', 'dateCreate']

    def validate_node_gateway(self, value):
        if Gateway.objects.filter(node_gateway=value).exists():
            raise serializers.ValidationError("A Gateway with this node_gateway already exists.")
        return value

    def create(self, validated_data):
        validated_data['node'] = validated_data.get('node', '')
        return super().create(validated_data)

class GatewaySerializer(serializers.Serializer):
    customer_id = serializers.IntegerField(required=False)
    gateway_id = serializers.IntegerField(required=False)
    node_gateway = serializers.IntegerField(required=False) 
    node_data = serializers.DictField()  

class HistoryReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = HistoryReport
        fields = ['id', 'node_gateway', 'node', 'date', 'node_data']

class DataGatewayOneDaySerializer(serializers.ModelSerializer):
    class Meta:
        model = DataGatewayOneDay
        fields = ['customer_id', 'node_gateway', 'node', 'date_create', 'node_data']