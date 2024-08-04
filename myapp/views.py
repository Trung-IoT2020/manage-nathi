from rest_framework import generics, status,viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError
from django.contrib.auth.models import User
from myapp.models import Rule, Customer,History, Gateway,DataGatewayOneDay,HistoryReport
from .serializers import UserSerializer, CustomerSerializer, LoginSerializer, GatewaySerializer,GatewayTSerializer,HistoryReportSerializer,DataGatewayOneDaySerializer
from rest_framework.decorators import api_view, permission_classes
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.db import connection,transaction
from .utils import backup_database, get_database_size
from datetime import datetime, timedelta
from django.conf import settings
from pytz import timezone
import bcrypt
import jwt
from ratelimit import limits, sleep_and_retry
from django_ratelimit.decorators import ratelimit
from rest_framework.throttling import UserRateThrottle
from rest_framework.exceptions import Throttled
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CustomThrottle(UserRateThrottle):
    print(333,UserRateThrottle)
    rate = '2/second'

def success_response(data):
    return Response({
        "status": 1,
        "msg": "success",
        "detail": data
    }, status=status.HTTP_200_OK)

def fail_response(message, status_code=status.HTTP_400_BAD_REQUEST):
    return Response({
        "status": 0,
        "msg": message,
        "detail": None
    }, status=status_code)

class RegisterView(generics.CreateAPIView):
    queryset = Customer.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        try:
            username = request.data.get('username', '').strip()
            password = request.data.get('password', '').strip()
            email = request.data.get('email', '').strip()
            phone = request.data.get('phone', '').strip()
            address = request.data.get('address', '').strip()
    

            if not username or not password or not email or not phone or not address:
                return fail_response("Vui lòng điền đầy đủ thông tin.")

            if Customer.objects.filter(username=username).exists() or Customer.objects.filter(phone=phone).exists():
                return fail_response("Tài khoản đã được khởi tạo! Vui lòng thay đổi tài khoản!")

            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            customer_data = {
                'username': username,
                'password': hashed.decode(),
                'phone': phone,
                'email': email,
                'address': address,
                'rule': 2
            }

            serializer = self.get_serializer(data=customer_data)
            serializer.is_valid(raise_exception=True)
            customer_serializer = CustomerSerializer(data=customer_data)

            if customer_serializer.is_valid():
                customer = serializer.save()
            else:
                return fail_response(customer_serializer.errors)

            refresh = RefreshToken.for_user(customer)
            return success_response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

class LoginView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            user = serializer.validated_data['username']
            refresh = RefreshToken.for_user(user)
            return success_response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        except Exception as e:
            return fail_response("Username hoặc password không đúng! Vui lòng thử lại!")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_token(request):
    try:
        user = request.user
        refresh = RefreshToken.for_user(user)
        return success_response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
    except Exception as e:
        return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")


class CheckAuthcode(APIView):
    def post(self, request):
        try:
            auth_header = request.headers.get('X-Authorization', None)
            if not auth_header:
                return fail_response("Token không được cung cấp hoặc định dạng không hợp lệ", 200)

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return fail_response("X-Authorization header must contain two space-delimited values", 200)

            token = parts[1]

            try:
                access_token = AccessToken(token)
            except TokenError as e:
                return fail_response("Token không hợp lệ hoặc đã hết hạn", 200)

            user_id = access_token['user_id']

            try:
                customer = Customer.objects.get(id=user_id)
            except Customer.DoesNotExist:
                return fail_response("Không tìm thấy khách hàng", 200)

            user_data = {
                "username": customer.username,
                "email": customer.email,
            }
            return success_response({"user": user_data, "user_id": customer.id})
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!", status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class CustomerListView(APIView):
    def post(self, request):
        try:
            auth_header = request.headers.get('X-Authorization', None)
            if not auth_header:
                return fail_response("Token không được cung cấp hoặc định dạng không hợp lệ", 200)

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return fail_response("X-Authorization header must contain two space-delimited values", 200)

            token = parts[1]

            customers = Customer.objects.all()
            serializer = CustomerSerializer(customers, many=True)
            return success_response(serializer.data)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

class ResetPasswordView(APIView):
    def post(self, request):
        try:
            username = request.data.get('username', '')
            password = request.data.get('password', '')
            new_password = request.data.get('new_password', '')

            if not username or not password or not new_password:
                return fail_response('Tên người dùng, mật khẩu và mật khẩu mới phải được cung cấp')

            customer = Customer.objects.get(username=username)
            if bcrypt.checkpw(password.encode(), customer.password.encode()):
                hashed_new_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                customer.password = hashed_new_password.decode()
                customer.save()
                return success_response(f'Mật khẩu cho người dùng {username} đã được đặt lại.')
            else:
                return fail_response('Mật khẩu hiện tại không đúng.')
        except ObjectDoesNotExist:
            return fail_response(f'Người dùng {username} không tồn tại.', 200)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

@api_view(['GET'])
def check_and_backup(request):
    try:
        db_size_in_mb = get_database_size()
        if db_size_in_mb is None:
            return fail_response("Could not retrieve database size")
        
        db_size_in_gb = db_size_in_mb / 1024  # Convert MB to GB
        print(db_size_in_mb, db_size_in_gb)

        if db_size_in_gb >= 1:
            backup_file = backup_database()
            if backup_file is None:
                return fail_response("Database backup failed")

            total_records = DataGatewayOneDay.objects.count()
            records_to_delete = total_records // 2
            DataGatewayOneDay.objects.all()[:records_to_delete].delete()

            return success_response({
                "Database backed up to": backup_file,
                "Deleted records": records_to_delete
            })
        
        return success_response(f"Kích thước cơ sở dữ liệu chưa đạt mức giảm!")
    except Exception as e:
        return fail_response(f"Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp! Error: {str(e)}")

## Gateway

class GatewayUpdateView(APIView):
    throttle_classes = [CustomThrottle]
    def post(self, request, *args, **kwargs):
        try:
            node_gateway = request.data.get('node_gateway', 0)
            gateway = Gateway.objects.filter(node_gateway=node_gateway).first()
            if not gateway:
                return Response({"error": "Chưa có dữ liệu trong DB"}, status=200)
            customer_id = gateway.customer_id
            date_create = datetime.now().astimezone(timezone('Asia/Ho_Chi_Minh')).strftime('%Y-%m-%d %H:%M:%S')
                        # Get the current time in 'Asia/Ho_Chi_Minh' timezone
            date_create_T   =date_create
            node_data = request.data.get('node_data', {})
            node = request.data.get('node', '')
            print(date_create)
            # Save the data to DataGatewayOneDay
            createdTas =   DataGatewayOneDay.objects.create(
                customer_id=customer_id,
                node_gateway=node_gateway,
                node=node,
                date_create=date_create_T,
                node_data=node_data
            )
            print(createdTas)
            # Add or update the record in myapp_gateway table
            self.add_or_update_column(node_gateway, node_data, customer_id, node, date_create)
            return success_response( "Dữ liệu được cập nhật thành công")
        except Throttled as e:
            # Log the error details when throttling occurs
            logger.error(f"Rate limit exceeded: {e}")
            logger.error(f"Request method: {request.method}")
            logger.error(f"Request IP: {request.META.get('REMOTE_ADDR')}")
            logger.error(f"Request data: {request.data}")
            
            # Return a custom error response if desired
            return Response(
                {"error": "Rate limit exceeded. Try again later."},
                status=429
            )
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")


    def add_or_update_column(self, node_gateway, node_data, customer_id, node, date_create):
        with transaction.atomic():
            gateway, created = Gateway.objects.update_or_create(
                node_gateway=node_gateway,
                defaults={
                    'customer_id': customer_id,
                    'node': node,
                    'node_data': node_data,
                    'dateCreate': date_create,
                }
            )


class GetNodeGatewayView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            node_gateway = request.data.get('node_gateway')
           

            if not node_gateway:
                return fail_response("node_gateway là bắt buộc")

            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM myapp_gateway WHERE node_gateway=%s", [node_gateway])
                row = cursor.fetchone()
                columns = [col[0] for col in cursor.description]

            if not row:
                return fail_response("Không tìm thấy dữ liệu cho node_gateway được chỉ định", 200)

            response_data = {key: value for key, value in zip(columns, row) if value != 0}

            return success_response(response_data)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

class GatewaySearchView(APIView):
    def post(self, request):
        try:
            node_gateway = request.data.get('node_gateway', '')
            customer = request.data.get('customer', '')
            
            if customer:
                customerT = Customer.objects.get(username=customer)
                gateways = Gateway.objects.filter(customer_id=customerT.id)
            else:
                if node_gateway == '':
                    gateways = Gateway.objects.all()
                else:
                    gateways = Gateway.objects.filter(node_gateway=node_gateway)
            
          # Adding node_data key count and values
            gateway_data_with_details = []
            for gateway in gateways:
                gateway_data = GatewayTSerializer(gateway).data
                
                node_data_F =  {}
                node_data_F= gateway.node_data
                node_data_details = {}
                if gateway.node_data and isinstance(gateway.node_data, dict):
                    for key, value in gateway.node_data.items():
                        if "NODE_" in key:
                            node_data_details[key] = value.get('value', None)
                gateway_data['node_data'] =  list(node_data_F.values()) if node_data_F else None
                gateway_data['list_node_value'] =list(node_data_details.values()) if node_data_details else None
                gateway_data['node_data_count'] = len(node_data_details)
                gateway_data_with_details.append(gateway_data)

            return success_response(gateway_data_with_details)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

class GatewayCreateView(generics.CreateAPIView):
    queryset = Gateway.objects.all()
    serializer_class = GatewayTSerializer

    def create(self, request, *args, **kwargs):
        try:
            auth_header = request.headers.get('X-Authorization', None)
            if not auth_header:
                return fail_response("Token không được cung cấp hoặc định dạng không hợp lệ", 200)

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return fail_response("X-Authorization header must contain two space-delimited values", 200)
            token = parts[1]
            response = super().create(request, *args, **kwargs)
            return success_response(response.data)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

class GatewayUpdateTView(generics.UpdateAPIView):
    queryset = Gateway.objects.all()
    serializer_class = GatewayTSerializer

    def update(self, request, *args, **kwargs):
        try:
            response = super().update(request, *args, **kwargs)
            return success_response(response.data)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")

class GatewayDeleteView(APIView):
    def post(self, request):
        try:
            auth_header = request.headers.get('X-Authorization', None)
            if not auth_header:
                return fail_response("Token không được cung cấp hoặc định dạng không hợp lệ", 200)

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return fail_response("X-Authorization header must contain two space-delimited values", 200)

            token = parts[1]
            node_gateway = request.data.get('node_gateway', '')
            if node_gateway == '':
                return fail_response('node_gateway must be provided.')

            gateway = Gateway.objects.get(node_gateway=node_gateway)
            gateway.delete()
                        # Delete related records from HistoryReport
            HistoryReport.objects.filter(node_gateway=node_gateway).delete()

            # Delete related records from DataGatewayOneDay
            DataGatewayOneDay.objects.filter(node_gateway=node_gateway).delete()
            return success_response(f'Gateway có node_gateway {node_gateway} đã bị xóa.')
        except Gateway.DoesNotExist:
            return fail_response(f'Gateway có node_gateway {node_gateway} không tồn tại.', 404)
        except Exception as e:
            return fail_response("Hệ thống lỗi! Vui lòng đảm bảo đúng format hệ thống cung cấp!")


class CalculateAndStoreHistoryView(APIView):
    def get(self, request, *args, **kwargs):
        target_date = datetime.now() - timedelta(days=1)
        target_date_str = target_date.strftime('%Y-%m-%d')
        data_entries = DataGatewayOneDay.objects.filter(date_create__startswith=target_date_str)
        
        if not data_entries.exists():
            return Response({"message": "Không tìm thấy dữ liệu cho ngày được chỉ định"}, status=200)

        aggregated_data = {}
        customer_id = None
        node_gateway = None
        node = None
    
        for entry in data_entries:
            if customer_id is None:
                customer_id = entry.customer_id
            if node_gateway is None:
                node_gateway = entry.node_gateway
            if node is None:
                node = entry.node

            for node_key, value in entry.node_data.items():
                if "NODE_" in node_key:  # Check if key contains "NODE_"
                    if node_key not in aggregated_data:
                        aggregated_data[node_key] = []
                    aggregated_data[node_key].append(value)
    
        averaged_data = {}
        for node_key, values in aggregated_data.items():
        
            if values:
                total = sum(int(value['value']) for value in values)
                averaged_data[node_key] = total / len(values)
            
            else:
                averaged_data[node_key] = 0

        try:
            gateway_instance = Gateway.objects.get(node_gateway=node_gateway)
            HistoryReport.objects.create(
                node_gateway=gateway_instance,
                node=node,
                date=target_date,
                node_data=averaged_data
            )
            data_entries.delete()
            return success_response(averaged_data)
        except Gateway.DoesNotExist:
            return fail_response({"message": "Gateway không tồn tại"})

class HistoryReportListView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            auth_header = request.headers.get('X-Authorization', None)
            if not auth_header:
                return fail_response("Token không được cung cấp hoặc định dạng không hợp lệ", 200)

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return fail_response("X-Authorization header must contain two space-delimited values", 200)
            token = parts[1]
            from_date = request.data.get('from_date', None)
            to_date = request.data.get('to_date', None)

            # Initialize the queryset
            queryset = HistoryReport.objects.all()

            # Apply date filters if both dates are provided
            if from_date and to_date:
                try:
                    from_date_obj = datetime.strptime(from_date, '%Y-%m-%d').date()
                    to_date_obj = datetime.strptime(to_date, '%Y-%m-%d').date()
                    queryset = queryset.filter(date__range=[from_date_obj, to_date_obj])
                except ValueError:
                    return fail_response({"error": "Định dạng ngày tháng hợp lệ. Sử dụng 'YYYY-MM-DD'."})
            # Apply date filter if only from_date is provided
            elif from_date:
                try:
                    from_date_obj = datetime.strptime(from_date, '%Y-%m-%d').date()
                    queryset = queryset.filter(date__gte=from_date_obj)
                except ValueError:
                    return fail_response({"error": "Định dạng ngày tháng hợp lệ. Sử dụng 'YYYY-MM-DD'."})
            # Apply date filter if only to_date is provided
            elif to_date:
                try:
                    to_date_obj = datetime.strptime(to_date, '%Y-%m-%d').date()
                    queryset = queryset.filter(date__lte=to_date_obj)
                except ValueError:
                    return fail_response({"error": "Định dạng ngày tháng hợp lệ. Sử dụng 'YYYY-MM-DD'."})
            serializer = HistoryReportSerializer(queryset, many=True)
            return success_response(serializer.data)
        except Exception as e:
            return fail_response({"error": str(e)})

class DataGatewayOneDayFilterView(APIView):
    def post(self, request, *args, **kwargs):
        try:

            auth_header = request.headers.get('X-Authorization', None)
            if not auth_header:
                return fail_response("Token không được cung cấp hoặc định dạng không hợp lệ", 200)

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return fail_response("X-Authorization header must contain two space-delimited values", 200)

            token = parts[1]

            # Extract parameters from the request data
            node_gateway = request.data.get('node_gateway', None)
            name_node = request.data.get('name_node', None)
            date_create = request.data.get('date_create', None)
            
            # Initialize the queryset
            queryset = DataGatewayOneDay.objects.all()
            
            # Apply filters if parameters are provided
            if node_gateway is not None:
                queryset = queryset.filter(node_gateway=node_gateway)
            if date_create:
                try:
                    # Convert date_create to a string in 'YYYY-MM-DD' format
                    date_create_str = datetime.strptime(date_create, '%Y-%m-%d').date().strftime('%Y-%m-%d')
                    queryset = queryset.filter(date_create=date_create_str)
                except ValueError:
                    return fail_response({"error": "Invalid date format. Use 'YYYY-MM-DD'."})
            
            # Further filtering by node_data
            if name_node:
                filtered_queryset = []
                for record in queryset:
                    if record.node_data and isinstance(record.node_data, dict):
                        for key in record.node_data.keys():
                            if "NODE_" in key and key == name_node:
                                filtered_queryset.append(record)
                                break
                queryset = filtered_queryset
     
            # Process node_data to extract values for the given name_node
            result_data = []
            if name_node and name_node.strip():  # Check if name_node is not None or empty
                for record in queryset:
                    if record.node_data and isinstance(record.node_data, dict):
                        node_value = record.node_data.get(name_node, {}).get('value', None)
                        if node_value is not None:
                            result_data.append({
                                'customer_id': record.customer_id,
                                'node_gateway': record.node_gateway,
                                'date_create': record.date_create,
                                'node_data': {name_node: node_value}
                            })
            else:
                # If name_node is not provided or is empty, return all node_data
                for record in queryset:
                    result_data.append({
                        'customer_id': record.customer_id,
                        'node_gateway': record.node_gateway,
                        'date_create': record.date_create,
                        'node_data': record.node_data
                    })
            # Serialize the result data
            return success_response(result_data)
        
        except Exception as e:
            return fail_response({"error": str(e)})