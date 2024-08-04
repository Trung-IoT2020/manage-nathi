from django.urls import path


from .views import RegisterView, CheckAuthcode, LoginView, reset_token,check_and_backup,GatewayUpdateView,GatewayCreateView,GatewayUpdateTView,GetNodeGatewayView,GatewaySearchView,GatewayDeleteView,CustomerListView,ResetPasswordView,CalculateAndStoreHistoryView,HistoryReportListView,DataGatewayOneDayFilterView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('check-permission/', CheckAuthcode.as_view(), name='check_authcode'),
    path('reset-token/', reset_token, name='reset_token'),
    path('customer/', CustomerListView.as_view(), name='customer-list'),
    path('customer/reset-password/', ResetPasswordView.as_view(), name='reset-password'),


    path('check-and-backup/', check_and_backup, name='check_and_backup'),
    path('update-gateway/', GatewayUpdateView.as_view(), name='update-gateway'),
    path('history/', HistoryReportListView.as_view(), name='history'),
    path('history-one-day/', DataGatewayOneDayFilterView.as_view(), name='history'),
    path('calculate-and-store-history/', CalculateAndStoreHistoryView.as_view(), name='calculate-and-store-history'),

    path('gateway/get-node-gateway/', GetNodeGatewayView.as_view(), name='get-node-gateway'),

    path('gateway/search/', GatewaySearchView.as_view(), name='gateway-search'),
    path('gateway/create/', GatewayCreateView.as_view(), name='gateway-create'),
    path('gateway/update/<int:pk>/', GatewayUpdateTView.as_view(), name='gateway-update'),
    path('gateway/delete/', GatewayDeleteView.as_view(), name='gateway-delete'),
]