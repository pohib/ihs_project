from django.urls import path
from . import views

urlpatterns = [
    path('', views.rule_list, name='rule_list'),
    path('file/<int:file_id>/', views.rule_list, name='rule_list_by_file'),
    path('upload/', views.upload_file, name='upload_file'),
    path('analyze/', views.run_analysis, name='run_analysis'),
]