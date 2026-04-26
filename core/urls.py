from django.urls import path
from . import views

urlpatterns = [
    path('', views.rule_list, name='rule_list'),
    path('file/<int:file_id>/', views.rule_list, name='rule_list_by_file'),
    path('upload/', views.upload_file, name='upload_file'),
    path('analyze/', views.run_analysis, name='run_analysis'),
    path('analyze/<int:file_id>/', views.run_analysis, name='run_analysis_by_file'),
    path('delete-file/<int:file_id>/', views.delete_file, name='delete_file'),
    path('rules/export/', views.export_rules_csv, name='export_rules_all'),
    path('rules/export/<int:file_id>/', views.export_rules_csv, name='export_rules_file'),
]