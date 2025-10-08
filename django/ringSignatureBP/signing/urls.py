from django.urls import path 

from . import views

urlpatterns = [
    path("", views.sign, name="sign"),
    path('verifier/', views.verifier, name='verifier'),
    path('github-lookup/', views.github_lookup, name='github_lookup'),
]