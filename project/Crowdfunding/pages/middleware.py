# pages/middleware.py
from django.shortcuts import redirect
from django.contrib import messages

class AdminSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only process if request.user exists
        if hasattr(request, 'user'):
            # Check if accessing admin area
            is_admin_area = request.path.startswith('/admin/')
            
            # Check if this is an admin session
            is_admin_session = request.session.get('admin_session', False)
            
            # If user is authenticated and in admin area but not admin session
            if (request.user.is_authenticated and is_admin_area and 
                not is_admin_session and 
                not (request.user.is_staff or request.user.is_superuser)):
                messages.error(request, 'Please login through admin login to access dashboard.')
                return redirect('admin_login')
            
            # If user is authenticated and in admin area and is admin
            elif (request.user.is_authenticated and is_admin_area and 
                 (request.user.is_staff or request.user.is_superuser) and
                 not is_admin_session):
                # Auto-create admin session for staff/superusers in admin area
                request.session['admin_session'] = True
            
            # If user is authenticated in regular area but has admin session
            elif (request.user.is_authenticated and not is_admin_area and 
                 is_admin_session and 
                 (request.user.is_staff or request.user.is_superuser)):
                # This is fine - admin can browse regular site during admin session
                pass
        
        response = self.get_response(request)
        return response