from django.conf import settings

def store_original_user(request, user):
    """Store original user information in session"""
    request.session['original_user'] = {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'is_admin': user.is_staff or user.is_superuser
    }
    request.session.modified = True

def get_original_user(request):
    """Get original user information from session"""
    return request.session.get('original_user')

def clear_original_user(request):
    """Clear original user information from session"""
    if 'original_user' in request.session:
        del request.session['original_user']
    request.session.modified = True

def is_switched_user(request):
    """Check if user is currently switched from another account"""
    return 'original_user' in request.session

def get_current_user_type(request):
    """Get current user type (admin or regular)"""
    if request.user.is_authenticated:
        if is_switched_user(request):
            return 'switched_admin' if (request.user.is_staff or request.user.is_superuser) else 'switched_regular'
        else:
            return 'admin' if (request.user.is_staff or request.user.is_superuser) else 'regular'
    return 'anonymous'