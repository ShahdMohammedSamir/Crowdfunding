from django.db.models import F,Sum, Count, Avg, Q
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import Report, Project, Comment
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from .models import User, Project, Donation
from .forms import UserRegistrationForm, UserLoginForm, UserProfileForm, AdminLoginForm, CustomPasswordResetForm, CustomSetPasswordForm
from .tokens import account_activation_token, password_reset_token
from .models import Project, Category, Tag
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q, Count 
from .models import Project, ProjectPicture, Donation, Comment, Rating, Report, Tag
from .forms import ProjectForm, ProjectPictureForm, DonationForm, CommentForm, RatingForm, ReportForm
from django.utils import timezone
from django.core.exceptions import ValidationError
@login_required
def create_project(request):
    if request.method == 'POST':
        project_form = ProjectForm(request.POST, request.FILES)

        if project_form.is_valid():
            project = project_form.save(commit=False)
            project.user = request.user
            project.save()
            tags_str = project_form.cleaned_data.get('tags', '')
            if tags_str:
                tags_list = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
                for tag_name in tags_list:
                    tag, created = Tag.objects.get_or_create(name=tag_name.lower())
                    project.tags.add(tag)

            images = request.FILES.getlist('image')
            for image in images:
                ProjectPicture.objects.create(project=project, image=image)

            messages.success(request, f'Project created successfully with {len(images)} images!')
            return redirect('project_detail', project_id=project.id)
        else:
            print("Form errors:", project_form.errors)
            messages.error(request, 'Please correct the errors below.')
    else:
        project_form = ProjectForm()

    return render(request, 'projects/create_project.html', {
        'project_form': project_form,
    })

def project_detail(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    
    try:
        similar_projects = project.get_similar_projects()
    except Exception as e:
        similar_projects = Project.objects.filter(
            is_cancelled=False,
            category=project.category
        ).exclude(id=project.id).order_by('-created_at')[:4]
    
    # Handle donations
    if request.method == 'POST' and 'donate' in request.POST and request.user.is_authenticated:
        donation_form = DonationForm(request.POST)
        if donation_form.is_valid():
            donation = donation_form.save(commit=False)
            donation.user = request.user
            donation.project = project
            donation.save()
            messages.success(request, 'Thank you for your donation!')
            return redirect('project_detail', project_id=project.id)
    else:
        donation_form = DonationForm()
    
    # Handle comments
    if request.method == 'POST' and 'comment' in request.POST and request.user.is_authenticated:
        comment_form = CommentForm(request.POST)
        if comment_form.is_valid():
            comment = comment_form.save(commit=False)
            comment.user = request.user
            comment.project = project
            
            # Handle replies
            parent_id = request.POST.get('parent_id')
            if parent_id:
                try:
                    comment.parent = Comment.objects.get(id=parent_id)
                except Comment.DoesNotExist:
                    pass
            
            comment.save()
            messages.success(request, 'Comment added successfully!')
            return redirect('project_detail', project_id=project.id)
    else:
        comment_form = CommentForm()
    
    # Handle ratings
    if request.method == 'POST' and 'rate' in request.POST and request.user.is_authenticated:
        rating_form = RatingForm(request.POST)
        if rating_form.is_valid():
            rating, created = Rating.objects.update_or_create(
                user=request.user,
                project=project,
                defaults={'rating': rating_form.cleaned_data['rating']}
            )
            messages.success(request, 'Rating submitted successfully!')
            return redirect('project_detail', project_id=project.id)
    else:
        # Get user's existing rating if any
        user_rating = None
        if request.user.is_authenticated:
            try:
                user_rating = Rating.objects.get(user=request.user, project=project)
            except Rating.DoesNotExist:
                pass
        rating_form = RatingForm(instance=user_rating)
    
    # Handle reports
    if request.method == 'POST' and 'report' in request.POST and request.user.is_authenticated:
        report_form = ReportForm(request.POST)
        if report_form.is_valid():
            report = report_form.save(commit=False)
            report.reporter = request.user
            
            report_type = request.POST.get('report_type')
            if report_type == 'project':
                report.project = project
            elif report_type == 'comment':
                comment_id = request.POST.get('comment_id')
                if comment_id:
                    try:
                        report.comment = Comment.objects.get(id=comment_id)
                    except Comment.DoesNotExist:
                        messages.error(request, 'Comment not found.')
                        return redirect('project_detail', project_id=project.id)
            
            report.save()
            messages.success(request, 'Report submitted successfully!')
            return redirect('project_detail', project_id=project.id)
    else:
        report_form = ReportForm()
    
    # Get top-level comments (not replies)
    comments = project.comments.filter(parent=None).order_by('-created_at')
    
    return render(request, 'projects/project_detail.html', {
        'project': project,
        'similar_projects': similar_projects,
        'donation_form': donation_form,
        'comment_form': comment_form,
        'rating_form': rating_form,
        'report_form': report_form,
        'comments': comments,
        'user_rating': Rating.objects.filter(user=request.user, project=project).first() if request.user.is_authenticated else None,
    })

@login_required
def cancel_project(request, project_id):
    project = get_object_or_404(Project, id=project_id, user=request.user)
    
    # Only process cancellation on POST requests
    if request.method == 'POST':
        if project.cancel():
            messages.success(request, 'Project cancelled successfully.')
        else:
            messages.error(request, 'Cannot cancel project. Donations must be less than 25% of target.')
        
        return redirect('project_detail', project_id=project.id)
    
    # If it's a GET request, just redirect to project detail
    return redirect('project_detail', project_id=project.id)

@login_required
def report_content(request):
    if request.method == "POST" and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        report_type = request.POST.get("report_type")
        content_id = request.POST.get("content_id")
        reason = request.POST.get("reason")

        if not reason:
            return JsonResponse({"success": False, "error": "Reason is required."})

        try:
            if report_type == "project":
                project = get_object_or_404(Project, id=content_id)

                # Prevent reporting own project
                if project.user == request.user:
                    return JsonResponse({"success": False, "error": "You cannot report your own project."})

                # Prevent duplicate reports from same user
                if Report.objects.filter(reporter=request.user, report_type="project", project=project).exists():
                    return JsonResponse({"success": False, "error": "You have already reported this project."})

                # Save report
                Report.objects.create(
                    reporter=request.user,
                    report_type="project",
                    project=project,
                    reason=reason
                )

                # Count reports
                count = Report.objects.filter(report_type="project", project=project).count()
                if count >= 2:
                    project.delete()
                    return JsonResponse({
                        "success": True,
                        "message": "Project deleted due to multiple reports.",
                        "item_deleted": True
                    })

            elif report_type == "comment":
                comment = get_object_or_404(Comment, id=content_id)

                # Prevent reporting own comment
                if comment.user == request.user:
                    return JsonResponse({"success": False, "error": "You cannot report your own comment."})

                # Prevent duplicate reports from same user
                if Report.objects.filter(reporter=request.user, report_type="comment", comment=comment).exists():
                    return JsonResponse({"success": False, "error": "You have already reported this comment."})

                # Save report
                Report.objects.create(
                    reporter=request.user,
                    report_type="comment",
                    comment=comment,
                    reason=reason
                )

                # Count reports
                count = Report.objects.filter(report_type="comment", comment=comment).count()
                if count >= 2:
                    comment.delete()
                    return JsonResponse({
                        "success": True,
                        "message": "Comment deleted due to multiple reports.",
                        "item_deleted": True
                    })

            else:
                return JsonResponse({"success": False, "error": "Invalid report type."})

            # If not deleted yet
            return JsonResponse({
                "success": True,
                "message": "Report submitted successfully.",
                "item_deleted": False
            })

        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})

    return JsonResponse({"success": False, "error": "Invalid request"})


def project_list(request):
    category = request.GET.get('category')
    tag = request.GET.get('tag')
    search = request.GET.get('search')
    
    projects = Project.objects.filter(is_cancelled=False)
    
    if category:
        projects = projects.filter(category__name__icontains=category)
    
    if tag:
        projects = projects.filter(tags__name__icontains=tag)
    
    if search:
        projects = projects.filter(
            Q(title__icontains=search) | 
            Q(details__icontains=search) |
            Q(tags__name__icontains=search)
        ).distinct()
    
    # Filter by status
    status = request.GET.get('status')
    now = timezone.now()
    
    if status == 'running':
        projects = projects.filter(start_time__lte=now, end_time__gte=now)
    elif status == 'completed':
        projects = projects.filter(end_time__lt=now)
    elif status == 'upcoming':
        projects = projects.filter(start_time__gt=now)
    
    projects = projects.order_by('-created_at')
    
    categories = Category.objects.all()
    popular_tags = Tag.objects.annotate(project_count=Count('project')).order_by('-project_count')[:10]
    
    return render(request, 'projects/project_list.html', {
        'projects': projects,
        'categories': categories,
        'popular_tags': popular_tags,
    })


def home(request):
    now = timezone.now()
    
    # Highest rated running projects (slider)
    highest_rated = Project.objects.filter(
        is_cancelled=False,
        start_time__lte=now,
        end_time__gte=now
    ).annotate(
        total_donated=Sum('donations__amount'),  # sum of donations
        avg_rating=Avg('ratings__rating')
    ).order_by('-avg_rating')[:5]
    
    # Latest 5 projects
    latest_projects = Project.objects.filter(
        is_cancelled=False
    ).annotate(
        total_donated=Sum('donations__amount')
    ).order_by('-created_at')[:5]
    
    # Featured projects (selected by admin)
    featured_projects = Project.objects.filter(
        is_featured=True,
        is_cancelled=False
    ).annotate(
        total_donated=Sum('donations__amount')
    ).order_by('-created_at')[:5]
    
    # All categories with project counts
    categories = Category.objects.annotate(
        project_count=Count('project', filter=Q(project__is_cancelled=False))
    )
    
    # Get all tags
    tags = Tag.objects.all()
    
    # Statistics for homepage
    total_projects = Project.objects.filter(is_cancelled=False).count()
    total_backers = Donation.objects.count()
    total_donations = Donation.objects.aggregate(total=Sum('amount'))['total'] or 0
    
    # Success rate = % of projects that reached their goal
    funded_projects = Project.objects.annotate(
        total_donated=Sum('donations__amount')
    ).filter(total_donated__gte=F('total_target')).count()
    
    success_rate = int((funded_projects / total_projects) * 100) if total_projects > 0 else 0
    
    context = {
        'highest_rated': highest_rated,
        'latest_projects': latest_projects,
        'featured_projects': featured_projects,
        'categories': categories,
        'tags': tags,
        'total_projects': total_projects,
        'total_backers': total_backers,
        'total_donations': total_donations,
        'success_rate': success_rate,
    }
    
    return render(request, 'home.html', context)


def search_projects(request):
    query = request.GET.get('q', '')
    
    if query:
        projects = Project.objects.filter(
            Q(title__icontains=query) |
            Q(tags__name__icontains=query) |
            Q(category__name__icontains=query),
            is_cancelled=False
        ).distinct().order_by('-created_at')
    else:
        projects = Project.objects.filter(is_cancelled=False).order_by('-created_at')
    
    context = {
        'projects': projects,
        'query': query,
        'results_count': projects.count()
    }
    return render(request, 'projects/search_results.html', context)

def category_projects(request, category_id):
    category = Category.objects.get(id=category_id)
    projects = Project.objects.filter(
        category=category,
        is_cancelled=False
    ).order_by('-created_at')
    
    context = {
        'category': category,
        'projects': projects
    }
    return render(request, 'projects/category_projects.html', context)

# Admin check function
def is_admin(user):
    return user.is_staff or user.is_superuser


def register(request):
    if request.user.is_authenticated:
        if request.session.get('admin_session'):
            messages.info(request, 'Please logout from admin session to register as a user.')
            return redirect('admin_dashboard')
        return redirect('home')
    
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
           
            # Send activation email
            mail_subject = 'Activate your account'
            
            html_message = render_to_string('auth/activate_account_email.html', {
                'user': user,
                'domain': request.get_host(),
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            
            plain_message = f"""
Hi {user.first_name},

Please click on the link below to activate your account:

http://{request.get_host()}/activate/{urlsafe_base64_encode(force_bytes(user.pk))}/{account_activation_token.make_token(user)}/

Thank you,
Crowdfunding Team
"""
            
            email = EmailMessage(
                mail_subject, 
                plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email]
            )
            email.content_subtype = "html"
            email.body = html_message
            
            email.send()
            
            messages.success(request, 'Please confirm your email address to complete the registration. Check your inbox!')
            return redirect('login')
    else:
        form = UserRegistrationForm()
    return render(request, 'auth/register.html', {'form': form})

def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and account_activation_token.check_token(user, token):
        if not user.is_active:
            user.is_active = True
            user.save()
            messages.success(request, 'Your account has been activated successfully. You can now login.')
        else:
            messages.info(request, 'Your account is already activated.')
        return redirect('login')
    else:
        messages.error(request, 'Activation link is invalid or has expired!')
        return redirect('login')

def handle_inactive_account(request, form, email, user_id):
    messages.error(request, 'Your account is not activated. Please check your email for the activation link.')
    request.session['inactive_email'] = email
    request.session['inactive_user_id'] = user_id
    return render(request, 'auth/login.html', {
        'form': form,
        'show_resend_option': True,
        'email': email
    })

def handle_auth_failure(request, form, email, is_admin_login=False):
    try:
        user = User.objects.get(email=email)
        if not user.is_active:
            return handle_inactive_account(request, form, email, user.id)
        else:
            if is_admin_login:
                if not (user.is_staff or user.is_superuser):
                    messages.error(request, 'You do not have admin privileges.')
                else:
                    messages.error(request, 'Invalid password. Please try again.')
            else:
                if user.is_staff or user.is_superuser:
                    messages.error(request, 'Administrators must use the admin login page.')
                else:
                    messages.error(request, 'Invalid password. Please try again.')
    except User.DoesNotExist:
        if is_admin_login:
            messages.error(request, 'Invalid admin credentials.')
        else:
            messages.error(request, 'Invalid email or password.')
    
    return render(request, 'auth/login.html', {'form': form})

def handle_get_login(request, form, is_admin=False):
    inactive_email = request.session.get('inactive_email')
    inactive_user_id = request.session.get('inactive_user_id')
    
    if inactive_email and inactive_user_id:
        try:
            user = User.objects.get(id=inactive_user_id, email=inactive_email, is_active=False)
            template = 'auth/admin_login.html' if is_admin else 'auth/login.html'
            return render(request, template, {
                'form': form,
                'show_resend_option': True,
                'email': inactive_email
            })
        except User.DoesNotExist:
            if 'inactive_email' in request.session:
                del request.session['inactive_email']
            if 'inactive_user_id' in request.session:
                del request.session['inactive_user_id']
    
    template = 'auth/admin_login.html' if is_admin else 'auth/login.html'
    return render(request, template, {'form': form})

def user_login(request):
    # If already in admin session, don't allow regular login
    if request.session.get('admin_session'):
        messages.info(request, 'Please logout from admin session first to login as regular user.')
        return redirect('admin_dashboard')
    
    # Redirect if already logged in as regular user
    if request.user.is_authenticated and not (request.user.is_staff or request.user.is_superuser):
        return redirect('home')
    
    if request.method == 'POST':
        form = UserLoginForm(request, data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username')  # This contains the email
            password = form.cleaned_data.get('password')
            
            # Authenticate user
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                if user.is_active:
                    # Don't allow admin to login through regular login
                    if user.is_staff or user.is_superuser:
                        messages.error(request, 'Administrators must use the admin login page.')
                        return render(request, 'auth/login.html', {'form': form})
                    
                    login(request, user)
                    # Clear any admin session data
                    if 'admin_session' in request.session:
                        del request.session['admin_session']
                    if 'original_user_id' in request.session:
                        del request.session['original_user_id']
                    
                    next_url = request.GET.get('next')
                    if next_url:
                        return redirect(next_url)
                    else:
                        messages.success(request, f'Welcome back, {user.first_name}!')
                        return redirect('home')
                else:
                    return handle_inactive_account(request, form, email, user.id)
            else:
                return handle_auth_failure(request, form, email, is_admin_login=False)
    else:
        form = UserLoginForm()
        return handle_get_login(request, form, is_admin=False)
    
    return render(request, 'auth/login.html', {'form': form})

def admin_login(request):
    # If regular user is logged in but trying to access admin login
    if (request.user.is_authenticated and 
        not request.session.get('admin_session') and 
        not (request.user.is_staff or request.user.is_superuser)):
        messages.info(request, 'You are logged in as a regular user. Please logout first to access admin login.')
        return redirect('profile')
    
    # Redirect if already logged in as admin with admin session
    if request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser):
        if request.session.get('admin_session'):
            return redirect('admin_dashboard')
        else:
            # Admin is logged in but not through admin session - create admin session
            request.session['admin_session'] = True
            return redirect('admin_dashboard')
    
    if request.method == 'POST':
        form = AdminLoginForm(request, data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username')  # This contains the email
            password = form.cleaned_data.get('password')
            
            # Authenticate admin
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                if user.is_active:
                    if not (user.is_staff or user.is_superuser):
                        messages.error(request, 'You do not have admin privileges.')
                        return render(request, 'auth/admin_login.html', {'form': form})
                    
                    # Mark this as an admin session
                    request.session['admin_session'] = True
                    # Log in the admin user
                    login(request, user)
                    messages.success(request, f'Admin login successful. Welcome, {user.first_name}!')
                    next_url = request.GET.get('next', 'admin_dashboard')
                    return redirect(next_url)
                else:
                    messages.error(request, 'This admin account is inactive.')
            else:
                return handle_auth_failure(request, form, email, is_admin_login=True)
    else:
        form = AdminLoginForm()
        return handle_get_login(request, form, is_admin=True)
    
    return render(request, 'auth/admin_login.html', {'form': form})

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # Check if this is an admin session
    if not request.session.get('admin_session'):
        messages.error(request, 'Please login through admin login page to access dashboard.')
        return redirect('admin_login')
    
    # Get counts for the dashboard
    user_count = User.objects.filter(is_staff=False, is_superuser=False, is_active=True).count()
    project_count = Project.objects.count()
    donation_count = Donation.objects.count()
    pending_users = User.objects.filter(is_active=False).count()
    
    context = {
        'user_count': user_count,
        'project_count': project_count,
        'donation_count': donation_count,
        'pending_count': pending_users
    }
    
    return render(request, 'admin/dashboard.html', context)

def user_logout(request):
    if request.user.is_authenticated:
        # Only logout if this is NOT an admin session
        if not request.session.get('admin_session'):
            logout(request)
            messages.success(request, 'You have been logged out successfully.')
        else:
            messages.info(request, 'You are in an admin session. Please use admin logout.')
            return redirect('admin_dashboard')
    else:
        messages.info(request, 'You are not logged in.')
    
    return redirect('home')

def admin_logout(request):
    if request.user.is_authenticated:
        # Only process if this is an admin session
        if request.session.get('admin_session'):
            logout(request)
            if 'admin_session' in request.session:
                del request.session['admin_session']
            if 'original_user_id' in request.session:
                del request.session['original_user_id']
            messages.success(request, 'Admin session ended successfully.')
        else:
            messages.info(request, 'No active admin session found.')
    else:
        messages.info(request, 'You are not logged in.')
    
    return redirect('home')

def resend_activation(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user_id = request.POST.get('user_id')
        
        try:
            user = User.objects.get(id=user_id, email=email, is_active=False)
            
            # Send activation email
            mail_subject = 'Activate your account'
            
            html_message = render_to_string('auth/activate_account_email.html', {
                'user': user,
                'domain': request.get_host(),
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })
            
            plain_message = f"""
Hi {user.first_name},

Please click on the link below to activate your account:

http://{request.get_host()}/activate/{urlsafe_base64_encode(force_bytes(user.pk))}/{account_activation_token.make_token(user)}/

Thank you,
Crowdfunding Team
"""
            
            email_msg = EmailMessage(
                mail_subject, 
                plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email]
            )
            email_msg.content_subtype = "html"
            email_msg.body = html_message
            
            email_msg.send()
            
            messages.success(request, 'Activation email has been resent. Please check your inbox!')
            
            # Clear session data
            if 'inactive_email' in request.session:
                del request.session['inactive_email']
            if 'inactive_user_id' in request.session:
                del request.session['inactive_user_id']
                
        except User.DoesNotExist:
            messages.error(request, 'No inactive account found with this email.')
        
        return redirect('login')
    
    return redirect('login')

@login_required
def profile(request):
    # Prevent admin users from accessing regular user profile during admin session
    if request.user.is_staff or request.user.is_superuser:
        if request.session.get('admin_session'):
            messages.error(request, 'Admins cannot access user profile pages during admin sessions.')
            return redirect('admin_dashboard')
    
    user = request.user
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('profile')
    else:
        form = UserProfileForm(instance=user)
    
    # Get user's projects and donations
    projects = Project.objects.filter(user=user)
    donations = Donation.objects.filter(user=user).select_related('project')
    
    return render(request, 'auth/profile.html', {
        'form': form,
        'projects': projects,
        'donations': donations
    })

@login_required
def delete_account(request):
    # Prevent admin users from accessing this during admin session
    if request.user.is_staff or request.user.is_superuser:
        if request.session.get('admin_session'):
            messages.error(request, 'Admins cannot delete accounts during admin sessions.')
            return redirect('admin_dashboard')
    
    if request.method == 'POST':
        # Check if password is provided
        password = request.POST.get('password')
        if password and request.user.check_password(password):
            request.user.delete()
            logout(request)
            messages.success(request, 'Your account has been deleted successfully.')
            return redirect('home')
        else:
            messages.error(request, 'Invalid password. Account deletion failed.')
            return redirect('profile')
    
    return render(request, 'auth/delete.html')

@login_required
def switch_to_user(request):
    """Switch from admin back to original user account"""
    if request.session.get('original_user_id'):
        try:
            original_user = User.objects.get(id=request.session['original_user_id'])
            if original_user.is_active:
                # Login as original user
                login(request, original_user)
                
                # Clear admin session data
                if 'admin_session' in request.session:
                    del request.session['admin_session']
                if 'original_user_id' in request.session:
                    del request.session['original_user_id']
                
                messages.success(request, f'Switched back to user account: {original_user.email}')
                return redirect('profile')
            else:
                messages.error(request, 'User account is inactive.')
        except User.DoesNotExist:
            messages.error(request, 'User account no longer exists.')
            if 'original_user_id' in request.session:
                del request.session['original_user_id']
    else:
        messages.info(request, 'No user account to switch back to.')
    
    return redirect('admin_dashboard')

@login_required
def switch_to_admin(request):
    """Switch from user to admin account"""
    if not (request.user.is_staff or request.user.is_superuser):
        # Store original user ID
        request.session['original_user_id'] = request.user.id
        
        # Find an active admin account
        admin_user = User.objects.filter(
            (Q(is_staff=True) | Q(is_superuser=True)) & Q(is_active=True)
        ).first()
        
        if admin_user:
            # Login as admin
            login(request, admin_user)
            request.session['admin_session'] = True
            messages.success(request, f'Switched to admin account: {admin_user.email}')
            return redirect('admin_dashboard')
        else:
            messages.error(request, 'No active admin accounts available.')
            if 'original_user_id' in request.session:
                del request.session['original_user_id']
    else:
        messages.info(request, 'You are already an admin.')
    
    return redirect('profile')


def password_reset_request(request):
    if request.user.is_authenticated:
        messages.info(request, 'You are already logged in.')
        return redirect('home')
    
    if request.method == 'POST':
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email, is_active=True)
                
                # Send password reset email
                mail_subject = 'Reset your password'
                
                html_message = render_to_string('auth/password_reset_email.html', {
                    'user': user,
                    'domain': request.get_host(),
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': password_reset_token.make_token(user),
                })
                
                plain_message = f"""
Hi {user.first_name},

You requested to reset your password. Please click on the link below to reset your password:

http://{request.get_host()}/password-reset-confirm/{urlsafe_base64_encode(force_bytes(user.pk))}/{password_reset_token.make_token(user)}/

If you didn't request this, please ignore this email.

Thank you,
Crowdfunding Team
"""
                
                email_msg = EmailMessage(
                    mail_subject, 
                    plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[user.email]
                )
                email_msg.content_subtype = "html"
                email_msg.body = html_message
                
                email_msg.send()
                
                messages.success(request, 'Password reset link has been sent to your email.')
                return redirect('password_reset_done')
                
            except User.DoesNotExist:
                messages.error(request, 'No active account found with this email address.')
    else:
        form = CustomPasswordResetForm()
    
    return render(request, 'auth/password_reset.html', {'form': form})

def password_reset_done(request):
    return render(request, 'auth/password_reset_done.html')

def password_reset_confirm(request, uidb64, token):
    if request.user.is_authenticated:
        messages.info(request, 'You are already logged in.')
        return redirect('home')
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid, is_active=True)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and password_reset_token.check_token(user, token):
        if request.method == 'POST':
            form = CustomSetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully. You can now login with your new password.')
                return redirect('password_reset_complete')
        else:
            form = CustomSetPasswordForm(user)
        
        return render(request, 'auth/password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'Password reset link is invalid or has expired!')
        return redirect('password_reset')

def password_reset_complete(request):
    return render(request, 'auth/password_reset_complete.html')