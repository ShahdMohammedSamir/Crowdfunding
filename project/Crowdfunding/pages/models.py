from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import RegexValidator, MinValueValidator
from django.utils import timezone
from django.core.exceptions import ValidationError
import os
from uuid import uuid4
from django import forms


# Add Custom UserManager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

def user_profile_picture_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"{uuid4().hex}.{ext}"
    return os.path.join('profiles/', filename)

class User(AbstractUser):
    # Remove username field, we'll use email instead
    username = None
    email = models.EmailField(unique=True)
    
    # Additional fields
    mobile_phone = models.CharField(
        max_length=11,
        validators=[RegexValidator(
            regex=r'^01[0125][0-9]{8}$',
            message="Egyptian phone number must be 11 digits and start with 010, 011, 012, or 015"
        )]
    )
    profile_picture = models.ImageField(upload_to=user_profile_picture_path, null=True, blank=True)
    birthdate = models.DateField(null=True, blank=True)
    facebook_profile = models.URLField(null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    is_active = models.BooleanField(default=False)  # Will be activated via email
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'mobile_phone']
    
    # Use the custom manager
    objects = CustomUserManager()
    
    def _str_(self):
        return self.email
    
    def send_activation_email(self, request):
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        from django.template.loader import render_to_string
        from django.core.mail import EmailMessage
        from .tokens import account_activation_token
        
        mail_subject = 'Activate your account'
        message = render_to_string('accounts/auth/activate_account_email.html', {
            'user': self,
            'domain': request.get_host(),
            'uid': urlsafe_base64_encode(force_bytes(self.pk)),
            'token': account_activation_token.make_token(self),
        })
        email = EmailMessage(mail_subject, message, to=[self.email])
        email.send()



class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)
    
    def _str_(self):
        return self.name
    

class Project(models.Model):
    CATEGORY_CHOICES = [
        ('technology', 'Technology'),
        ('art', 'Art'),
        ('music', 'Music'),
        ('film', 'Film & Video'),
        ('design', 'Design'),
        ('food', 'Food'),
        ('publishing', 'Publishing'),
        ('games', 'Games'),
        ('fashion', 'Fashion'),
        ('health', 'Health & Fitness'),
        ('education', 'Education'),
        ('environment', 'Environment'),
        ('community', 'Community'),
    ]

    needs_review = models.BooleanField(default=False)
    title = models.CharField(max_length=200)
    details = models.TextField()
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)  # fixed list here ✅
    total_target = models.DecimalField(max_digits=12, decimal_places=2, validators=[MinValueValidator(1)])
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='projects')
    is_featured = models.BooleanField(default=False)
    is_cancelled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    tags = models.ManyToManyField("Tag", blank=True)  # keep tags flexible

    def _str_(self):
        return self.title

    def clean(self):
        if self.end_time <= self.start_time:
            raise ValidationError('End time must be after start time.')

    def save(self, *args, **kwargs):
        skip_validation = kwargs.pop("skip_validation", False)
        if not skip_validation:
            self.full_clean()
        super().save(*args, **kwargs)

    @property
    def average_rating(self):
        from django.db.models import Avg # type: ignore
        return self.ratings.aggregate(Avg('rating'))['rating__avg'] or 0

    @property
    def current_donations(self):
        return self.donations.aggregate(total=models.Sum('amount'))['total'] or 0

    @property
    def progress_percentage(self):
        if self.total_target == 0:
            return 0
        return (self.current_donations / self.total_target) * 100

    @property
    def can_cancel(self):
        return self.progress_percentage < 25 and not self.is_cancelled

    @property
    def is_running(self):
        now = timezone.now()
        return self.start_time <= now <= self.end_time and not self.is_cancelled

    @property
    def is_completed(self):
        now = timezone.now()
        return now > self.end_time and not self.is_cancelled

    @property
    def is_upcoming(self):
        now = timezone.now()
        return now < self.start_time and not self.is_cancelled

    @property
    def status(self):
        if self.is_cancelled:
            return "cancelled"
        elif self.is_upcoming:
            return "upcoming"
        elif self.is_running:
            return "running"
        elif self.is_completed:
            return "completed"
        return "unknown"

    def debug_status(self):
        now = timezone.now()
        return {
            'current_time': now.strftime("%Y-%m-%d %H:%M:%S %Z"),
            'start_time': self.start_time.strftime("%Y-%m-%d %H:%M:%S %Z") if self.start_time else None,
            'end_time': self.end_time.strftime("%Y-%m-%d %H:%M:%S %Z") if self.end_time else None,
            'time_until_start': (self.start_time - now) if self.start_time and self.start_time > now else None,
            'time_since_start': (now - self.start_time) if self.start_time and self.start_time <= now else None,
            'time_until_end': (self.end_time - now) if self.end_time and self.end_time > now else None,
            'time_since_end': (now - self.end_time) if self.end_time and self.end_time <= now else None,
            'calculated_status': self.status,
            'is_cancelled': self.is_cancelled
        }

    def cancel(self):
        if self.can_cancel:
            self.is_cancelled = True
            self.save(skip_validation=True)
            return True
        return False

    def get_similar_projects(self, limit=4):
        similar = Project.objects.filter(
            category=self.category,
            tags__in=self.tags.all(),
            is_cancelled=False
        ).exclude(id=self.id).distinct().order_by('-created_at')[:limit]

        if len(similar) < limit:
            additional = Project.objects.filter(
                category=self.category,
                is_cancelled=False
            ).exclude(id=self.id).exclude(id__in=[p.id for p in similar]).order_by('-created_at')[:limit - len(similar)]
            similar = list(similar) + list(additional)

        return similar

class ProjectPicture(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='pictures')
    image = models.ImageField(upload_to='projects/')
    
    def _str_(self):
        return f"Picture for {self.project.title}"
    
    

class Donation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='donations')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='donations')
    amount = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(1)])
    donated_at = models.DateTimeField(auto_now_add=True)
    
    def _str_(self):
        return f"{self.user.email} donated {self.amount} to {self.project.title}"
    
    def clean(self):
        if self.amount <= 0:
            raise ValidationError('Donation amount must be positive.')
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

class Comment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='comments')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    
    def _str_(self):
        return f"Comment by {self.user.email} on {self.project.title}"
    
    def clean(self):
        if self.parent and self.parent.project != self.project:
            raise ValidationError('Reply must be for a comment on the same project.')

class Rating(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ratings')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='ratings')
    rating = models.PositiveSmallIntegerField(choices=[(i, i) for i in range(1, 6)])  # 1-5 scale
    
    class Meta:
        unique_together = ('user', 'project')  # A user can rate a project only once
    
    def _str_(self):
        return f"Rating {self.rating} by {self.user.email} for {self.project.title}"
    
    def clean(self):
        if self.rating < 1 or self.rating > 5:
            raise ValidationError('Rating must be between 1 and 5.')

class Report(models.Model):
    REPORT_TYPES = [
        ('project', 'Project'),
        ('comment', 'Comment'),
    ]
    
    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    report_type = models.CharField(max_length=10, choices=REPORT_TYPES)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, null=True, blank=True)
    reason = models.TextField()
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def clean(self):
        if self.report_type == 'project' and not self.project:
            raise ValidationError('Project must be specified for project reports.')
        if self.report_type == 'comment' and not self.comment:
            raise ValidationError('Comment must be specified for comment reports.')
        if self.report_type == 'project' and self.comment:
            raise ValidationError('Comment should not be specified for project reports.')
        if self.report_type == 'comment' and self.project:
            raise ValidationError('Project should not be specified for comment reports.')
    
    def _str_(self):
        if self.project:
            return f"Report on {self.project.title} by {self.reporter.email}"
        return f"Report on comment by {self.reporter.email}"