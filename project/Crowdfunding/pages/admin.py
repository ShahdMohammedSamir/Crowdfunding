# accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Tag, Project, ProjectPicture, Donation, Comment, Rating, Report

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('email', 'first_name', 'last_name', 'mobile_phone', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff', 'country')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'mobile_phone', 'profile_picture', 'birthdate', 'facebook_profile', 'country')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'mobile_phone', 'password1', 'password2', 'is_active', 'is_staff')}
        ),
    )
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)

class ProjectPictureInline(admin.TabularInline):
    model = ProjectPicture
    extra = 1
    readonly_fields = ('preview_image',)
    
    def preview_image(self, obj):
        if obj.image:
            return f'<img src="{obj.image.url}" style="max-height: 100px; max-width: 100px;" />'
        return "No Image"
    preview_image.allow_tags = True
    preview_image.short_description = 'Preview'

class ProjectAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'category', 'total_target', 'start_time', 'end_time', 'is_featured', 'is_cancelled')
    list_filter = ('category', 'is_featured', 'is_cancelled', 'start_time', 'end_time')
    search_fields = ('title', 'user__email', 'details')
    inlines = [ProjectPictureInline]
    filter_horizontal = ('tags',)
    readonly_fields = ('created_at',)

class DonationAdmin(admin.ModelAdmin):
    list_display = ('user', 'project', 'amount', 'donated_at')
    list_filter = ('donated_at', 'project')
    search_fields = ('user__email', 'project__title')
    readonly_fields = ('donated_at',)

class CommentAdmin(admin.ModelAdmin):
    list_display = ('user', 'project', 'created_at', 'short_content', 'parent')
    list_filter = ('created_at', 'project')
    search_fields = ('user__email', 'project__title', 'content')
    readonly_fields = ('created_at',)
    
    def short_content(self, obj):
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    short_content.short_description = 'Content'

class RatingAdmin(admin.ModelAdmin):
    list_display = ('user', 'project', 'rating')
    list_filter = ('rating', 'project')
    search_fields = ('user__email', 'project__title')

class ReportAdmin(admin.ModelAdmin):
    list_display = ('reporter', 'report_type', 'reported_content', 'is_resolved', 'created_at')
    list_filter = ('report_type', 'is_resolved', 'created_at')
    search_fields = ('reporter__email', 'project__title', 'comment__content', 'reason')
    readonly_fields = ('created_at',)
    actions = ['mark_as_resolved', 'mark_as_unresolved']
    
    def reported_content(self, obj):
        if obj.project:
            return f"Project: {obj.project.title}"
        elif obj.comment:
            return f"Comment: {obj.comment.content[:50]}..."
        return "Unknown"
    reported_content.short_description = 'Reported Content'
    
    def mark_as_resolved(self, request, queryset):
        queryset.update(is_resolved=True)
    mark_as_resolved.short_description = "Mark selected reports as resolved"
    
    def mark_as_unresolved(self, request, queryset):
        queryset.update(is_resolved=False)
    mark_as_unresolved.short_description = "Mark selected reports as unresolved"

# Register ProjectPicture model separately
class ProjectPictureAdmin(admin.ModelAdmin):
    list_display = ('project', 'preview_image')
    list_filter = ('project',)
    search_fields = ('project__title',)
    
    def preview_image(self, obj):
        if obj.image:
            return f'<img src="{obj.image.url}" style="max-height: 50px; max-width: 50px;" />'
        return "No Image"
    preview_image.allow_tags = True
    preview_image.short_description = 'Preview'

admin.site.register(User, CustomUserAdmin)

admin.site.register(Tag)
admin.site.register(Project, ProjectAdmin)
admin.site.register(ProjectPicture, ProjectPictureAdmin)  # Register ProjectPicture model
admin.site.register(Donation, DonationAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(Rating, RatingAdmin)
admin.site.register(Report, ReportAdmin)