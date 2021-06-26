from django.contrib import admin
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_admin_display import admin_display

from . import filters
from .. import models


@admin.register(models.RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ["user", "token", "created", "revoked", "is_expired"]
    list_filter = (filters.RevokedFilter, filters.ExpiredFilter)
    raw_id_fields = ("user",)
    search_fields = ("token",)
    actions = ("revoke",)

    @admin_display(short_description=_("Revoke selected %(verbose_name_plural)s"))
    def revoke(self, request, queryset):
        queryset.update(revoked=timezone.now())

    @admin_display(short_description=_("is expired"), boolean=True)
    def is_expired(self, obj):
        return obj.is_expired()
