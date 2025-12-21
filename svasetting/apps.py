from django.apps import AppConfig


class SvasettingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'svasetting'
    
    def ready(self):
        """Import signal handlers when app is ready"""
        import svasetting.signals  # noqa